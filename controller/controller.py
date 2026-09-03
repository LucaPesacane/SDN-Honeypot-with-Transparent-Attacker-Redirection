import time
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.lib.packet import ether_types

# --- infrastruttura -------------------------------------------------------
HONEYPOT_IP = '10.0.0.200'
HONEYPOT_MAC = '00:00:00:00:02:00'
HONEYPOT_DPID = 2
PROTECTED_IP = '10.0.0.100'
PROTECTED_MAC = '00:00:00:00:01:00'
PORT_TO_HONEYPOT = {1: 5, 2: 2}          # porta di uscita verso l'honeypot

# --- monitoraggio e detection ---------------------------------------------
MONITOR_INTERVAL = 2.0                   # periodo di polling delle FlowStats
WINDOW = 5.0                             # finestra scorrevole
PORTSCAN_PORT_THRESHOLD = 20             # porte distinte in WINDOW secondi
PORTSCAN_MIN_FLOWS = 20                  # minimo di flussi attivi
FLOOD_PKT_THRESHOLD = 500.0              # pacchetti/s
FLOOD_MAX_PORTS = 5                      # oltre questo valore e' uno scan
ALERT_COOLDOWN = 15.0
WHITELIST = {HONEYPOT_IP, PROTECTED_IP}

# --- mitigazione ----------------------------------------------------------
REDIRECT_IDLE_TIMEOUT = 60               # inattivita' prima del recovery
COOKIE_REDIRECT = 0xBEEF                 # marca le regole di redirezione

# --- priorita' ------------------------------------------------------------
PRIO_REDIRECT = 100
PRIO_ALLOW = 60
PRIO_CONTAIN = 50
PRIO_FLOW = 10
PRIO_LEARN = 1
PRIO_MISS = 0
FLOW_IDLE_TIMEOUT = 10
LEARN_IDLE_TIMEOUT = 30


class HoneypotSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HoneypotSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_events = defaultdict(deque)    # ip -> (timestamp, dport)
        self.ip_location = {}                    # ip -> (dpid, port)
        self.suspicious = {}
        self.redirected = {}
        self.alert_count = 0
        self.logger.info("port scan: %d porte / %.0fs (PacketIn) | flood: %.0f pkt/s su <=%d porte (FlowStats)", PORTSCAN_PORT_THRESHOLD, WINDOW, FLOOD_PKT_THRESHOLD, FLOOD_MAX_PORTS)
        hub.spawn(self._monitor_loop)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[ev.datapath.id] = ev.datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(ev.datapath.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        self.logger.info("switch connesso: dpid=%s", datapath.id)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, PRIO_MISS, parser.OFPMatch(), actions)
        if datapath.id == HONEYPOT_DPID:
            self.install_containment(datapath)

    def install_containment(self, datapath):
        """Isola l'honeypot: puo' solo fare ARP, il resto viene scartato."""
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        to_ctrl = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, eth_src=HONEYPOT_MAC)
        self.add_flow(datapath, PRIO_ALLOW, match, to_ctrl)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=HONEYPOT_IP)
        self.add_flow(datapath, PRIO_CONTAIN, match, [])
        self.logger.info("containment honeypot installato su dpid=%s", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, cookie=0, flags=0):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(datapath=datapath, priority=priority, match=match, idle_timeout=idle_timeout, cookie=cookie, flags=flags, instructions=inst)
        if buffer_id:
            kwargs['buffer_id'] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Learning switch; per il traffico IP installa regole sulla 5-tupla."""
        msg = ev.msg
        datapath = msg.datapath
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is not None:
            self.ip_location[ip4.src] = (dpid, in_port)
            self._record_event(pkt, ip4)

        if out_port != ofproto.OFPP_FLOOD:
            if ip4 is not None:
                self.add_flow(datapath, PRIO_FLOW, self._flow_match(parser, pkt, ip4), actions, idle_timeout=FLOW_IDLE_TIMEOUT)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
                self.add_flow(datapath, PRIO_LEARN, match, actions, idle_timeout=LEARN_IDLE_TIMEOUT)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        datapath.send_msg(parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data))

    def _flow_match(self, parser, pkt, ip4):
        """Costruisce il match sulla 5-tupla del pacchetto."""
        kw = dict(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip4.src, ipv4_dst=ip4.dst, ip_proto=ip4.proto)
        t, u = pkt.get_protocol(tcp.tcp), pkt.get_protocol(udp.udp)
        if t is not None:
            kw['tcp_src'], kw['tcp_dst'] = t.src_port, t.dst_port
        elif u is not None:
            kw['udp_src'], kw['udp_dst'] = u.src_port, u.dst_port
        return parser.OFPMatch(**kw)

    def install_redirection(self, attacker_ip, target_ip=PROTECTED_IP):
        """Dirotta l'attaccante sull'honeypot in modo trasparente."""
        loc = self.ip_location.get(attacker_ip)
        if loc is None:
            return False
        dpid, att_port = loc
        datapath = self.datapaths.get(dpid)
        hp_port = PORT_TO_HONEYPOT.get(dpid)
        if datapath is None or hp_port is None:
            return False
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=attacker_ip, ipv4_dst=target_ip)
        actions = [parser.OFPActionSetField(ipv4_dst=HONEYPOT_IP), parser.OFPActionSetField(eth_dst=HONEYPOT_MAC), parser.OFPActionOutput(hp_port)]
        self.add_flow(datapath, PRIO_REDIRECT, match, actions, idle_timeout=REDIRECT_IDLE_TIMEOUT, cookie=COOKIE_REDIRECT, flags=ofproto.OFPFF_SEND_FLOW_REM)

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=HONEYPOT_IP, ipv4_dst=attacker_ip)
        actions = [parser.OFPActionSetField(ipv4_src=target_ip), parser.OFPActionSetField(eth_src=PROTECTED_MAC), parser.OFPActionOutput(att_port)]
        self.add_flow(datapath, PRIO_REDIRECT, match, actions, idle_timeout=REDIRECT_IDLE_TIMEOUT, cookie=COOKIE_REDIRECT)

        hp_dp = self.datapaths.get(HONEYPOT_DPID)
        if hp_dp is not None:
            hp_parser, hp_ofp = hp_dp.ofproto_parser, hp_dp.ofproto
            match = hp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=HONEYPOT_IP, ipv4_dst=attacker_ip)
            to_ctrl = [hp_parser.OFPActionOutput(hp_ofp.OFPP_CONTROLLER, hp_ofp.OFPCML_NO_BUFFER)]
            self.add_flow(hp_dp, PRIO_ALLOW, match, to_ctrl, idle_timeout=REDIRECT_IDLE_TIMEOUT, cookie=COOKIE_REDIRECT)

        self.redirected[attacker_ip] = time.time()
        self.logger.warning(">>> REDIREZIONE ATTIVA: %s -> honeypot %s (dpid=%s, in_port=%s, out_port=%s, idle=%ds). L'attaccante continua a vedere %s.", attacker_ip, HONEYPOT_IP, dpid, att_port, hp_port, REDIRECT_IDLE_TIMEOUT, target_ip)
        return True

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        """Riporta l'host al forwarding ordinario allo scadere della regola."""
        if ev.msg.cookie != COOKIE_REDIRECT:
            return
        src = ev.msg.match.get('ipv4_src')
        if src in self.redirected:
            duration = time.time() - self.redirected.pop(src)
            self.suspicious.pop(src, None)
            self.flow_events.pop(src, None)
            self.logger.warning("<<< RECOVERY: %s non e' piu' dirottato (quarantena %.1fs, pacchetti deviati %d)", src, duration, ev.msg.packet_count)

    def _record_event(self, pkt, ip4):
        """Registra la porta di destinazione contattata dalla sorgente."""
        dport = -1
        t, u = pkt.get_protocol(tcp.tcp), pkt.get_protocol(udp.udp)
        if t is not None:
            dport = t.dst_port
        elif u is not None:
            dport = u.dst_port
        elif pkt.get_protocol(icmp.icmp) is not None:
            dport = 0
        self.flow_events[ip4.src].append((time.time(), dport))

    def _prune(self, now):
        """Elimina dalla finestra gli eventi piu' vecchi di WINDOW secondi."""
        cutoff = now - WINDOW
        for src, dq in list(self.flow_events.items()):
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                del self.flow_events[src]

    def _monitor_loop(self):
        """Interroga periodicamente le statistiche di tutti gli switch."""
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(MONITOR_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Aggrega i contatori per sorgente e invoca il detector."""
        now = time.time()
        dpid = ev.msg.datapath.id
        self._prune(now)

        agg = defaultdict(lambda: {'pkts': 0, 'flows': 0, 'top': 0})
        for st in ev.msg.body:
            src = st.match.get('ipv4_src')
            if src is None:
                continue
            a = agg[src]
            a['pkts'] += st.packet_count
            a['flows'] += 1
            a['top'] = max(a['top'], st.packet_count)

        for src in set(agg) | set(self.flow_events):
            a = agg.get(src, {'pkts': 0, 'flows': 0, 'top': 0})
            n_ports = len({p for _, p in self.flow_events.get(src, ()) if p >= 0})
            pps = a['pkts'] / WINDOW if a['flows'] else 0.0
            top = a['top'] / WINDOW if a['flows'] else 0.0
            if n_ports or pps:
                self.logger.info("dpid=%s src=%-11s dports=%-5d pkt/s=%-9.1f topflow=%-9.1f flussi=%d%s", dpid, src, n_ports, pps, top, a['flows'], "  [REDIRECTED]" if src in self.redirected else "")
            self._detect(now, src, n_ports, pps, a['flows'])

    def _detect(self, now, src, n_ports, pps, n_flows):
        """Classifica la sorgente come port scan, flood, o traffico normale."""
        if src in WHITELIST or src in self.redirected:
            return
        if n_ports >= PORTSCAN_PORT_THRESHOLD and n_flows >= PORTSCAN_MIN_FLOWS:
            atype, channel, thr = 'port_scan', 'PacketIn', PORTSCAN_PORT_THRESHOLD
        elif pps >= FLOOD_PKT_THRESHOLD and n_ports <= FLOOD_MAX_PORTS:
            atype, channel, thr = 'volumetric_flood', 'FlowStats', FLOOD_PKT_THRESHOLD
        else:
            return
        if now - self.suspicious.get(src, 0) < ALERT_COOLDOWN:
            return
        self.suspicious[src] = now
        self.alert_count += 1
        action = 'redirect_to_honeypot' if self.install_redirection(src) else 'log_only'
        self.logger.warning("*** ALERT #%d  %s da %s  [canale %s]  |  porte=%d  pkt/s=%.0f (soglia %.0f)  flussi=%d  -> %s", self.alert_count, atype, src, channel, n_ports, pps, thr, n_flows, action)
