# controller.py - Project work NCIs
# SDN-based attack detection and transparent honeypot redirection
#
# Il controller rileva due tipologie di attacco sfruttando i DUE canali di
# raccolta previsti da OpenFlow, che hanno proprieta' complementari:
#
#   PORT SCAN        canale asincrono (PacketIn)
#                    Ogni connessione verso una porta nuova non trova
#                    corrispondenza nella tabella e viene inviata al
#                    controller. La firma e' la CARDINALITA' delle porte di
#                    destinazione distinte: molte destinazioni contattate
#                    una volta sola. Il segnale e' immediato ma vede solo
#                    il primo pacchetto di ogni flusso.
#
#   FLOOD VOLUMETRICO  canale sincrono (FlowStats)
#                    Un flood a 5-tupla costante genera un solo PacketIn:
#                    dopo l'installazione della regola tutto il traffico
#                    resta nel data plane ed e' invisibile al canale
#                    asincrono. Cio' che cresce sono i CONTATORI della flow
#                    entry, letti dal polling periodico. La firma e' quindi
#                    il RATE di pacchetti su poche porte.
#
# I due criteri sono mutuamente esclusivi: il port scan ha molte porte e
# rate basso, il flood ha poche porte e rate alto.
#
# Soglie, derivate sperimentalmente dalla baseline di traffico legittimo:
#   port scan   max osservato 5 porte distinte / 5 s   -> soglia  20 (4x)
#   flood       max osservato ~100 pacchetti/s         -> soglia 500 (5x)
#
# Mitigazione: in entrambi i casi il traffico viene dirottato in modo
# trasparente sull'honeypot, dove viene registrato. Il flood viene
# dirottato integralmente; una limitazione di banda mediante meter
# OpenFlow e' possibile ed e' discussa come estensione.
#
# Priorita' nella tabella 0:
#   100  redirezione verso honeypot
#    60  eccezioni al containment
#    50  containment honeypot
#    10  forwarding per flusso (IP)
#     1  learning switch L2 (ARP, resto)
#     0  table-miss -> controller
#
# Uso:
#   ryu-manager controller.py

import csv
import json
import os
import time
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types

# ---------------------------------------------------------------------------
# Infrastruttura: configurazione dell'amministratore, non conoscenza a priori
# dell'attacco. L'identita' dell'attaccante NON e' configurata: emerge dal
# comportamento osservato ed e' popolata a runtime in self.suspicious.
# ---------------------------------------------------------------------------
HONEYPOT_IP = '10.0.0.200'
HONEYPOT_MAC = '00:00:00:00:02:00'
HONEYPOT_DPID = 2

PROTECTED_IP = '10.0.0.100'
PROTECTED_MAC = '00:00:00:00:01:00'

# Porta di uscita verso l'honeypot per ciascuno switch: su s1 e' il trunk
# verso s2, su s2 e' la porta di accesso dell'honeypot (cfr. port_map.json).
PORT_TO_HONEYPOT = {1: 5, 2: 2}

ENABLE_CONTAINMENT = True

# --- monitoraggio ---------------------------------------------------------
MONITOR_INTERVAL = 2.0
WINDOW = 5.0
CSV_PATH = '/tmp/ncis_monitor.csv'

# --- detection ------------------------------------------------------------
ENABLE_DETECTION = True

# Port scan: cardinalita' delle porte distinte (canale PacketIn)
PORTSCAN_PORT_THRESHOLD = 20
PORTSCAN_MIN_FLOWS = 20

# Flood volumetrico: rate di pacchetti (canale FlowStats)
FLOOD_PKT_THRESHOLD = 500.0       # pacchetti/s
FLOOD_MAX_PORTS = 5               # oltre questo valore e' uno scan, non un flood

ALERT_COOLDOWN = 15.0
ALERT_LOG = '/tmp/ncis_alerts.jsonl'
DETECTION_WHITELIST = {HONEYPOT_IP, PROTECTED_IP}

# --- mitigazione ----------------------------------------------------------
ENABLE_REDIRECTION = True
REDIRECT_IDLE_TIMEOUT = 60

# --- priorita' ------------------------------------------------------------
PRIO_REDIRECT = 100
PRIO_ALLOW = 60
PRIO_CONTAIN = 50
PRIO_FLOW = 10
PRIO_LEARN = 1
PRIO_MISS = 0

FLOW_IDLE_TIMEOUT = 10
LEARN_IDLE_TIMEOUT = 30

COOKIE_REDIRECT = 0xBEEF


class HoneypotSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HoneypotSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        # --- monitoraggio ---
        self.flow_events = defaultdict(deque)
        self.packet_in_count = 0
        self.packet_in_last = 0

        # posizione degli host appresa dai PacketIn: ip -> (dpid, port, mac)
        self.ip_location = {}

        # --- detector / mitigazione ---
        self.suspicious = {}
        self.redirected = {}
        self.alert_count = 0

        self._init_csv()
        self.logger.info("monitor: campionamento %.1fs, finestra %.1fs",
                         MONITOR_INTERVAL, WINDOW)
        if ENABLE_DETECTION:
            self.logger.info("detector port scan: %d porte distinte / %.0fs "
                             "(canale PacketIn)",
                             PORTSCAN_PORT_THRESHOLD, WINDOW)
            self.logger.info("detector flood:     %.0f pkt/s su <=%d porte "
                             "(canale FlowStats)",
                             FLOOD_PKT_THRESHOLD, FLOOD_MAX_PORTS)
        self.logger.info("redirezione honeypot: %s (idle_timeout %ds)",
                         "ATTIVA" if ENABLE_REDIRECTION else "disattivata",
                         REDIRECT_IDLE_TIMEOUT)

        self.monitor_thread = hub.spawn(self._monitor_loop)

    # =======================================================================
    # Connessione switch
    # =======================================================================
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("switch connesso: dpid=%s", datapath.id)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, PRIO_MISS, match, actions)

        if ENABLE_CONTAINMENT and datapath.id == HONEYPOT_DPID:
            self.install_containment(datapath)

    # =======================================================================
    # Isolamento honeypot (policy statica)
    # =======================================================================
    def install_containment(self, datapath):
        """
        L'honeypot puo' solo fare ARP; ogni altro traffico che origina da lui
        viene scartato. Le eccezioni verso gli host dirottati non sono
        preconfigurate: vengono installate nel momento in cui un host viene
        classificato come malevolo (install_redirection).
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        to_ctrl = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                eth_src=HONEYPOT_MAC)
        self.add_flow(datapath, PRIO_ALLOW, match, to_ctrl)

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=HONEYPOT_IP)
        self.add_flow(datapath, PRIO_CONTAIN, match, [])

        self.logger.info("containment honeypot installato su dpid=%s",
                         datapath.id)

    # =======================================================================
    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle_timeout=0, hard_timeout=0, cookie=0, flags=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        kwargs = dict(datapath=datapath, priority=priority, match=match,
                      idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                      cookie=cookie, flags=flags, instructions=inst)
        if buffer_id:
            kwargs['buffer_id'] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    # =======================================================================
    # Packet-in
    # =======================================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype in (ether_types.ETH_TYPE_LLDP,
                             ether_types.ETH_TYPE_IPV6):
            return

        self.packet_in_count += 1

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is not None:
            self.ip_location[ip4.src] = (dpid, in_port, src)
            self._record_event(pkt, ip4)

        if out_port == ofproto.OFPP_FLOOD:
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        if ip4 is not None:
            match = self._build_flow_match(parser, pkt, ip4)
            self.add_flow(datapath, PRIO_FLOW, match, actions,
                          idle_timeout=FLOW_IDLE_TIMEOUT)
        else:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, PRIO_LEARN, match, actions,
                          idle_timeout=LEARN_IDLE_TIMEOUT)

        self._send_packet_out(datapath, msg, in_port, actions)

    def _build_flow_match(self, parser, pkt, ip4):
        kw = dict(eth_type=ether_types.ETH_TYPE_IP,
                  ipv4_src=ip4.src, ipv4_dst=ip4.dst,
                  ip_proto=ip4.proto)
        t = pkt.get_protocol(tcp.tcp)
        u = pkt.get_protocol(udp.udp)
        if t is not None:
            kw['tcp_src'] = t.src_port
            kw['tcp_dst'] = t.dst_port
        elif u is not None:
            kw['udp_src'] = u.src_port
            kw['udp_dst'] = u.dst_port
        return parser.OFPMatch(**kw)

    def _send_packet_out(self, datapath, msg, in_port, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # =======================================================================
    # REDIREZIONE TRASPARENTE
    # =======================================================================
    def install_redirection(self, attacker_ip, target_ip=PROTECTED_IP):
        """
        NAT bidirezionale che dirotta l'attaccante sull'honeypot.

        In andata si riscrivono ipv4_dst ed eth_dst verso l'honeypot; in
        ritorno si riscrivono ipv4_src ed eth_src con quelli della vittima.
        L'attaccante invia a target_ip e riceve risposte da target_ip, quindi
        non ha modo di accorgersi del dirottamento. Open vSwitch ricalcola
        automaticamente i checksum a seguito delle azioni set_field.

        L'ARP non viene toccato (le regole matchano solo eth_type=IP): le
        richieste raggiungono il server reale, quindi la cache ARP
        dell'attaccante contiene il MAC autentico della vittima.
        """
        loc = self.ip_location.get(attacker_ip)
        if loc is None:
            self.logger.warning("redirezione impossibile: posizione di %s "
                                "sconosciuta", attacker_ip)
            return False

        dpid, att_port, att_mac = loc
        datapath = self.datapaths.get(dpid)
        if datapath is None:
            self.logger.warning("redirezione impossibile: dpid %s non "
                                "connesso", dpid)
            return False

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        hp_port = PORT_TO_HONEYPOT.get(dpid)
        if hp_port is None:
            self.logger.warning("redirezione impossibile: nessuna porta "
                                "verso l'honeypot su dpid %s", dpid)
            return False

        # ---- ANDATA: attaccante -> vittima, riscritto verso l'honeypot ----
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=attacker_ip,
                                ipv4_dst=target_ip)
        actions = [
            parser.OFPActionSetField(ipv4_dst=HONEYPOT_IP),
            parser.OFPActionSetField(eth_dst=HONEYPOT_MAC),
            parser.OFPActionOutput(hp_port),
        ]
        self.add_flow(datapath, PRIO_REDIRECT, match, actions,
                      idle_timeout=REDIRECT_IDLE_TIMEOUT,
                      cookie=COOKIE_REDIRECT,
                      flags=ofproto.OFPFF_SEND_FLOW_REM)

        # ---- RITORNO: honeypot -> attaccante, riscritto come vittima ----
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=HONEYPOT_IP,
                                ipv4_dst=attacker_ip)
        actions = [
            parser.OFPActionSetField(ipv4_src=target_ip),
            parser.OFPActionSetField(eth_src=PROTECTED_MAC),
            parser.OFPActionOutput(att_port),
        ]
        self.add_flow(datapath, PRIO_REDIRECT, match, actions,
                      idle_timeout=REDIRECT_IDLE_TIMEOUT,
                      cookie=COOKIE_REDIRECT)

        # ---- eccezione dinamica al containment sullo switch honeypot ----
        hp_dp = self.datapaths.get(HONEYPOT_DPID)
        if hp_dp is not None:
            hp_parser = hp_dp.ofproto_parser
            hp_ofp = hp_dp.ofproto
            match = hp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                       ipv4_src=HONEYPOT_IP,
                                       ipv4_dst=attacker_ip)
            to_ctrl = [hp_parser.OFPActionOutput(hp_ofp.OFPP_CONTROLLER,
                                                 hp_ofp.OFPCML_NO_BUFFER)]
            self.add_flow(hp_dp, PRIO_ALLOW, match, to_ctrl,
                          idle_timeout=REDIRECT_IDLE_TIMEOUT,
                          cookie=COOKIE_REDIRECT)

        self.redirected[attacker_ip] = {
            'since': time.time(), 'dpid': dpid, 'att_port': att_port,
            'target': target_ip, 'hp_port': hp_port,
        }

        self.logger.warning(
            ">>> REDIREZIONE ATTIVA: %s -> honeypot %s "
            "(dpid=%s, in_port=%s, out_port=%s, idle=%ds). "
            "L'attaccante continua a vedere %s.",
            attacker_ip, HONEYPOT_IP, dpid, att_port, hp_port,
            REDIRECT_IDLE_TIMEOUT, target_ip)
        return True

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        """
        Recovery: quando la regola di andata scade per inattivita', l'host
        esce dalla quarantena e torna al forwarding ordinario, senza alcun
        intervento esterno.
        """
        msg = ev.msg
        if msg.cookie != COOKIE_REDIRECT:
            return
        src = msg.match.get('ipv4_src')
        if src in self.redirected:
            info = self.redirected.pop(src)
            duration = time.time() - info['since']
            self.suspicious.pop(src, None)
            # svuota la finestra, altrimenti eventi residui potrebbero far
            # rientrare immediatamente l'host in quarantena
            self.flow_events.pop(src, None)
            self.logger.warning(
                "<<< RECOVERY: %s non e' piu' dirottato "
                "(durata quarantena %.1fs, pacchetti deviati %d)",
                src, duration, msg.packet_count)
            self._log_event({
                'timestamp': time.time(),
                'datetime': time.strftime('%Y-%m-%dT%H:%M:%S',
                                          time.localtime()),
                'src_ip': src,
                'event': 'recovery',
                'quarantine_duration_s': round(duration, 2),
                'redirected_packets': msg.packet_count,
                'redirected_bytes': msg.byte_count,
            })

    # =======================================================================
    # Monitoraggio
    # =======================================================================
    def _record_event(self, pkt, ip4):
        now = time.time()
        dport = -1
        t = pkt.get_protocol(tcp.tcp)
        u = pkt.get_protocol(udp.udp)
        if t is not None:
            dport = t.dst_port
        elif u is not None:
            dport = u.dst_port
        elif pkt.get_protocol(icmp.icmp) is not None:
            dport = 0
        self.flow_events[ip4.src].append((now, ip4.dst, dport, ip4.proto))

    def _prune(self, now):
        cutoff = now - WINDOW
        for src, dq in list(self.flow_events.items()):
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                del self.flow_events[src]

    def _monitor_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(MONITOR_INTERVAL)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
        datapath.send_msg(
            parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        now = time.time()
        dpid = ev.msg.datapath.id
        self._prune(now)

        agg = defaultdict(lambda: {'pkts': 0, 'bytes': 0,
                                   'flows': 0, 'single': 0, 'max_pkts': 0})
        for st in ev.msg.body:
            src = st.match.get('ipv4_src')
            if src is None:
                continue
            a = agg[src]
            a['pkts'] += st.packet_count
            a['bytes'] += st.byte_count
            a['flows'] += 1
            if st.packet_count <= 1:
                a['single'] += 1
            # il flusso piu' voluminoso: e' la firma dell'attacco
            # volumetrico su 5-tupla costante
            if st.packet_count > a['max_pkts']:
                a['max_pkts'] = st.packet_count

        pi_delta = self.packet_in_count - self.packet_in_last
        self.packet_in_last = self.packet_in_count
        pi_rate = pi_delta / MONITOR_INTERVAL

        rows = []
        features = {}
        for src in set(agg) | set(self.flow_events):
            ev_list = self.flow_events.get(src, ())
            dports = {e[2] for e in ev_list if e[2] >= 0}
            dips = {e[1] for e in ev_list}
            a = agg.get(src, {'pkts': 0, 'bytes': 0, 'flows': 0,
                              'single': 0, 'max_pkts': 0})

            # Rate misurati sulla finestra scorrevole anziche' come derivata
            # dei contatori del data plane: le flow entry hanno idle_timeout
            # breve, quindi scadono e vengono ricreate azzerando i contatori
            # cumulativi, e la derivata risulterebbe nulla o negativa.
            pps = a['pkts'] / WINDOW if a['flows'] else 0.0
            bps = a['bytes'] / WINDOW if a['flows'] else 0.0
            top_pps = a['max_pkts'] / WINDOW if a['flows'] else 0.0
            avg_bytes = (a['bytes'] / a['flows']) if a['flows'] else 0.0
            single_ratio = (a['single'] / a['flows']) if a['flows'] else 0.0

            f = {
                'timestamp': '%.3f' % now,
                'dpid': dpid,
                'src_ip': src,
                'distinct_dports': len(dports),
                'distinct_dst_ips': len(dips),
                'new_flows_per_s': '%.2f' % (len(ev_list) / WINDOW),
                'active_flows': a['flows'],
                'pkts_per_s': '%.2f' % pps,
                'top_flow_pkts_per_s': '%.2f' % top_pps,
                'bytes_per_s': '%.2f' % bps,
                'avg_bytes_per_flow': '%.1f' % avg_bytes,
                'single_pkt_flow_ratio': '%.3f' % single_ratio,
                'packet_in_per_s': '%.2f' % pi_rate,
                'redirected': 1 if src in self.redirected else 0,
            }
            rows.append(f)
            features[src] = f

        self._write_csv(rows)

        if ENABLE_DETECTION:
            self._detect(now, features)

        for r in sorted(rows, key=lambda x: -float(x['pkts_per_s']))[:3]:
            if int(r['distinct_dports']) > 0 or float(r['pkts_per_s']) > 0:
                self.logger.info(
                    "dpid=%s src=%-11s dports=%-4s pkt/s=%-9s "
                    "topflow=%-9s avgB=%-9s single=%s%s",
                    r['dpid'], r['src_ip'], r['distinct_dports'],
                    r['pkts_per_s'], r['top_flow_pkts_per_s'],
                    r['avg_bytes_per_flow'], r['single_pkt_flow_ratio'],
                    "  [REDIRECTED]" if r['redirected'] else "")

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        pass  # raccolte per la valutazione sperimentale

    # =======================================================================
    # DETECTOR
    # =======================================================================
    def _detect(self, now, features):
        """
        Due rilevatori distinti, alimentati da canali OpenFlow diversi.
        Le condizioni sono mutuamente esclusive: il port scan presenta molte
        porte distinte e volume trascurabile, il flood poche porte e volume
        elevato. Una sorgente gia' in quarantena non viene rivalutata.
        """
        for src, f in features.items():
            if src in DETECTION_WHITELIST or src in self.redirected:
                continue

            n_ports = int(f['distinct_dports'])
            n_flows = int(f['active_flows'])
            pps = float(f['pkts_per_s'])

            atype = None

            # --- port scan: cardinalita' delle porte (canale PacketIn) ---
            if n_ports >= PORTSCAN_PORT_THRESHOLD and n_flows >= PORTSCAN_MIN_FLOWS:
                atype = 'port_scan'

            # --- flood volumetrico: rate (canale FlowStats) ---
            elif pps >= FLOOD_PKT_THRESHOLD and n_ports <= FLOOD_MAX_PORTS:
                atype = 'volumetric_flood'

            if atype is None:
                continue

            prev = self.suspicious.get(src)
            if prev and (now - prev['last_alert']) < ALERT_COOLDOWN:
                prev['evidence'] = f
                continue

            self._raise_alert(now, src, atype, f, renewed=bool(prev))

    def _raise_alert(self, now, src, atype, evidence, renewed=False):
        self.alert_count += 1
        entry = self.suspicious.get(src) or {'first_seen': now}
        entry.update({'type': atype, 'last_alert': now, 'evidence': evidence})
        self.suspicious[src] = entry

        threshold = (PORTSCAN_PORT_THRESHOLD if atype == 'port_scan'
                     else FLOOD_PKT_THRESHOLD)
        channel = ('PacketIn' if atype == 'port_scan' else 'FlowStats')

        action = 'log_only'
        if ENABLE_REDIRECTION and self.install_redirection(src):
            action = 'redirect_to_honeypot'

        self._log_event({
            'alert_id': self.alert_count,
            'timestamp': now,
            'datetime': time.strftime('%Y-%m-%dT%H:%M:%S',
                                      time.localtime(now)),
            'src_ip': src,
            'event': 'alert',
            'attack_type': atype,
            'detection_channel': channel,
            'renewed': renewed,
            'threshold': threshold,
            'evidence': {
                'distinct_dports': int(evidence['distinct_dports']),
                'distinct_dst_ips': int(evidence['distinct_dst_ips']),
                'new_flows_per_s': float(evidence['new_flows_per_s']),
                'active_flows': int(evidence['active_flows']),
                'pkts_per_s': float(evidence['pkts_per_s']),
                'top_flow_pkts_per_s':
                    float(evidence['top_flow_pkts_per_s']),
                'bytes_per_s': float(evidence['bytes_per_s']),
                'avg_bytes_per_flow': float(evidence['avg_bytes_per_flow']),
                'single_pkt_flow_ratio':
                    float(evidence['single_pkt_flow_ratio']),
            },
            'action': action,
        })

        self.logger.warning(
            "*** ALERT #%d  %s da %s  [canale %s]  |  porte=%d  "
            "pkt/s=%.0f (soglia %.0f)  flussi=%d  -> %s",
            self.alert_count, atype, src, channel,
            int(evidence['distinct_dports']),
            float(evidence['pkts_per_s']), threshold,
            int(evidence['active_flows']), action)

    def _log_event(self, record):
        with open(ALERT_LOG, 'a') as fh:
            fh.write(json.dumps(record) + '\n')

    # =======================================================================
    # CSV
    # =======================================================================
    FIELDS = ['timestamp', 'dpid', 'src_ip', 'distinct_dports',
              'distinct_dst_ips', 'new_flows_per_s', 'active_flows',
              'pkts_per_s', 'top_flow_pkts_per_s', 'bytes_per_s',
              'avg_bytes_per_flow', 'single_pkt_flow_ratio',
              'packet_in_per_s', 'redirected']

    def _init_csv(self):
        new = not os.path.exists(CSV_PATH)
        self._csv_file = open(CSV_PATH, 'a', newline='')
        self._csv = csv.DictWriter(self._csv_file, fieldnames=self.FIELDS)
        if new:
            self._csv.writeheader()
            self._csv_file.flush()

    def _write_csv(self, rows):
        if not rows:
            return
        self._csv.writerows(rows)
        self._csv_file.flush()
