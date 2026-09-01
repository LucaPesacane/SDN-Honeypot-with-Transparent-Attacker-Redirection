#!/usr/bin/python
#
# topology.py - Topologia Mininet per il project work NCIs
# SDN-based attack detection and transparent honeypot redirection
#
# Topologia:
#
#   h_att   h_ben1   h_ben2   h_srv                 h_ben3   h_pot
#     |       |        |        |                      |       |
#    [-------------- s1 ---------------]----------[----- s2 -----]
#         SEGMENTO DI PRODUZIONE                  SEGMENTO HONEYPOT
#
#   - attaccante e vittima su s1: il traffico legittimo non attraversa mai
#     il link inter-switch
#   - honeypot su s2: quando il controller rileva l'attacco e devia il
#     flusso, il traffico compare sul trunk s1-s2
#   - h_ben3 su s2 per avere traffico legittimo anche sul trunk
#
# Piano di indirizzamento (10.0.0.0/24):
#   h_att   10.0.0.10   00:00:00:00:00:10   attaccante
#   h_ben1  10.0.0.11   00:00:00:00:00:11   host benigno
#   h_ben2  10.0.0.12   00:00:00:00:00:12   host benigno
#   h_ben3  10.0.0.13   00:00:00:00:00:13   host benigno (su s2)
#   h_srv   10.0.0.100  00:00:00:00:01:00   server vittima
#   h_pot   10.0.0.200  00:00:00:00:02:00   honeypot
#
# Traffico benigno (iperf):
#   Il server espone piu' porte, una per "servizio". I client aprono
#   sessioni brevi verso porte scelte a caso, con attesa distribuita
#   esponenzialmente (processo di Poisson): il traffico non e' periodico e
#   la baseline del detector risulta realistica. Un flusso UDP costante
#   simula una comunicazione VoIP e fornisce jitter e packet loss per la
#   valutazione sperimentale.
#
# Uso:
#   sudo python3 topology.py                 # traffico benigno attivo
#   sudo python3 topology.py --no-traffic    # solo topologia
#

import argparse
import json
import os
import time

from mininet.log import setLogLevel, info
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch
from mininet.link import TCLink
from mininet.node import RemoteController

# --- parametri del traffico benigno ---------------------------------------
SERVICE_PORTS = [5001, 5002, 5003, 5004, 5005]   # "servizi" TCP esposti
VOIP_PORT = 5010

# Volume di una sessione invece della durata: con "-t" iperf trasmette al
# massimo della capacita' per tutta la durata indicata, saturando il link e
# rendendo il traffico irrealistico. Con "-n" la sessione trasferisce una
# quantita' fissa e termina, quindi risulta breve e di volume controllato.
SESSION_SIZE = '200K'
MEAN_RATE = 2.0            # sessioni/s medie per client
VOIP_BW = '64k'            # flusso CBR tipo G.711
VOIP_LEN = 60


class Environment(object):

    def __init__(self, with_traffic=True):
        "Create a network."
        self.net = Mininet(controller=RemoteController, link=TCLink)
        self.procs = []        # processi di traffico avviati con popen

        info("*** Starting controller\n")
        c1 = self.net.addController('c1', controller=RemoteController)
        c1.start()

        info("*** Adding hosts and switches\n")
        # --- segmento di produzione (s1) ---
        self.h_att = self.net.addHost('h_att', mac='00:00:00:00:00:10',
                                      ip='10.0.0.10/24')
        self.h_ben1 = self.net.addHost('h_ben1', mac='00:00:00:00:00:11',
                                       ip='10.0.0.11/24')
        self.h_ben2 = self.net.addHost('h_ben2', mac='00:00:00:00:00:12',
                                       ip='10.0.0.12/24')
        self.h_srv = self.net.addHost('h_srv', mac='00:00:00:00:01:00',
                                      ip='10.0.0.100/24')
        # --- segmento honeypot (s2) ---
        self.h_ben3 = self.net.addHost('h_ben3', mac='00:00:00:00:00:13',
                                       ip='10.0.0.13/24')
        self.h_pot = self.net.addHost('h_pot', mac='00:00:00:00:02:00',
                                      ip='10.0.0.200/24')

        self.prod = self.net.addSwitch('s1', cls=OVSKernelSwitch,
                                       dpid='0000000000000001',
                                       protocols='OpenFlow13')
        self.hpot = self.net.addSwitch('s2', cls=OVSKernelSwitch,
                                       dpid='0000000000000002',
                                       protocols='OpenFlow13')

        info("*** Adding links\n")
        self.net.addLink(self.h_att, self.prod, bw=10, delay='1ms')
        self.net.addLink(self.h_ben1, self.prod, bw=10, delay='1ms')
        self.net.addLink(self.h_ben2, self.prod, bw=10, delay='1ms')
        self.net.addLink(self.h_srv, self.prod, bw=10, delay='1ms')
        self.net.addLink(self.h_ben3, self.hpot, bw=10, delay='1ms')
        self.net.addLink(self.h_pot, self.hpot, bw=10, delay='1ms')
        self.trunk = self.net.addLink(self.prod, self.hpot,
                                      bw=20, delay='2ms')

        info("*** Starting network\n")
        self.net.build()
        self.net.start()

        self.disable_ipv6()
        self.export_portmap()

        if with_traffic:
            self.start_servers()
            self.start_traffic()

    # ------------------------------------------------------------------
    def disable_ipv6(self):
        """
        Il multicast IPv6 (router solicitation, MLD) genererebbe PacketIn
        non pertinenti che inquinerebbero le statistiche del detector.
        """
        info("*** Disabling IPv6\n")
        for node in self.net.hosts + self.net.switches:
            node.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
            node.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
            node.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')

    # ------------------------------------------------------------------
    def export_portmap(self, path='port_map.json'):
        """
        Esporta la mappa host -> (switch, dpid, porta) su file JSON: il
        controller la usa per costruire l'azione OFPActionOutput della
        regola di redirezione senza cablare numeri di porta nel codice.
        """
        port_map = {}
        for host in self.net.hosts:
            for intf in host.intfList():
                if not intf.link:
                    continue
                peer = (intf.link.intf2 if intf.link.intf1 == intf
                        else intf.link.intf1)
                port_map[host.name] = {
                    'ip': host.IP(), 'mac': host.MAC(),
                    'switch': peer.node.name,
                    'dpid': int(peer.node.dpid, 16),
                    'port': peer.node.ports[peer],
                }
        with open(path, 'w') as f:
            json.dump(port_map, f, indent=2)

        info("*** Port map (salvata in %s)\n" % path)
        for name in sorted(port_map):
            d = port_map[name]
            info("    %-7s %-11s %s  ->  %s porta %d\n"
                 % (name, d['ip'], d['mac'], d['switch'], d['port']))

    # ------------------------------------------------------------------
    # Traffico benigno con iperf
    #
    # Nota implementativa: i processi di traffico sono avviati con
    # host.popen() e non con host.cmd('... &'). Ogni host Mininet dispone
    # di una sola shell: i processi lanciati in background con cmd() ne
    # restano figli e vengono terminati non appena la shell viene
    # riutilizzata (ad esempio da un comando digitato nella CLI). Con
    # popen() ciascun processo e' indipendente e sopravvive per l'intera
    # durata dell'esperimento.
    # ------------------------------------------------------------------
    def start_servers(self):
        """
        Server iperf sulla vittima e sull'honeypot.

        L'honeypot espone gli stessi servizi della vittima: e' cio' che
        rende credibile il dirottamento, perche' l'attaccante ritrova le
        porte che si aspetta di trovare invece di trovare tutto chiuso.
        """
        info("*** Starting iperf servers\n")
        for host in (self.h_srv, self.h_pot):
            for port in SERVICE_PORTS:
                p = host.popen('iperf -s -p %d' % port,
                               stdout=open(os.devnull, 'w'),
                               stderr=open(os.devnull, 'w'))
                self.procs.append(p)
            p = host.popen('iperf -s -u -p %d' % VOIP_PORT,
                           stdout=open(os.devnull, 'w'),
                           stderr=open(os.devnull, 'w'))
            self.procs.append(p)
        time.sleep(1)

    def _write_client_script(self, path, target, rate, logfile):
        """
        Genera lo script del client benigno.

        L'attesa fra una sessione e la successiva e' esponenziale, quindi
        gli arrivi seguono un processo di Poisson. Con intervalli fissi la
        baseline risulterebbe innaturalmente regolare e le soglie derivate
        sarebbero troppo strette: al primo burst legittimo il detector
        produrrebbe un falso positivo.
        """
        ports = ' '.join(str(p) for p in SERVICE_PORTS)
        script = """#!/bin/bash
PORTS=(%s)
while true; do
    P=${PORTS[$RANDOM %% ${#PORTS[@]}]}
    iperf -c %s -p $P -n %s >> %s 2>&1 || true
    sleep $(awk -v r=%s 'BEGIN{srand(); print -log(1-rand())/r}')
done
""" % (ports, target, SESSION_SIZE, logfile, rate)
        with open(path, 'w') as f:
            f.write(script)
        os.chmod(path, 0o755)

    def _write_voip_script(self, path, target):
        """Flusso UDP costante: fornisce jitter e packet loss."""
        script = """#!/bin/bash
while true; do
    iperf -c %s -u -p %d -t %d -b %s >> /tmp/voip.log 2>&1 || true
done
""" % (target, VOIP_PORT, VOIP_LEN, VOIP_BW)
        with open(path, 'w') as f:
            f.write(script)
        os.chmod(path, 0o755)

    def start_traffic(self):
        info("*** Starting benign traffic (iperf)\n")
        target = self.h_srv.IP()

        specs = [
            (self.h_ben1, MEAN_RATE, '/tmp/ben1.log', '/tmp/client1.sh'),
            (self.h_ben2, MEAN_RATE * 0.8, '/tmp/ben2.log', '/tmp/client2.sh'),
        ]
        for host, rate, log, script in specs:
            self._write_client_script(script, target, rate, log)
            p = host.popen(script, stdout=open(os.devnull, 'w'),
                           stderr=open(os.devnull, 'w'))
            self.procs.append(p)

        self._write_voip_script('/tmp/voip.sh', target)
        p = self.h_ben3.popen('/tmp/voip.sh', stdout=open(os.devnull, 'w'),
                              stderr=open(os.devnull, 'w'))
        self.procs.append(p)

        info("    h_ben1, h_ben2: sessioni TCP da %s su %d porte (Poisson)\n"
             % (SESSION_SIZE, len(SERVICE_PORTS)))
        info("    h_ben3: flusso UDP costante %s\n" % VOIP_BW)

    def stop_traffic(self):
        info("*** Stopping benign traffic\n")
        for p in self.procs:
            try:
                p.terminate()
            except Exception:
                pass
        for host in self.net.hosts:
            host.cmd('pkill -f iperf 2>/dev/null')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Topologia NCIs honeypot SDN')
    parser.add_argument('--no-traffic', action='store_true',
                        help='avvia solo la topologia, senza traffico')
    args = parser.parse_args()

    setLogLevel('info')
    info('starting the environment\n')
    env = Environment(with_traffic=not args.no_traffic)

    info("*** Running CLI\n")
    info("    Attacco:  h_att nmap -sS -p 1-1000 10.0.0.100\n")
    info("    Flussi:   sh ovs-ofctl -O OpenFlow13 dump-flows s1\n")
    info("    Trunk:    sh tcpdump -i s1-eth5 -nn\n\n")
    CLI(env.net)

    env.stop_traffic()
    env.net.stop()
