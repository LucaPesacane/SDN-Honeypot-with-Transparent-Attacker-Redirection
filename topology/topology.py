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
#   - attaccante e vittima sono entrambi su s1: il traffico legittimo non
#     attraversa mai il link inter-switch
#   - l'honeypot e' su s2: quando il controller rileva l'attacco e devia il
#     flusso, il traffico compare sul trunk s1-s2 (verificabile con tcpdump)
#   - h_ben3 e' su s2 per avere traffico legittimo anche sul trunk
#
# Piano di indirizzamento (10.0.0.0/24):
#   h_att   10.0.0.10   00:00:00:00:00:10   attaccante
#   h_ben1  10.0.0.11   00:00:00:00:00:11   host benigno
#   h_ben2  10.0.0.12   00:00:00:00:00:12   host benigno
#   h_ben3  10.0.0.13   00:00:00:00:00:13   host benigno (su s2)
#   h_srv   10.0.0.100  00:00:00:00:01:00   server vittima
#   h_pot   10.0.0.200  00:00:00:00:02:00   honeypot
#
# Uso:
#   sudo python3 topology.py
#

import json

from mininet.log import setLogLevel, info
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch
from mininet.link import TCLink
from mininet.node import RemoteController


class Environment(object):

    def __init__(self):
        "Create a network."
        self.net = Mininet(controller=RemoteController, link=TCLink)

        info("*** Starting controller\n")
        c1 = self.net.addController('c1', controller=RemoteController)
        c1.start()

        info("*** Adding hosts and switches\n")
        # --- segmento di produzione (s1) ---
        self.h_att = self.net.addHost('h_att',
                                      mac='00:00:00:00:00:10',
                                      ip='10.0.0.10/24')
        self.h_ben1 = self.net.addHost('h_ben1',
                                       mac='00:00:00:00:00:11',
                                       ip='10.0.0.11/24')
        self.h_ben2 = self.net.addHost('h_ben2',
                                       mac='00:00:00:00:00:12',
                                       ip='10.0.0.12/24')
        self.h_srv = self.net.addHost('h_srv',
                                      mac='00:00:00:00:01:00',
                                      ip='10.0.0.100/24')
        # --- segmento honeypot (s2) ---
        self.h_ben3 = self.net.addHost('h_ben3',
                                       mac='00:00:00:00:00:13',
                                       ip='10.0.0.13/24')
        self.h_pot = self.net.addHost('h_pot',
                                      mac='00:00:00:00:02:00',
                                      ip='10.0.0.200/24')

        self.prod = self.net.addSwitch('s1', cls=OVSKernelSwitch,
                                       dpid='0000000000000001',
                                       protocols='OpenFlow13')
        self.hpot = self.net.addSwitch('s2', cls=OVSKernelSwitch,
                                       dpid='0000000000000002',
                                       protocols='OpenFlow13')

        info("*** Adding links\n")
        # link di accesso: s1
        self.net.addLink(self.h_att, self.prod, bw=10, delay='1ms')
        self.net.addLink(self.h_ben1, self.prod, bw=10, delay='1ms')
        self.net.addLink(self.h_ben2, self.prod, bw=10, delay='1ms')
        self.net.addLink(self.h_srv, self.prod, bw=10, delay='1ms')
        # link di accesso: s2
        self.net.addLink(self.h_ben3, self.hpot, bw=10, delay='1ms')
        self.net.addLink(self.h_pot, self.hpot, bw=10, delay='1ms')
        # trunk inter-switch
        self.trunk = self.net.addLink(self.prod, self.hpot,
                                      bw=20, delay='2ms')

        info("*** Starting network\n")
        self.net.build()
        self.net.start()

        self.export_portmap()

    def export_portmap(self, path='port_map.json'):
        """
        Esporta la mappa host -> (switch, dpid, porta) su file JSON.

        Il controller deve sapere su quale porta e' attestato l'honeypot per
        costruire l'azione OFPActionOutput della regola di redirezione.
        Leggere la mappa da qui evita di cablare i numeri di porta nel codice
        del controller.
        """
        port_map = {}
        for host in self.net.hosts:
            for intf in host.intfList():
                if not intf.link:
                    continue
                peer = (intf.link.intf2 if intf.link.intf1 == intf
                        else intf.link.intf1)
                port_map[host.name] = {
                    'ip': host.IP(),
                    'mac': host.MAC(),
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


if __name__ == '__main__':

    setLogLevel('info')
    info('starting the environment\n')
    env = Environment()

    info("*** Running CLI\n")
    CLI(env.net)
    env.net.stop()
