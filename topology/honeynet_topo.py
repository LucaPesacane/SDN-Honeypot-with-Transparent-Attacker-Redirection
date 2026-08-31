#!/usr/bin/env python3
"""
honeynet_topo.py - Topologia Mininet per il project work NCIs
SDN-based attack detection and transparent honeypot redirection

Topologia di default (2 switch):

   h_att   h_ben1   h_ben2   h_srv                 h_ben3   h_pot
     |       |        |        |                      |       |
    [--------------- s1 ---------------]----------[----- s2 -----]
          SEGMENTO DI PRODUZIONE                  SEGMENTO HONEYPOT

  - attaccante e vittima sono entrambi su s1: il traffico legittimo NON
    attraversa mai il link inter-switch
  - l'honeypot e' su s2: quando il controller rileva un attacco e devia il
    flusso, il traffico compare sul link s1-s2. Il contrasto e' immediato
    da mostrare con tcpdump sull'interfaccia di trunk.
  - h_ben3 sta su s2 per avere traffico legittimo anche sul link
    inter-switch (serve a dimostrare che la redirezione non lo degrada)

Piano di indirizzamento (10.0.0.0/24):
  h_att   10.0.0.10   00:00:00:00:00:10   attaccante
  h_ben1  10.0.0.11   00:00:00:00:00:11   host benigno
  h_ben2  10.0.0.12   00:00:00:00:00:12   host benigno
  h_ben3  10.0.0.13   00:00:00:00:00:13   host benigno (su s2)
  h_srv   10.0.0.100  00:00:00:00:01:00   server vittima
  h_pot   10.0.0.200  00:00:00:00:02:00   honeypot

Uso:
  sudo python3 honeynet_topo.py                # CLI interattiva, 2 switch
  sudo python3 honeynet_topo.py --test         # pingall e termina
  sudo python3 honeynet_topo.py --switches 3   # variante a 3 switch
"""

import argparse
import json

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

CONTROLLER_IP = '127.0.0.1'
CONTROLLER_PORT = 6653
OF_PROTO = 'OpenFlow13'

# Ruoli logici: il controller li rilegge da port_map.json
ATTACKER = '10.0.0.10'
VICTIM = '10.0.0.100'
HONEYPOT = '10.0.0.200'

ACCESS_BW = 50
ACCESS_DELAY = '1ms'
TRUNK_BW = 100
TRUNK_DELAY = '2ms'

# (nome, ip, mac, switch nella variante 2sw, switch nella variante 3sw)
HOSTS = [
    ('h_att',  '10.0.0.10',  '00:00:00:00:00:10', 's1', 's1'),
    ('h_ben1', '10.0.0.11',  '00:00:00:00:00:11', 's1', 's1'),
    ('h_ben2', '10.0.0.12',  '00:00:00:00:00:12', 's1', 's2'),
    ('h_srv',  '10.0.0.100', '00:00:00:00:01:00', 's1', 's1'),
    ('h_ben3', '10.0.0.13',  '00:00:00:00:00:13', 's2', 's2'),
    ('h_pot',  '10.0.0.200', '00:00:00:00:02:00', 's2', 's3'),
]


def build_network(n_switches):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink,
                  autoSetMacs=False, autoStaticArp=False, build=False)

    info('*** Controller remoto (Ryu) su %s:%d\n'
         % (CONTROLLER_IP, CONTROLLER_PORT))
    net.addController('c0', controller=RemoteController,
                      ip=CONTROLLER_IP, port=CONTROLLER_PORT)

    info('*** Switch\n')
    switches = {}
    for i in range(1, n_switches + 1):
        name = 's%d' % i
        switches[name] = net.addSwitch(name, dpid=str(i).zfill(16),
                                       protocols=OF_PROTO)

    info('*** Host e link di accesso\n')
    col = 3 if n_switches == 2 else 4
    for row in HOSTS:
        name, ip, mac = row[0], row[1], row[2]
        sw = row[col]
        h = net.addHost(name, ip='%s/24' % ip, mac=mac)
        net.addLink(h, switches[sw], bw=ACCESS_BW, delay=ACCESS_DELAY)

    info('*** Link inter-switch (catena lineare, nessun loop)\n')
    for i in range(1, n_switches):
        net.addLink(switches['s%d' % i], switches['s%d' % (i + 1)],
                    bw=TRUNK_BW, delay=TRUNK_DELAY)

    net.build()
    return net


def export_portmap(net, path='port_map.json'):
    """
    Esporta la mappa host -> (switch, porta) su file JSON.

    Il controller deve sapere su quale porta e' attestato l'honeypot per
    costruire l'azione OFPActionOutput della regola di redirezione.
    Leggerla da qui evita di cablare numeri di porta nel codice del
    controller, che cambierebbero al variare della topologia.
    """
    port_map = {}
    for host in net.hosts:
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

    info('\n*** Mappa porte (salvata in %s)\n' % path)
    for name, d in sorted(port_map.items()):
        info('    %-7s %-11s %s  ->  %s porta %d\n' %
             (name, d['ip'], d['mac'], d['switch'], d['port']))
    info('\n')


def main():
    parser = argparse.ArgumentParser(description='Topologia NCIs honeypot SDN')
    parser.add_argument('--test', action='store_true',
                        help='esegue pingall e termina')
    parser.add_argument('--switches', type=int, default=2, choices=(2, 3),
                        help='numero di switch (default: 2)')
    args = parser.parse_args()

    setLogLevel('info')
    net = build_network(args.switches)

    info('*** Avvio rete\n')
    net.start()
    export_portmap(net)

    if args.test:
        result = net.pingAll()
        net.stop()
        raise SystemExit(0 if result == 0 else 1)

    info('*** Rete pronta.\n')
    info('    Ruoli:  attaccante %s | vittima %s | honeypot %s\n'
         % (ATTACKER, VICTIM, HONEYPOT))
    info('    Prova:  h_att ping h_srv\n')
    info('    Flow:   sh ovs-ofctl -O OpenFlow13 dump-flows s1\n')
    info('    Trunk:  sh tcpdump -i s1-eth5 -nn\n\n')
    CLI(net)
    net.stop()


if __name__ == '__main__':
    main()
