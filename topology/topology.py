import threading
import random
import time
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, Host
from mininet.link import TCLink, Link
from mininet.node import RemoteController


class Environment(object):

    def __init__(self):
        "Create a network."
        self.net = Mininet(controller=RemoteController, link=TCLink)

        info("*** Starting controller\n")
        c1 = self.net.addController('c1', controller=RemoteController)
        c1.start()

        info("*** Adding hosts\n")
        self.h_att = self.net.addHost('h_att', mac='00:00:00:00:00:10', ip='10.0.0.10/24')
        self.h_ben1 = self.net.addHost('h_ben1', mac='00:00:00:00:00:11', ip='10.0.0.11/24')
        self.h_ben2 = self.net.addHost('h_ben2', mac='00:00:00:00:00:12', ip='10.0.0.12/24')
        self.h_srv = self.net.addHost('h_srv', mac='00:00:00:00:01:00', ip='10.0.0.100/24')

        self.h_ben3 = self.net.addHost('h_ben3', mac='00:00:00:00:00:13', ip='10.0.0.13/24')
        self.h_pot = self.net.addHost('h_pot', mac='00:00:00:00:02:00', ip='10.0.0.200/24')
        
        info("*** Adding switches\n")
        self.s1 = self.net.addSwitch('s1', cls=OVSKernelSwitch, dpid='0000000000000001', protocols='OpenFlow13')
        self.s2 = self.net.addSwitch('s2', cls=OVSKernelSwitch, dpid='0000000000000002', protocols='OpenFlow13')

        info("*** Adding links\n")
        self.net.addLink(self.h_att, self.s1, bw=10, delay='1ms')
        self.net.addLink(self.h_ben1, self.s1, bw=10, delay='1ms')
        self.net.addLink(self.h_ben2, self.s1, bw=10, delay='1ms')
        self.net.addLink(self.h_srv, self.s1, bw=10, delay='1ms')
        self.net.addLink(self.h_ben3, self.s2, bw=10, delay='1ms')
        self.net.addLink(self.h_pot, self.s2, bw=10, delay='1ms')
        self.net.addLink(self.s1, self.s2, bw=20, delay='2ms')

        info("*** Starting network\n")
        self.net.build()
        self.net.start()


if __name__ == '__main__':

    setLogLevel('info')
    info('starting the environment\n')
    env = Environment()
    
    info("*** Running CLI\n")
    CLI(env.net)
    env.net.stop()
