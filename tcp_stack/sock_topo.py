#!/usr/bin/python

from mininet.node import OVSBridge
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink

import time

class TCPTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        s1 = self.addSwitch('s1')

        # Delay: 1ms, Packet Drop Rate: 2%
        self.addLink(h1, s1, delay='1ms', loss=2)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

if __name__ == '__main__':
    topo = TCPTopo()
    net = Mininet(topo = topo, switch = OVSBridge, controller = None, link=TCLink)

    h1, h2, h3, s1 = net.get('h1', 'h2', 'h3', 's1')
    h1.cmd('ifconfig h1-eth0 10.0.0.1/24')
    h2.cmd('ifconfig h2-eth0 10.0.0.2/24')
    h3.cmd('ifconfig h3-eth0 10.0.0.3/24')

    s1.cmd('scripts/disable_ipv6.sh')

    for h in (h1, h2, h3):
        h.cmd('scripts/disable_ipv6.sh')
        h.cmd('scripts/disable_offloading.sh')
        h.cmd('scripts/disable_tcp_rst.sh')

    net.start()

    CLI(net)

    net.stop()
