#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def myNetwork():
    net = Mininet(build=False, ipBase='10.0.0.0/8')

    info('*** Adding controller\n')
    c0 = net.addController('c0', controller=RemoteController,
                           ip='10.224.78.63', protocol='tcp', port=6653)

    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)

    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    h3 = net.addHost('h3', ip='10.0.0.3')
    h4 = net.addHost('h4', ip='10.0.0.4')

    info('*** Adding links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s2)
    net.addLink(h4, s2)
    net.addLink(s1, s2)

    info('*** Starting network\n')

    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s1.cmd('ovs-vsctl set bridge s1 protocols=OpenFlow13')
    s2.cmd('ovs-vsctl set bridge s2 protocols=OpenFlow13')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()
