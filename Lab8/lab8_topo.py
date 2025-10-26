#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    Controller=net.addController(name='Controller',
                      controller=RemoteController,
                      ip='10.224.78.63',
                      protocol='tcp',
                      port=6653)

    info( '*** Add switches\n')
    OvS7 = net.addSwitch('OvS7', cls=OVSKernelSwitch, dpid='0000000000000007')
    OvS5 = net.addSwitch('OvS5', cls=OVSKernelSwitch, dpid='0000000000000005')
    OvS1 = net.addSwitch('OvS1', cls=OVSKernelSwitch, dpid='0000000000000001')
    OvS6 = net.addSwitch('OvS6', cls=OVSKernelSwitch, dpid='0000000000000006')
    OvS8 = net.addSwitch('OvS8', cls=OVSKernelSwitch, dpid='0000000000000008')
    OvS4 = net.addSwitch('OvS4', cls=OVSKernelSwitch, dpid='0000000000000004')
    OvS3 = net.addSwitch('OvS3', cls=OVSKernelSwitch, dpid='0000000000000003')
    OvS2 = net.addSwitch('OvS2', cls=OVSKernelSwitch, dpid='0000000000000002')

    info( '*** Add hosts\n')
    Server = net.addHost('Server', cls=Host, ip='1.1.1.1', defaultRoute='1.1.1.2')
    H1 = net.addHost('H1', cls=Host, ip='10.0.0.1', defaultRoute='10.0.0.2')

    info( '*** Add links\n')
    net.addLink(H1, OvS1)
    net.addLink(OvS1, OvS2)
    net.addLink(OvS2, OvS3)
    net.addLink(OvS3, OvS4)
    net.addLink(OvS4, OvS5)
    net.addLink(OvS6, OvS7)
    net.addLink(OvS6, OvS1)
    net.addLink(OvS7, OvS5)
    net.addLink(OvS8, OvS1)
    net.addLink(OvS8, OvS5)
    net.addLink(OvS5, Server)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('OvS7').start([Controller])
    net.get('OvS5').start([Controller])
    net.get('OvS1').start([Controller])
    net.get('OvS6').start([Controller])
    net.get('OvS8').start([Controller])
    net.get('OvS4').start([Controller])
    net.get('OvS3').start([Controller])
    net.get('OvS2').start([Controller])
    OvS1.cmd('ovs-vsctl set bridge OvS1 protocols=OpenFlow13')
    OvS2.cmd('ovs-vsctl set bridge OvS2 protocols=OpenFlow13')
    OvS3.cmd('ovs-vsctl set bridge OvS3 protocols=OpenFlow13')
    OvS4.cmd('ovs-vsctl set bridge OvS4 protocols=OpenFlow13')
    OvS5.cmd('ovs-vsctl set bridge OvS5 protocols=OpenFlow13')
    OvS6.cmd('ovs-vsctl set bridge OvS6 protocols=OpenFlow13')
    OvS7.cmd('ovs-vsctl set bridge OvS7 protocols=OpenFlow13')
    OvS8.cmd('ovs-vsctl set bridge OvS8 protocols=OpenFlow13')
    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

