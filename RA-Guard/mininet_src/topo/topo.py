from ipmininet.iptopo import IPTopo
from ipmininet.router.config import RADVD, AdvConnectedPrefix
from mininet.log import info


class WebserverAttacker(IPTopo):
    def build(self, *args, **kwargs):
        router = self.addRouter('router')
        router.addDaemon(RADVD, debug=0)
        host = self.addHost('host', mac="00:00:00:00:00:22")
        attacker = self.addHost('attacker', mac="00:00:00:00:00:33")
        server = self.addHost('server')
        switch = self.addSwitch('s1')
        link_router_switch = self.addLink(router, switch, txo=False, rxo=False,
                                          addr1="00:00:00:00:00:11")
        self.addLink(switch, host, txo=False, rxo=False)
        self.addLink(switch, attacker, txo=False, rxo=False)
        link_router_switch[router].addParams(ip=("2001:42::1/64"),
                                             ra=[AdvConnectedPrefix()])
        link_router_server = self.addLink(router, server, txo=False, rxo=False)
        link_router_server[router].addParams(ip=("2001:23::1/64"),
                                             ra=[AdvConnectedPrefix()])
        link_router_server[server].addParams(ip=("2001:23::2/64"))
        super().build(*args, **kwargs)


class Simple(IPTopo):
    def build(self, *args, **kwargs):
        h1 = self.addHost('h1', mac="00:00:00:00:00:11",
                          ip=("10.0.0.1/24", "2001:42::1/64"),
                          cmd="ip neigh add 10.0.0.2 dev h1-eth0 lladdr 00:00:00:00:00:22 &\
                          ip neigh add 2001:42::2 dev h1-eth0 lladdr 00:00:00:00:00:22")
        h2 = self.addHost('h2', mac="00:00:00:00:00:22",
                          ip=("10.0.0.2/24", "2001:42::2/64"),
                          cmd="arp -i h2-eth0 -s 10.0.0.1 00:00:00:00:00:11 &\
                          ip neigh add 2001:42::1 dev h2-eth0 lladdr 00:00:00:00:00:11")
        s1 = self.addSwitch('s1')
        self.addLink(s1, h1, txo=False, rxo=False)
        self.addLink(s1, h2, txo=False, rxo=False)
        super().build(*args, **kwargs)
