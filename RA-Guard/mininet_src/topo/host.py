from ipmininet.host import IPHost
from mininet.log import info, error, debug


class MyHost(IPHost):
    def config(self, cmd=None, **params):
        r = super(IPHost, self).config(**params)
        # run tcpdump
        for intf in self.intfList():
            info("tcpdump on ", intf, "\n")
            self.cmd(f"tcpdump -U -i {intf} -w pcaps/{intf}.pcap &")
        if cmd:
            info("run cmd: '", cmd, "'\n")
            self.cmd(cmd)
        return r

    def IP(self, **params):
        ips = []
        for intf in self.intfList():
            ips = ips + list(intf.ip6s())
        return ips
