from mininet.util import dumpNodeConnections
from mininet.log import info
from time import sleep


def SimpleConnectivityTest(net):
    h1 = net.get('h1')
    h2 = net.get('h2')
    h1.cmd("python3 tests/ipv6-httpserver.py &")
    info("Node Connections:\n")
    dumpNodeConnections(net.hosts)
    sleep(10)
    net.ping6All()
    info("Webserver connectivity:\n")
    info(h2.cmd("curl -s h1:8080 | head -n1"))
