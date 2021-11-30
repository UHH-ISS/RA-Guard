from ipmininet.cli import IPCLI
from ipmininet.ipnet import IPNet
from tests import AttackTest, SimpleConnectivityTest
from topo import WebserverAttacker, Simple, MyHost, MySwitch
from mininet.log import setLogLevel, info
import argparse

setLogLevel("info")
parser = argparse.ArgumentParser()
parser.add_argument("topo")
parser.add_argument("--test", action='store_true')
args = parser.parse_args()

if args.topo == "attack":
    net = IPNet(topo=WebserverAttacker(), host=MyHost,
                use_v4=False, allocate_IPs=False)
    test = AttackTest
elif args.topo == "attack-bmv2":
    net = IPNet(topo=WebserverAttacker(),  host=MyHost,
                switch=MySwitch, use_v4=False, allocate_IPs=False)
    test = AttackTest
elif args.topo == "simple-bmv2":
    net = IPNet(topo=Simple(), host=MyHost, switch=MySwitch, allocate_IPs=True)
    test = SimpleConnectivityTest
else:
    net = IPNet(topo=Simple(), host=MyHost, allocate_IPs=True)
    test = SimpleConnectivityTest

net.start()
if args.test:
    info("\n**** Start tests ****\n\n")
    test(net)
    info("\n\n**** End tests ****\n\n")

IPCLI(net)

net.stop()
