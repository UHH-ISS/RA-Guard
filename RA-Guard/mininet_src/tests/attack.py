from mininet.util import dumpNodeConnections
from mininet.log import info
from time import sleep


def AttackConnectivityTest(net):
    server = net.get('server')
    host = net.get('host')
    server.cmd("python3 tests/ipv6-httpserver.py &")
    info("Node Connections:\n")
    dumpNodeConnections(net.hosts)
    info("\nWait for Network Discovery...\n")
    info(host.cmd("timeout 60 tcpdump -q -c1 'icmp6 && ip6[40] == 134' 2>/dev/null  && echo 'Router Advertisement Received\n' || echo 'TIMEOUT: NO ROUTER ADVERTISEMENT RECEIVED!\n'"))
    net.ping6All()
    info("\nHost Neighbor Table:\n")
    info(host.cmd("ip -6 neigh"))
    info("\nHost Routing Table:\n")
    info(host.cmd("ip -6 route"))
    info("\nWebserver connectivity:\n")
    info(host.cmd("curl -s server:8080 | head -n1"))


def AttackTest(net):
    AttackConnectivityTest(net)
    host = net.get('host')
    attacker = net.get('attacker')
    info("\nSetup MitM Attack\n")
    attacker.cmd("sysctl -w net.ipv6.conf.all.forwarding=1")
    attacker.cmd("ip6tables -A OUTPUT -p icmpv6 --icmpv6-type redirect -j DROP")
    attacker.cmd("ip -6 route add fe80::200:ff:fe00:11 dev attacker-eth0")
    attacker.cmd("ip -6 route add default via fe80::200:ff:fe00:11 dev attacker-eth0")
    attacker.cmd("echo You have been hacked | ncat -l 8080 &")
    attacker.cmd("ip6tables -t nat -s 2001:42::200:ff:fe00:22 -A POSTROUTING -j MASQUERADE")
    attacker.cmd("ip6tables -t nat -A PREROUTING -j REDIRECT -p tcp --dport 8080 --to-ports 8080")
    info("\nSend simple Rouge RA\n")
    attacker.cmd("sleep 2 && ra6 -ve -i attacker-eth0 -d 2001:42::200:ff:fe00:22 &")
    info("Wait for Rouge RA on host:\n")
    info(host.cmd("timeout 6 tcpdump -q -c1 'src fe80::200:ff:fe00:33 and icmp6 && ip6[40] == 134' 2>/dev/null  && echo 'Router Advertisement Received\n' || echo 'TIMEOUT: NO ROUTER ADVERTISEMENT RECEIVED!\n'"))
    info("Host Routing Table:\n")
    info(host.cmd("ip -6 route"))
    info("\n\nSend Rouge RA with extentions header and fragmentation\n")
    attacker.cmd("sleep 2 && ra6 -ve -i attacker-eth0 -d 2001:42::200:ff:fe00:22 -H 8 -y 800 -U 8 -u 8 &")
    attacker.cmd("sleep 5 && ra6 -ve -i attacker-eth0 -d 2001:42::200:ff:fe00:22 -H 8 -u 8 -u 8 &")
    attacker.cmd("sleep 8 && ra6 -ve -i attacker-eth0 -d 2001:42::200:ff:fe00:22 -y 24 -u 8 -u 8 -u 8 &")
    attacker.cmd("sleep 11 && ra6 -ve -i attacker-eth0 -d 2001:42::200:ff:fe00:22 -y 16 -u 8 -u 8 -u 8 &")
    attacker.cmd("sleep 14 && ra6 -ve -i attacker-eth0 -d 2001:42::200:ff:fe00:22 -y 8 &")
    info("Wait for Rouge RA on host:\n")
    info(host.cmd("timeout 20 tcpdump -q -c1 'src fe80::200:ff:fe00:33 and (ip6[6]=0 or ip6[6]=60 or (ip6[6]=44 and ip6[43]=1))' 2>/dev/null  && echo 'Router Advertisement Received\n' || echo 'TIMEOUT: NO ROUTER ADVERTISEMENT RECEIVED!\n'"))
    sleep(10)
    info("Host Routing Table:\n")
    info(host.cmd("ip -6 route"))
    info("\nTry to access webserver from host: \n")
    info(host.cmd("curl -s server:8080 | head -n1"))
