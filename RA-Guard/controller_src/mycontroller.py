#!/usr/bin/python3
import sys
import p4runtime_sh.shell as sh
from table_entries import attackTopology, simpleToplogy, addDefaultRouter
from scapy.all import Ether
from time import time
import re
import curses
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--p4-init", "-p4",
                    help="Name of the P4 program to initialize the data plane with")
parser.add_argument("--topology", "-t", default="attack",
                    help="Name of the topology that should be used to setup the forwarding table")
parser.add_argument("--default-router", "-d", action="store_true",
                    help="Insert preconfigured router information for RA filtering")
parser.add_argument("--stateful", "-sf", action="store_true",
                    help="Initiate stateful RA learning")
parser.add_argument("--stateless", "-sl", action="store_true",
                    help="Set RA-Guard in stateless mode")
parser.add_argument("--off", "-o", action="store_true",
                    help="Deactivate RA-Guard filtering")
parser.add_argument("--learning-period", "-p", default=10, type=int,
                    help="set the time period in seconds for the LEARNING state")
parser.add_argument("--monitor", "-m", action="store_true",
                    help="Monitor RA incidents")
subparsers = parser.add_subparsers(dest='router')
router_parser = subparsers.add_parser('router', help="Manually add legitimate router information for RA filtering")
router_parser.add_argument('srcMAC')
router_parser.add_argument('ingress_port')
router_parser.add_argument('srcIP')
router_parser.add_argument('prefix')
args = parser.parse_args()


# Connect the controller to the P4-Switch
# initialise the P4 programm and setup the topology
def setup_sh(p4_init, topology):
    if p4_init:
        sh.setup(
            device_id=0,
            grpc_addr='172.17.0.2:50051',
            election_id=(0, 1),  # (high, low)
            config=sh.FwdPipeConfig('p4build/{}.p4info.txt'.format(p4_init),
                                    'p4build/{}.json'.format(p4_init)))
        if topology == "attack":
            attackTopology(sh)
        elif topology == "simple":
            simpleToplogy(sh)
    else:
        sh.setup(
            device_id=0,
            grpc_addr='172.17.0.2:50051',
            election_id=(0, 1))


# Add the legitimate RA information in either stateless or stateful way
# Transition the interfaces to the proper state
def setup_router(args):
    if args.p4_init and args.default_router and "raguard" in args.p4_init:
        addDefaultRouter(sh)
    if args.router:
        add_router(args.ingress_port, args.srcMAC, args.srcIP, args.prefix)
    if args.stateful:
        learn_router(args.learning_period)
    elif args.stateless:
        print("Transition interfaces to FORWARDING state")
        for port in get_all_ports():
            set_state("forwarding", port)
    elif args.off:
        print("Transition interfaces to OFF state")
        for port in get_all_ports():
            set_state("off", port)


# Add legitimate RA information to the P4-Switch
def add_router(ingress_port, srcMAC, srcIP, prefix):
    if ingress_port and srcMAC and srcIP and prefix:
        print("Add Router:")
        print(format_identifier(ingress_port, srcMAC, srcIP, prefix))
        te = sh.TableEntry("MyIngress.check_ra")(action="NoAction")
        te.match["hdr.ethernet.srcAddr"] = srcMAC
        te.match["standard_metadata.ingress_port"] = ingress_port
        te.match["hdr.ipv6.srcAddr"] = srcIP
        te.match["hdr.ndp_prefix.prefix"] = prefix
        if len(list(te.read())):
            te.modify()
        else:
            te.insert()


# Extract the relevant information from the received packet.
def parse_packet(packet):
    ingress_port = str(int.from_bytes(packet.metadata[0].value, "big"))
    blocked = int.from_bytes(packet.metadata[1].value, "big")
    learned = int.from_bytes(packet.metadata[2].value, "big")
    pkt = Ether(packet.payload)
    srcMAC = pkt.src
    srcIP = pkt.getlayer("IPv6").src if pkt.haslayer("IPv6") else None
    prefix = pkt.getlayer("ICMPv6NDOptPrefixInfo").prefix \
        if pkt.haslayer("ICMPv6NDOptPrefixInfo") else None
    identifier = (ingress_port, srcMAC, srcIP, prefix)
    details = pkt.show2(dump=True)
    return blocked, learned, identifier, details


# Format the output for the aggregated incidents
def format_incidents(incidents):
    output = ""
    for i in incidents:
        output += f"Count: {incidents[i]}\n"
        output += format_identifier(*i)
    return output


# Format the output for the RA identifying information
def format_identifier(ingress_port, srcMAC, srcIP, prefix):
    output = f"\
    Port:      {ingress_port}\n\
    SrcMAC:    {srcMAC}\n\
    SrcIP:     {srcIP}\n\
    Prefix:    {prefix}\n"
    return output


# Receive blocked packets and print them in a human readable way
def monitor_incidents():
    print("Start Monitoring")
    stdscr = curses.initscr()
    stream = sh.client.stream_in_q
    incidents = {}
    while True:
        stdscr.clear()
        msg = stream.get()
        blocked, learned, identifier, details = parse_packet(msg.packet)
        if not blocked:
            continue
        if identifier not in incidents:
            incidents[identifier] = 0
        incidents[identifier] += 1
        stdscr.addstr(0, 0, format_incidents(incidents))
        stdscr.addstr(len(incidents)*5, 0, "\n###### Last Incident: ######\n")
        max_size = stdscr.getmaxyx()[0] - len(incidents) * 5 - 2
        output = "\n".join(details.splitlines()[0:max_size])
        stdscr.addstr(output)
        stdscr.refresh()


# Obtain all the P4-Switch ports from the forwarding table
def get_all_ports():
    ports = []
    for entry in sh.TableEntry("MyIngress.dmac").read():
        msg = entry.action.msg()
        port = str(int.from_bytes(msg.params[0].value, "big"))
        ports.append(port)
    return ports


# Change the port to a specified state
# possible states: off, blocking, learning, forwarding
def set_state(state, port):
    action = "NoAction" if state == "off" else f"MyIngress.{state}"
    te = sh.TableEntry("MyIngress.interface_state")(action=action)
    te.match["standard_metadata.ingress_port"] = str(port)
    # Check if entry is existing
    if len(list(te.read())):
        te.modify()
    else:
        te.insert()
    return


# Stateful RA-Guard
# Learn RA information from received RAs during the learning period
# and add them as legitimate RAs
def learn_router(learning_period):
    print("Transition interfaces to LEARNING State")
    for port in get_all_ports():
        set_state("learning", port)
    print("Start Learning Phase")
    start_time = time()
    stream = sh.client.stream_in_q
    router = []
    while (start_time + learning_period) > time():
        msg = stream.get()
        blocked, learned, identifier, details = parse_packet(msg.packet)
        if learned and identifier not in router:
            router.append(identifier)
            add_router(*identifier)
    print("End Learning Phase")
    print("Transition interfaces of learned router to FORWARDING state")
    router_ports = [i[0] for i in router]
    for port in router_ports:
        set_state("forwarding", port)
    print("Transition other interfaces BLOCKING state")
    for port in get_all_ports():
        if port not in router_ports:
            set_state("blocking", port)


if __name__ == "__main__":
    setup_sh(args.p4_init, args.topology)
    setup_router(args)
    if args.monitor:
        monitor_incidents()
    sh.teardown()
