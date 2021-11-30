def attackTopology(sh):
    te = sh.TableEntry("MyIngress.dmac")(action="MyIngress.forward")
    te.match["hdr.ethernet.dstAddr"] = "00:00:00:00:00:11"
    te.action["egress_port"] = "1"
    te.insert()
    te = sh.TableEntry("MyIngress.dmac")(action="MyIngress.forward")
    te.match["hdr.ethernet.dstAddr"] = "00:00:00:00:00:22"
    te.action["egress_port"] = "2"
    te.insert()
    te = sh.TableEntry("MyIngress.dmac")(action="MyIngress.forward")
    te.match["hdr.ethernet.dstAddr"] = "00:00:00:00:00:33"
    te.action["egress_port"] = "3"
    te.insert()

    # Use MulticastGroup = 1 for all broadcasting
    me = sh.MulticastGroupEntry(group_id=1)
    me.add(1, 1)
    me.add(2, 1)
    me.add(3, 1)
    me.insert()

    te = sh.TableEntry("MyIngress.multicast")(action="MyIngress.set_mcast_grp")
    te.match["standard_metadata.ingress_port"] = "1"
    te.action["mcast_grp"] = "1"
    te.insert()
    te = sh.TableEntry("MyIngress.multicast")(action="MyIngress.set_mcast_grp")
    te.match["standard_metadata.ingress_port"] = "2"
    te.action["mcast_grp"] = "1"
    te.insert()
    te = sh.TableEntry("MyIngress.multicast")(action="MyIngress.set_mcast_grp")
    te.match["standard_metadata.ingress_port"] = "3"
    te.action["mcast_grp"] = "1"
    te.insert()


def simpleToplogy(sh):
    te = sh.TableEntry("MyIngress.dmac")(action="MyIngress.forward")
    te.match["hdr.ethernet.dstAddr"] = "00:00:00:00:00:11"
    te.action["egress_port"] = "1"
    te.insert()
    te = sh.TableEntry("MyIngress.dmac")(action="MyIngress.forward")
    te.match["hdr.ethernet.dstAddr"] = "00:00:00:00:00:22"
    te.action["egress_port"] = "2"
    te.insert()

    # Use MulticastGroup = 1 for all broadcasting
    me = sh.MulticastGroupEntry(group_id=1)
    me.add(1, 1)
    me.add(2, 1)
    me.insert()

    te = sh.TableEntry("MyIngress.multicast")(action="MyIngress.set_mcast_grp")
    te.match["standard_metadata.ingress_port"] = "1"
    te.action["mcast_grp"] = "1"
    te.insert()
    te = sh.TableEntry("MyIngress.multicast")(action="MyIngress.set_mcast_grp")
    te.match["standard_metadata.ingress_port"] = "2"
    te.action["mcast_grp"] = "1"
    te.insert()


def addDefaultRouter(sh):
    te = sh.TableEntry("MyIngress.check_ra")(action="NoAction")
    te.match["hdr.ethernet.srcAddr"] = "00:00:00:00:00:11"
    te.match["standard_metadata.ingress_port"] = "1"
    te.match["hdr.ipv6.srcAddr"] = "fe80::200:ff:fe00:11"
    te.match["hdr.ndp_prefix.prefix"] = "2001:42::0"
    te.insert()
