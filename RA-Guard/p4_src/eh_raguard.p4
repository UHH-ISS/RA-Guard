/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<128> ip6Addr_t;

//------------------------------------------------------------------------------
// CONSTANT VALUES
//------------------------------------------------------------------------------
#define CPU_PORT 255
#define MAX_HEADER 8
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<8>  IP_PROTO_ICMPV6 = 58;
const bit<8>  IP_EH_HBH = 0;
const bit<8>  IP_EH_ROUTING = 43;
const bit<8>  IP_EH_FRAGMENT = 44;
const bit<8>  IP_EH_DEST_OPTIONS = 60;
const bit<8>  ICMPV6_TYPE_RA = 134;
const bit<8>  NDP_SOURCE_OPTION = 1;
const bit<8>  NDP_TARGET_OPTION = 2;
const bit<8>  NDP_PREFIX_OPTION = 3;
const bit<8>  NDP_REDIRECT_OPTION = 4;
const bit<8>  NDP_MTU_OPTION = 5;
const macAddr_t MCAST_MASK = 0xFF_FF_00_00_00_00;
const macAddr_t IPV6_MCAST = 0x33_33_00_00_00_00;
const bit<10> LINK_LOCAL = 0x3FA;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    traffic_class;
    bit<20>   flow_label;
    bit<16>   payload_len;
    bit<8>    next_hdr;
    bit<8>    hop_limit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

header hop_by_hop_t {
    bit<8>      next_hdr;
    bit<8>      length;  // totallength: (length+1) * 8Byte
    varbit<1024> options;
}

struct next_extension_header {
    bit<8>      next_hdr;
    bit<8>      length;
}

header routing_t {
    bit<8>      next_hdr;
    bit<8>      length;  // totallength: (length+1) * 8Byte
    bit<8>      type;
    bit<8>      segments;
    //bit<32> data;
    varbit<1024> data;
}

header fragment_t {
    bit<8>    next_hdr;
    bit<8>    reserved;
    bit<13>   offset; // Offset, in 8B units, relative to the start of the fragmentable part of the original packet.
    bit<2>    res;
    bit<1>    m_flag; // m=0: last fragment
    bit<32>   identification;
}

header dest_options_t {
    bit<8>       next_hdr;
    bit<8>       length;  // totallength: (length+1) * 8Byte
    //bit<48>  options;
    varbit<1024>  options;
}

header icmpv6_t {
    bit<8>   type;
    bit<8>   code;
    bit<16>  checksum;
}

header ndp_ra_t {
    bit<8>       hop_limit;
    bit<2>       flags;
    bit<6>       reserved;
    bit<16>      lifetime;
    bit<32>      reachable_time;
    bit<32>      retrans_timer;
}

header ndp_ll_addr_t {
    bit<8>       type;
    bit<8>       length;
    macAddr_t    Addr;
}

header ndp_prefix_t {
    bit<8>       type;
    bit<8>       length;
    bit<8>       prefix_length;
    bit<2>       flags;
    bit<6>       reserved;
    bit<32>      valid_lifetime;
    bit<32>      preferred_lifetime;
    bit<32>      prefix_reserved;
    ip6Addr_t    prefix;
}

header ndp_redirect_t {
    bit<8>       type;
    bit<8>       length;
    bit<16>      reserved;
    bit<128>     original_pkt; // TODO: use varbit and length
    ip6Addr_t    prefix;
}

header ndp_mtu_t {
    bit<8>       type;
    bit<8>       length;
    bit<16>      reserved;
    bit<32>      mtu;
}


struct metadata_t {
    bool            is_multicast;
    bool            is_blocked;
}

@controller_header("packet_in")
header packet_in_t {
    bit<9> ingress_port;
    bit<1> is_blocked;
    bit<1> is_learned;
    bit<5> padding;
}

@controller_header("packet_out")
header packet_out_t {
    bit<9> egress_port;
    bit<7> padding;
}

struct headers_t {
    packet_out_t   packet_out;
    packet_in_t    packet_in;
    ethernet_t     ethernet;
    ipv6_t         ipv6;
    hop_by_hop_t[MAX_HEADER]   hop_by_hop;
    routing_t[MAX_HEADER]      routing;
    fragment_t[MAX_HEADER]     fragment;
    dest_options_t[MAX_HEADER] dest_options;
    icmpv6_t       icmpv6;
    ndp_ra_t       ndp_ra;
    ndp_ll_addr_t  ndp_ll_source;
    ndp_ll_addr_t  ndp_ll_target;
    ndp_prefix_t   ndp_prefix;
    ndp_redirect_t ndp_redirect;
    ndp_mtu_t      ndp_mtu;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IP_EH_HBH: parse_hbh;
            IP_EH_ROUTING: parse_routing;
            IP_EH_FRAGMENT: parse_fragment;
            IP_EH_DEST_OPTIONS: parse_dest_options;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_hbh {
        bit<32> field_length = (bit<32>) packet.lookahead<next_extension_header>().length;
        bit<32> field_size = (field_length * 64) + 48;
        packet.extract(hdr.hop_by_hop.next, field_size);
        transition select(hdr.hop_by_hop.last.next_hdr) {
            IP_EH_HBH: parse_hbh;
            IP_EH_ROUTING: parse_routing;
            IP_EH_FRAGMENT: parse_fragment;
            IP_EH_DEST_OPTIONS: parse_dest_options;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_routing {
        bit<32> field_length = (bit<32>) packet.lookahead<next_extension_header>().length;
        bit<32> field_size = (field_length * 64) + 32;
        packet.extract(hdr.routing.next, field_size);
        transition select(hdr.routing.last.next_hdr) {
            IP_EH_HBH: parse_hbh;
            IP_EH_ROUTING: parse_routing;
            IP_EH_FRAGMENT: parse_fragment;
            IP_EH_DEST_OPTIONS: parse_dest_options;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_fragment {
        packet.extract(hdr.fragment.next);
        transition select(hdr.fragment.last.next_hdr) {
            IP_EH_HBH: parse_hbh;
            IP_EH_ROUTING: parse_routing;
            IP_EH_FRAGMENT: parse_fragment;
            IP_EH_DEST_OPTIONS: parse_dest_options;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_dest_options {
        bit<32> field_length = (bit<32>) packet.lookahead<next_extension_header>().length;
        bit<32> field_size = (field_length * 64) + 48;
        packet.extract(hdr.dest_options.next, field_size);
        transition select(hdr.dest_options.last.next_hdr) {
            IP_EH_HBH: parse_hbh;
            IP_EH_ROUTING: parse_routing;
            IP_EH_FRAGMENT: parse_fragment;
            IP_EH_DEST_OPTIONS: parse_dest_options;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition select(hdr.icmpv6.type) {
            ICMPV6_TYPE_RA: parse_ndp_ra;
            default: accept;
        }
    }

    state parse_ndp_ra {
        packet.extract(hdr.ndp_ra);
        transition parse_ndp_options;
    }

    state parse_ndp_options {
        //TODO handle other option types
        transition select(packet.lookahead<bit<8>>()) {
            NDP_SOURCE_OPTION: parse_ndp_source;
            NDP_TARGET_OPTION: parse_ndp_target;
            NDP_PREFIX_OPTION: parse_ndp_prefix;
            NDP_REDIRECT_OPTION: parse_ndp_redirect;
            NDP_MTU_OPTION: parse_ndp_mtu;
        }
    }

    state parse_ndp_source {
        packet.extract(hdr.ndp_ll_source);
        transition parse_ndp_options;
    }

    state parse_ndp_target {
        packet.extract(hdr.ndp_ll_target);
        transition parse_ndp_options;
    }

    state parse_ndp_prefix {
        packet.extract(hdr.ndp_prefix);
        transition parse_ndp_options;
    }

    state parse_ndp_redirect {
        packet.extract(hdr.ndp_redirect);
        transition parse_ndp_options;
    }

    state parse_ndp_mtu {
        packet.extract(hdr.ndp_mtu);
        transition parse_ndp_options;
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {  
        //TODO 
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {

        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table dmac {
        key = {
            hdr.ethernet.dstAddr: exact;
        }

        actions = {
            forward;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }


    action set_mcast_grp(bit<16> mcast_grp) {
        standard_metadata.mcast_grp = mcast_grp;
        meta.is_multicast = true;
    }

    table multicast {

        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            set_mcast_grp;
            NoAction;
        }
        size = 32;
        default_action =  NoAction;

    }

    action send_to_cpu() {
        meta.is_blocked = true;
        standard_metadata.egress_spec = CPU_PORT;
        exit;
    }

    table check_ra {

        key = {
            hdr.ethernet.srcAddr: exact;
            //hdr.ndp_ll_source.srcAddr: exact;
            standard_metadata.ingress_port : exact;
            hdr.ipv6.srcAddr: exact;
            hdr.ndp_prefix.prefix: exact;
        }
        actions = {
            NoAction;
            send_to_cpu;
        }
        size = 32;
        default_action =  send_to_cpu;

    }

    apply {
        if (hdr.ndp_ra.isValid() && (hdr.ipv6.srcAddr[127:118]) == LINK_LOCAL && hdr.ipv6.hop_limit == 255){
            check_ra.apply();
        }
        if ((hdr.ethernet.dstAddr & MCAST_MASK) == IPV6_MCAST) {
            multicast.apply();
        }
        else {
            dmac.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {


    apply {
        if (standard_metadata.egress_port == CPU_PORT) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_metadata.ingress_port;
            hdr.packet_in.is_blocked = (bit<1>) meta.is_blocked;
            exit;
        }
        if (meta.is_multicast == true && standard_metadata.ingress_port == standard_metadata.egress_port) {
            mark_to_drop(standard_metadata);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
     apply {
        //TODO
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        //parsed headers have to be added again into the packet.
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.hop_by_hop);
        packet.emit(hdr.dest_options);
        packet.emit(hdr.routing);
        packet.emit(hdr.fragment);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ndp_ra);
        packet.emit(hdr.ndp_ll_source);
        packet.emit(hdr.ndp_ll_target);
        packet.emit(hdr.ndp_prefix);
        packet.emit(hdr.ndp_redirect);
        packet.emit(hdr.ndp_mtu);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
