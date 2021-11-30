# IPv6 Neighborhood Discovery (NDP)

- https://tools.ietf.org/html/rfc4861
- Summary: https://packetlife.net/blog/2008/aug/28/ipv6-neighbor-discovery/
- NDP address following problems:
    - Router Discovery 
    - Prefix Discovery (on-link address vs router-reachable address)
    - Address Autoconfiguration
    - Address Resolution (determine the link-layer from IP)
    - Next-hop Determination (which algorithm to use)
    - Neighbor Unreachability Detection
    - Duplicate Address Detection
    - Redirect: better first hop to reach a destination
- Messages:
    - Router Solicitation / Advertisement
    - Neighbor Solicitation / Advertisement
    - Redirect

## ICMPv6 Router Advertisements

- Summary: https://blogs.infoblox.com/ipv6-coe/why-you-must-use-icmpv6-router-advertisements-ras/
- Host sends Router Solicitation (RS)
    - to all-routers multicast group address (ff02::2)
- Router sends Router Advertisment (RA)
    - periodically and as respond to RS
    - all-nodes multicast group address (ff02::1)
    - contains method to obtain their global unicast IPv6 address
        - A-bit: Stateless Address Autoconfiguration (SLAAC)
        - On-Link Flag: prefix listed in the RA is the local IPv6
        - Managed Address Config Flag: stateful DHCPv6
        - Other Config Flag: stateless DHCPv6 
    - global unicast prefix
    - information about local router/default gateway
        - use the link-local address of the router itself
        - Neighborhood Discovery (NDP)
    - send the DNS server and domain search list
        - hosts use it with their SLAAC auto-generated IPv6 addresses.
        - https://tools.ietf.org/html/rfc6106
        - RDNSS deamon for Linux (rdnssd): https://rdnssd.linkfanel.net/

## Configuration Methods

- Stateless Address Autoconfiguration (SLAAC)
    - https://tools.ietf.org/html/rfc4862
        1. host generates a link-local address
            - Duplicate Address Detection
                - sends NS with link-local address as target
                - if used: receive NA with "no"
                - then manual configuration
        2. router advertise global 64-bit prefix (RA)
            - host generate with EUI-64 (extend MAC) second 64-bit of address (interface identifier)
                - Duplicate Address Detection
    - exclusively rely on NDP
    - can't be centralized, can't specify further information (DNS)

- Stateless DHCPv6
    - RA flag called other-config
    - use SLAAC to obtain reachability information, and use DHCPv6 for extra items
    - client sends DHCPv6 request
        - server replies with extra information (like DNS)
    - stateless: DHCPv6 doesn't manage client leases

- Stateful DHCPv6
    - DHCPv6 Server handles leases and extra information
    - https://tools.ietf.org/html/rfc3315
    - DHCPv6 doesn't contain the gateway

##  Attacks

### Rogue Router Advertisements

- https://tools.ietf.org/html/rfc6104
    - every host can send crafted RAs

- IPv6 Network: 
    - destabilize the network (and still perform a MitM attack).

- IPv4 Network:
    - perform MitM attacks
    - SLAAC Attack
        - https://resources.infosecinstitute.com/topic/slaac-attack/
        - The host will use the source address of the RA 
        - NAT-PT: translate IPv4<->IPv6
            - clients access internet over attacker IPv4 interface
        - Setup IPv6 DNS-Server
            - dual stack hosts prefer IPv6
            - NAT-PT translates IPv4 DNS responds to IPv6 DNS responds
        - setup attack: https://github.com/CiscoCXSecurity/suddensix

### Rogue Router Mitigation (RFC6104)

- RA Guard
    - https://tools.ietf.org/html/rfc6105
    - RA Snooping: block RAs from incorrect sources
    - light-weight alternative to SEND
    - filtering in the layer-2 network fabric
        - identify invalids RAs and block them
        - allow/disallow on specific interface
        - allow from pre-defined sources
        - SEND "allow from authorized sources only"
    - router authorization proxy
        - legitimate "node-in-in-the-middle" performs analysis on behalf of all other nodes
        - SEND: check RA against X.509 certificates
    - Stateless
        - Sender Link-layer address
        - Ingress Port
        - Source IP
        - Prefix list
    - Stateful
        - learn dynamically about legitimate RA senders
        - listen to RAs during certain manually configured period of time
            - only allow those RAs received in this time
            - activate learning manually (i.e. add new router to the Network)
        - Interface states:
            - Off: no RA Guard capability
            - LEARNING: block/forward "all" RAs, record RA informations
            - BLOCKING: block ingress RAs
            - FORWARDING: forward valid ingress RAs
    - SEND-Based RA-Guard
        - verify Cryptographically generated Address, RSA signature.
            - failure: drop
        - retrieve valid certificate from cache/public key referred in the RA
            - found: forward
            - not found: 
                - generate a Certification Path Solicitation (CPS), query the router certificate.
                - capture CPA, validate the certificate chain.
                - fail: drop RA
                - success: forward RA, store certificate in cache
    - Security:
        - no protection for direct connection between devices (Ethernet Hub)
        - no protection if tunneled
    - Implementation Advice 
        - https://tools.ietf.org/html/rfc7113
        - Possibility to circumvent RA header identification
            - make it difficult to Find the ICMPv6 layer-4 header information
            - https://tools.ietf.org/html/draft-gont-v6ops-ra-guard-evasion-01
        - RA Guard Evasion Techniques
            - IPv6 Extension Headers (EH)
                - no legitimate use for EHs in RAs (but NDP allows EHs)
                - RA-Guard implementations look at next header instead of following header chain
            - IPv6 Fragmentation + EH
                - fragment RA in two packets
                - "Hdr ext len" only in first fragment
                    - important to locate header in second fragment
        - RFC7113 Implementation
            1. source not a link-local-address: pass the packet
                - hosts should only accepts RAs from link-local address
            2. Hop Limit is not 255: pass the packet
                - hosts should only accepts RAs with Hop Limit = 255
            3. Parse the entire Header Chain in the packet
            4. Drop first fragment if it fails to contain entire IPv6 header chain
            5. Drop RAs with unrecognized Next Header value
            6. Else pass RAs as usual
                - ESP header are allow (IPsec)
            - Log packet drops as security fault
            - IPv6 implementation that allow overlapping fragments might still subject to RA-based attacks (not common)

- Using ACLs
    - block user inbound RA messages
    - https://www.ietf.org/archive/id/draft-nward-ipv6-autoconfig-filtering-ethernet-00.txt

- SEND: https://tools.ietf.org/html/rfc3971
    - non-trival to deploy
    - provisioning hosts with trust anchors
    - IPv6-enabled sensors might not implement SEND at all

- Using an "Intelligent" Deprecation Tool
    - Monitor incorrect RAs (RAMOND, NDPMon)
    - send RA with lifetime to 0

### Generate Attacks

- Scapy
- https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-slaac.html
- https://www.si6networks.com/tools/ipv6toolkit
- https://github.com/vanhauser-thc/thc-ipv6
- https://github.com/aatlasis/Chiron

#### Detect attack

- http://ndpmon.sourceforge.net/
- http://ramond.sourceforge.net/
- https://www.6monplus.it

### Other Attacks

- Neighbor Spoofing
    - https://packetlife.net/blog/2009/feb/2/ipv6-neighbor-spoofing/
    - prevent: SEND / IPSec

- Rogue DHCP (DHCPv6)
    - https://tools.ietf.org/html/rfc3315#section-23
    - https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/
        - https://github.com/fox-it/mitm6
    - https://cciethebeginning.wordpress.com/2012/01/27/dhcpv6-fake-attack/
    - https://github.com/purpleteam/snarf

# Literature

- https://www.juniper.net/documentation/en_US/junos/topics/concept/port-security-ra-guard.html
- https://publications.sba-research.org/publications/Johanna%20IPv6.pdf
- https://www.internetsociety.org/deploy360/ipv6/security/faq/
- https://blogs.infoblox.com/ipv6-coe/why-you-must-use-icmpv6-router-advertisements-ras/
- https://packetlife.net/blog/2008/aug/28/ipv6-neighbor-discovery/
- https://resources.infosecinstitute.com/topic/slaac-attack/
- RFCs
    - NDP: https://tools.ietf.org/html/rfc4861
    - Rogue-RA: https://tools.ietf.org/html/rfc6104
    - RA Guard: https://tools.ietf.org/html/rfc6105
    - RA Guard evasion: https://tools.ietf.org/html/draft-gont-v6ops-ra-guard-evasion-01
    - RA Guard Implementation advices: https://tools.ietf.org/html/rfc7113
    - RA-DNS: https://tools.ietf.org/html/rfc6106
    - SLAAC: https://tools.ietf.org/html/rfc4862
    - SEND: https://tools.ietf.org/html/rfc3971
    - DHCPv6: https://tools.ietf.org/html/rfc3315
    - DHCPv6 attack: https://www.rfc-editor.org/info/rfc7610
