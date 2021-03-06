
#define ETHERTYPE_IPV4 0x0800
#define TCP 0x6

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type tcp_t {
	fields {
		srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 3;
        ecn : 3;
        ctrl : 6;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
	}
}


header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;

/* header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;
    }
}
*/
metadata routing_metadata_t routing_metadata;

header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;
	ecmp_offset: 14;
        // TODO: if you need extra metadata for ECMP, define it here
    }
}
