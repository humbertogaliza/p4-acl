/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "headers.p4" 

parser start {
    return parse_ethernet;
}



parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}


field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

#define IP_PROTOCOLS_TCP 6

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        IP_PROTOCOLS_TCP : parse_tcp;
        default: ingress;
    }
}


parser parse_tcp {
    extract(tcp);
    return ingress;
}


action _drop() {
    drop();
}

action _nop() {
    no_op();
}

action set_nhop(nhop_ipv4, port) {
    modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}


field_list ecmp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        ipv4.protocol;
	    tcp.srcPort;
        tcp.dstPort;
}

field_list_calculation ecmp_hash {
    input {
        ecmp_checksum_list;
    }
    algorithm : csum16;
    output_width : 10;
}


action set_ecmp_select(ecmp_base, ecmp_count) {
	modify_field_with_hash_based_offset(routing_metadata.ecmp_offset, ecmp_base, ecmp_hash, ecmp_count);
}

table ecmp_group {
    reads {
	ipv4.dstAddr: lpm;
    } 
    actions {
	    _drop;
	    set_ecmp_select;
    }
    size: 512;
} 

table ecmp_nhop {
	reads {
		routing_metadata.ecmp_offset: exact;
	}
	actions {
		_drop;
		set_nhop;
	}
	size: 2048;
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

table forward {
    reads {
        routing_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}



table access_control {
	reads {
		tcp.srcPort: exact;
		tcp.dstPort: exact;
	}
	actions {
        _nop;
		_drop;
	}
	size: 1024;
}


control ingress {
    if(valid(ipv4) and ipv4.ttl > 0) {
        // TODO: implement ECMP here
	    apply(ecmp_group);
        apply(ecmp_nhop);
        //apply(ipv4_lpm);
        apply(access_control);
        apply(forward);
    }
}

control egress {
    apply(send_frame);
}
