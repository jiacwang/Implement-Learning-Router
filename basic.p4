/* -*- P4_16 -*- */



// Author : Jiachen Wang.  PennID: 49678282
// Author : Chang Lee.     PennID: 23888214
#include <core.p4>
#include <v1model.p4>


typedef bit<48> macAddr_t;
typedef bit<9>  portId_t;
typedef bit<32>  IPv4Address;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    // TODO, this part must be correct.
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      totalLen;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      fragOffset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdrChecksum;
    IPv4Address  srcAddr;
    IPv4Address  dstAddr;

}

header arp_t {
    // TODO, this part must be correct.
    
    bit<16> HTYPE;
    bit<16> PTYPE;
    bit<8> HLEN;
    bit<8> PLEN;
    bit<16> oper;
    macAddr_t SHA;
    IPv4Address SPA;
    macAddr_t THA;
    IPv4Address targetPA;
   
}

struct cis553_metadata_t {
    // TODO
    IPv4Address temp;
    //portId_t ingressPort;
    bit<1> forMe;
}

struct headers_t {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    arp_t       arp;
}

/*************************************************************************
***********************  P A R S E   P A C K E T *************************
*************************************************************************/

parser cis553Parser(packet_in packet,
                    out headers_t parsed_header,
                    inout cis553_metadata_t metadata,
                    inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        // TODO, this should be correct
    
        packet.extract(parsed_header.ethernet);
        transition select(parsed_header.ethernet.etherType) {
            0x0800: parse_ipv4;
            0x0806: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(parsed_header.ipv4);
        transition accept;
    }

     state parse_arp {
        packet.extract(parsed_header.arp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control cis553VerifyChecksum(inout headers_t hdr,
                             inout cis553_metadata_t meta) {
     apply { }
}


/*************************************************************************
***********************  I N G R E S S  **********************************
*************************************************************************/

control cis553Ingress(inout headers_t hdr,
                      inout cis553_metadata_t metadata,
                      inout standard_metadata_t standard_metadata) {
    action aiForMe() {
        metadata.forMe = 1;
    }

    action aiNotForMe() {
        metadata.forMe = 0;
    }

    table tiHandleEthernet {

       
        key = {
            hdr.ethernet.dstAddr : exact;
            standard_metadata.ingress_port : exact;
        }
        actions = {
            aiForMe;
            aiNotForMe;
        }

        default_action = aiNotForMe();
    }

    action aDrop() {
        mark_to_drop();
    }

    action aiForward(macAddr_t mac_sa, macAddr_t mac_da, portId_t egress_port) {
        // TODO
        //maybe we need to update more fields
        //if we enter here, we know the packet is not arp, it is ipv4
        //so the header structure must be ipv4
        //forward, set the fields
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ethernet.srcAddr = mac_sa;
        hdr.ethernet.dstAddr = mac_da;
        standard_metadata.egress_spec = egress_port;
    }

    table tiIpv4Lpm {
        // TODO
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            aiForward;
            aDrop;
        }

        default_action = aDrop();

    }

    action aiArpResponse(macAddr_t mac_sa) {
        // TODO
        //hdr.arp.HTYPE = 1;
        //hdr.arp.PTYPE = 0x0800; 
        //hdr.arp.HLEN = 6;
        //hdr.arp.PLEN = 4;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        hdr.arp.oper = 2;
        hdr.arp.THA = hdr.arp.SHA;
        hdr.arp.SHA = mac_sa;
        metadata.temp = hdr.arp.SPA;
        hdr.arp.SPA = hdr.arp.targetPA;         
        hdr.arp.targetPA = metadata.temp;


    }

    table tiArpResponse {
        // TODO
        key = {
            hdr.arp.oper : exact;
            hdr.arp.targetPA : exact;
        }
        actions = {
            aiArpResponse;
            aDrop;
        }

        default_action = aDrop();
    }

    apply {
        tiHandleEthernet.apply();

        if (metadata.forMe == 0) {
            aDrop();
        } else if (hdr.ipv4.isValid()) {
            tiIpv4Lpm.apply();
        } else if (hdr.arp.isValid()) {
            tiArpResponse.apply();
        } else {
            aDrop();
        }
    }
}


/*************************************************************************
***********************  E G R E S S  ************************************
*************************************************************************/

control cis553Egress(inout headers_t hdr,
                     inout cis553_metadata_t metadata,
                     inout standard_metadata_t standard_metadata) {
    apply { }
}


/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   ***************
*************************************************************************/
//Take the fields of the ip header, compute their sum and put it in the checksum field.
control cis553ComputeChecksum(inout headers_t hdr,
                              inout cis553_metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { 
             //TODO: fields to checksum
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr               
            },
            // TODO: checksum field
            hdr.ipv4.hdrChecksum
            ,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control cis553Deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/

V1Switch(cis553Parser(),
         cis553VerifyChecksum(),
         cis553Ingress(),
         cis553Egress(),
         cis553ComputeChecksum(),
         cis553Deparser()) main;
