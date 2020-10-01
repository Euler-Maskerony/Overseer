#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include "protocols_numbers.h"
#include "protocol_classes.h"
#include "packets_processing.h"
#include "get_addr.h"


Packet::Packet(const unsigned char *packet)
{
    struct ethhdr ether_hdr;
    memcpy((void *)&ether_hdr, (void *)packet, ETH_HLEN);
    protocol_name = Eth_protocols[ntohs(ether_hdr.h_proto)];
    if(protocol_name == "Address Resolution Protocol")
    {
        ARP packet_info(packet+ETH_HLEN);
        dump = packet_info.Dump();
    }
    else if(protocol_name == "Internet Protocol version 4")
    {
        IPv4 packet_info(packet+ETH_HLEN);
        dump = packet_info.Dump();
        if(packet_info.connection)
        {
            connection = packet_info.info;
            if(packet_info.is_src_local)
            {
                mac_server = MACAddrFromBytes(ether_hdr.h_dest);
                mac_local = MACAddrFromBytes(ether_hdr.h_source);
            }
            else
            {
                mac_server = MACAddrFromBytes(ether_hdr.h_source);
                mac_local = MACAddrFromBytes(ether_hdr.h_dest);
            }
        }
    }
    else if(protocol_name == "Internet Protocol Version 6" and false)
    {
        IPv6 packet_info(packet+ETH_HLEN);
        dump = packet_info.Dump();
        if(packet_info.connection)
            connection = packet_info.info;
    }
    else
        dump = "Unknown protocol: " + protocol_name + '\n';
}
