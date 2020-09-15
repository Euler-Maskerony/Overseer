#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include "protocols_numbers.h"
#include "protocol_classes.h"
#include "packets_processing.h"


Packet::Packet(const char *packet)
{
    struct ethhdr ether_hdr;
    memcpy((void *)&ether_hdr, (void *)packet, ETH_HLEN);
    protocol_name = Eth_protocols[ntohs(ether_hdr.h_proto)];
    if(protocol_name == "Address Resolution Protocol")
    {
        ARP packet_info(packet+ETH_HLEN);
        dump = packet_info.Dump();
        protocol_info = &packet_info;
    }
    else if(protocol_name == "Internet Protocol version 4")
    {
        IPv4 packet_info(packet+ETH_HLEN);
        dump = packet_info.Dump();
        protocol_info = &packet_info;
    }
    else if(protocol_name == "Internet Protocol Version 6")
    {
        IPv6 packet_info(packet+ETH_HLEN);
        dump = packet_info.Dump();
        protocol_info = &packet_info;
    }
    else
        std::cout << "[!] Unknown protocol." << '\n';
}
