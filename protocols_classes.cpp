#include <iostream>
#include <unordered_map>
#include <cstring>
#include <arpa/inet.h>
#include "protocols_headers.h"
#include "protocols_numbers.h"
#include "protocol_classes.h"
#include "get_addr.h"

void IPv4::Parse(const char *packet)
{
    const int HEADER_SIZE(20);
    struct IPv4_catch packet_bytes;
    memcpy((void *)&packet_bytes, (void *)packet, HEADER_SIZE);
    size = static_cast<unsigned int>(ntohs(packet_bytes.size));
    ttl = static_cast<unsigned int>(packet_bytes.ttl);
    protocol = IP_protocols[static_cast<unsigned int>(packet_bytes.protocol)];
    char src_addr_bytes[4], dest_addr_bytes[4];
    memcpy((void *)src_addr_bytes, (void *)&packet_bytes.src, 4);
    memcpy((void *)dest_addr_bytes, (void *)&packet_bytes.dest, 4);
    src = IPv4AddrFromBytes(src_addr_bytes);
    dest = IPv4AddrFromBytes(dest_addr_bytes);
}

std::string IPv4::Dump()
{
    return src;
}


void IPv6::Parse(const char *packet)
{
    const int HEADER_SIZE(40);
    char src_addr_bytes[16], dest_addr_bytes[16];
    struct IPv6_catch packet_bytes;
    memcpy((void *)&packet_bytes, (void *)packet, HEADER_SIZE);
    size = static_cast<long>(ntohs(packet_bytes.payload_length)) + 40;
    ttl = static_cast<int>(packet_bytes.hop_limit);
    uint32_t *addr_ptr{&packet_bytes.src_first_addr};
    for(int i{0}; i<=7; i++)
        *(addr_ptr+i) = ntohl(*(addr_ptr+i));
    memcpy((void *)src_addr_bytes, (void *)&packet_bytes.src_first_addr, 16);
    memcpy((void *)dest_addr_bytes, (void *)&packet_bytes.dest_first_addr, 16);
    src = IPv6AddrFromBytes(src_addr_bytes);
    dest = IPv6AddrFromBytes(dest_addr_bytes);
}

std::string IPv6::Dump()
{
    return src;
}

void ARP::Parse(const char *packet)
{
    struct ARP_catch packet_bytes;
    const int HEADER_SIZE(8);
    memcpy((void *)&packet_bytes, (void *)packet, HEADER_SIZE);
    int hlen(packet_bytes.hlen);
    int plen(packet_bytes.plen);
    int htype(ntohs(packet_bytes.htype));
    int ptype(ntohs(packet_bytes.ptype));
    if(htype == 0x0001)
    {
        sha = MACAddrFromBytes(packet+HEADER_SIZE);
        tha = MACAddrFromBytes(packet+HEADER_SIZE+hlen+plen);
        if(Eth_protocols[ptype] == "Internet Protocol version 4")
        {
            spa = IPv4AddrFromBytes(packet+HEADER_SIZE+hlen);
            tpa = IPv4AddrFromBytes(packet+HEADER_SIZE+2*hlen+plen);
        }
        else if(Eth_protocols[ptype] == "Internet Protocol version 6")
        {
            spa = IPv6AddrFromBytes(packet+HEADER_SIZE+hlen);
            tpa = IPv6AddrFromBytes(packet+HEADER_SIZE+2*hlen+plen);
        }
        else
        {
            spa = "/Unknown protocol/";
            tha = "/Unknown protocol/";
        }

    }
    else
    {
        sha = "/Unknown protocol/";
        tha = "/Unknown protocol/";
    }
}

std::string ARP::Dump()
{
    return sha;
}
