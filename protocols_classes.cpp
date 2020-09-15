#include <iostream>
#include <unordered_map>
#include <cstring>
#include <arpa/inet.h>
#include <bitset>
#include "protocols_headers.h"
#include "protocols_numbers.h"
#include "protocol_classes.h"
#include "get_addr.h"

TCP::TCP(const char* packet)
{
    struct TCP_catch packet_bytes;
    const int HEADER_SIZE(160);
    memcpy((void *)&packet_bytes, (void *)packet, HEADER_SIZE);
    src_port = static_cast<unsigned int>(packet_bytes.src_port);
    dest_port = static_cast<unsigned int>(packet_bytes.dest_port);
    std::bitset<6> flags_bits(static_cast<std::bitset<6>>((static_cast<std::bitset<16>>(packet_bytes.offs_res_flags) & static_cast<std::bitset<16>>(0b0000000000111111)).to_ulong()));
    std::bitset<6> flag_mask(static_cast<std::bitset<6>>(0b100000));
    bool *flag(&flags.syn);
    for(int i(0); i<=6; i++)
    {
        flag += i;
        *flag = (bool)(flags_bits & (flag_mask >> i)).to_ulong();
    }
};


std::string TCP::getState()
{
    if(flags.syn) return "SYN RECIEVED";
    else if(flags.ack) return "ESTABLISHED";
    else if(flags.fin) return "FINISHED";
    else if(flags.rst) return "ABORTED";
    else { return "UNDEFINED"; }
}

std::string TCP::getDescription()
{
    std::string description("URG ACK PSH RST SYN FIN ");
    bool *flag(&flags.syn);
    for(int i(0); i <= 20; i+=4)
        if(not *(flag+i)) description.erase(i, 4);
    description += "| ";
    description += "Source port: " + src_port;
    description += " Destination port: " + dest_port;

    return description;
}


IPv4::IPv4(const char* packet)
{
    net_protocol = "Internet Protocol version 4";
    const int HEADER_SIZE(20);
    struct IPv4_catch packet_bytes;
    memcpy((void *)&packet_bytes, (void *)packet, HEADER_SIZE);
    size = static_cast<unsigned int>(ntohs(packet_bytes.size));
    ttl = static_cast<unsigned int>(packet_bytes.ttl);
    trans_protocol = IP_protocols[static_cast<unsigned int>(packet_bytes.protocol)];
    char src_addr_bytes[4], dest_addr_bytes[4];
    memcpy((void *)src_addr_bytes, (void *)&packet_bytes.src, 4);
    memcpy((void *)dest_addr_bytes, (void *)&packet_bytes.dest, 4);
    src = IPv4AddrFromBytes(src_addr_bytes);
    dest = IPv4AddrFromBytes(dest_addr_bytes);
    if(trans_protocol == "TCP")
    {
        connection = true;
        TCP tcp_packet(packet + HEADER_SIZE);
        state = tcp_packet.getState();
        description = tcp_packet.getDescription();
    }
    else if(trans_protocol == "UDP")
    {

    }
}

std::string IPv4::Description()
{
    return src;
}

std::string IPv4::Dump()
{
    return "dump";
}

IPv6::IPv6(const char *packet)
{
    net_protocol = "Internet Protocol version 4";
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

std::string IPv6::Description()
{
    return src;
}

std::string IPv6::Dump()
{
    return "dump";
}

ARP::ARP(const char *packet)
{
    protocol_name = "Address Resolution Protocol";
    struct ARP_catch packet_bytes;
    request = (int)packet_bytes.oper == 0x0001;
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
            src = IPv4AddrFromBytes(packet+HEADER_SIZE+hlen);
            dest = IPv4AddrFromBytes(packet+HEADER_SIZE+2*hlen+plen);
            description = Description();
        }
        else if(Eth_protocols[ptype] == "Internet Protocol version 6")
        {
            src = IPv6AddrFromBytes(packet+HEADER_SIZE+hlen);
            dest = IPv6AddrFromBytes(packet+HEADER_SIZE+2*hlen+plen);
            description = Description();
        }
        else
        {
            src = "/Unknown protocol/";
            dest = "/Unknown protocol/";
        }

    }
    else
    {
        sha = "/Unknown protocol/";
        tha = "/Unknown protocol/";
    }
}

std::string ARP::Description()
{
    return request ? "Who has " + dest + ", tell " + src + " your hardware address." : "I have " + src + " and my hardware address is " + tha;
}

std::string ARP::Dump()
{
    return "dump";
}
