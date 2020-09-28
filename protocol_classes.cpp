#include <iostream>
#include <unordered_map>
#include <cstring>
#include <arpa/inet.h>
#include <bitset>
#include "protocols_headers.h"
#include "protocols_numbers.h"
#include "protocol_classes.h"
#include "get_addr.h"

Connection Connection::operator+=(const Connection connection_dg)
{
    this->state = connection_dg.state;
    this->packets_count++;
    
    return *this;
}


void Connection::getDescription()
{

}


TCP::TCP(const char* packet)
{
    trans_protocol = "TCP";
    struct TCP_catch packet_bytes;
    const int HEADER_SIZE(20);
    memcpy((void *)&packet_bytes, (void *)packet, HEADER_SIZE);
    src_port = static_cast<unsigned int>(ntohs(packet_bytes.src_port));
    dest_port = static_cast<unsigned int>(ntohs(packet_bytes.dest_port));
    std::bitset<6> flags_bits(static_cast<std::bitset<6>>((static_cast<std::bitset<16>>(ntohs(packet_bytes.offs_res_flags)) & static_cast<std::bitset<16>>(0b0000000000111111)).to_ulong()));
    std::cout << packet_bytes.offs_res_flags << '\n';
    std::bitset<6> flag_mask(static_cast<std::bitset<6>>(0b100000));
    bool *flag(&flags.urg);
    for(int i(0); i<6; i++)
    {
        *(flag+i) = static_cast<bool>((flags_bits & (flag_mask >> i)).to_ulong());
    }
    state = getState();
    description = getDescription();
}


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
    description = "URG ACK PSH RST SYN FIN ";
    bool *flag(&flags.urg);
    for(int i(0); i < description.size(); i += 4)
    {
        if(not *flag)
        {
            description.erase(i, 4);
            i -= 4;
        }
        flag++;
    }
    description += "| ";
    description += "Source port: " + std::to_string(src_port);
    description += " Destination port: " + std::to_string(dest_port);

    return description;
}


IPv4::IPv4(const char* packet)
{
    std::string net_protocol("Internet Protocol version 4");
    const int HEADER_SIZE(20);
    struct IPv4_catch packet_bytes;
    memcpy((void *)&packet_bytes, (void *)packet, HEADER_SIZE);
    size = static_cast<unsigned int>(ntohs(packet_bytes.size));
    ttl = static_cast<unsigned int>(packet_bytes.ttl);
    hsize = (static_cast<std::bitset<8>>(packet_bytes.version_hsize) & static_cast<std::bitset<8>>(0b00001111)).to_ulong() * 4;
    std::cout << hsize << '\n';
    std::string trans_protocol(IP_protocols[static_cast<unsigned int>(packet_bytes.protocol)]);
    char src_addr_bytes[4], dest_addr_bytes[4];
    memcpy((void *)src_addr_bytes, (void *)&packet_bytes.src, 4);
    memcpy((void *)dest_addr_bytes, (void *)&packet_bytes.dest, 4);
    std::string src(IPv4AddrFromBytes(src_addr_bytes));
    std::string dest(IPv4AddrFromBytes(dest_addr_bytes));
    if(trans_protocol == "TCP")
    {
        connection = true;
        TCP tcp_packet(packet + hsize);
        if(src.find("192.168") != std::string::npos)
        {
            tcp_packet.local = src;
            tcp_packet.server = dest;
        }
        else
        {
            tcp_packet.local = dest;
            tcp_packet.server = src;
        }
        tcp_packet.net_protocol = net_protocol;
        info = &tcp_packet;
    }
    else if(trans_protocol == "UDP")
    {
        connection = false;
    }
}

std::string IPv4::Description()
{
    return "IPv4 lul";
}

std::string IPv4::Dump()
{
    return "dump";
}

IPv6::IPv6(const char *packet)
{
    std::string net_protocol("Internet Protocol version 6");
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
    std::string src(IPv6AddrFromBytes(src_addr_bytes));
    std::string dest(IPv6AddrFromBytes(dest_addr_bytes));
}

std::string IPv6::Description()
{
    return "IPv6 zdarova";
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
