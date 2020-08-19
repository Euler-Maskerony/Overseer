#include <iostream>
#include <unordered_map>
#include <bitset>
#include <cstring>
#include "protocols.h"
#include "protocols_headers.h"
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>


const std::bitset<8> version_mask{0b11110000};
const std::bitset<32> addr_byte_IPv4{0b11111111000000000000000000000000};
const std::bitset<32> payload_length_mask_IPv6{0b11111111111111110000000000000000};
const std::bitset<32> next_header_mask_IPv6{0b00000000000000001111111100000000};
const std::bitset<32> hop_limit_mask_IPv6{0b00000000000000000000000011111111};

std::unordered_map<std::bitset<4>, char> bin_to_hex = {
    {0b0000, '0'},
    {0b0001, '1'},
    {0b0010, '2'},
    {0b0011, '3'},
    {0b0100, '4'},
    {0b0101, '5'},
    {0b0110, '6'},
    {0b0111, '7'},
    {0b1000, '8'},
    {0b1001, '9'},
    {0b1010, 'a'},
    {0b1011, 'b'},
    {0b1100, 'c'},
    {0b1101, 'd'},
    {0b1110, 'e'},
    {0b1111, 'f'}
};


class Packet
{

};


std::string MACAddrFromBytes(const char *addr_bytes)
{
    std::string addr{};
    const std::bitset<8> fourbit_mask{0b11110000};
    for(int i{0}; i<=11; i+=1)
        addr += bin_to_hex[static_cast<std::bitset<4>>(((static_cast<std::bitset<8>>(addr_bytes[i/2]) & (fourbit_mask >> i%2*4)) >> (4-i%2*4)).to_ulong())];
    char sep{':'};
    for(int i{10}; i>=2; i-=2)
        addr.insert(i, (const char *)&sep);

    return addr;
}


std::string IPv4AddrFromBytes(const char *addr_bytes)
{
    std::string addr{};
    for(int i{0}; i<4; i++)
        addr += std::to_string(static_cast<int>(static_cast<std::bitset<8>>(addr_bytes[i]).to_ulong())) + ".";
    addr = addr.substr(0, addr.size()-1);

    return addr;
}


IP IPv4FromBytes(const char *packet, IP &packet_info)
{
    const int HEADER_SIZE = 20;
    struct IPv4_catch packet_info_c;
    memcpy((void *)&packet_info_c, (void *)packet, HEADER_SIZE);
    packet_info.size = static_cast<unsigned int>(ntohs(packet_info_c.size));
    packet_info.ttl = static_cast<unsigned int>(packet_info_c.ttl);
    packet_info.protocol = IP_protocols[static_cast<unsigned int>(packet_info_c.protocol)];
    packet_info_c.src = packet_info_c.src;
    packet_info_c.dest = packet_info_c.dest;
    char src_addr_bytes[4], dest_addr_bytes[4];
    memcpy((void *)src_addr_bytes, (void *)&packet_info_c.src, 4);
    memcpy((void *)dest_addr_bytes, (void *)&packet_info_c.dest, 4);
    packet_info.src = IPv4AddrFromBytes(src_addr_bytes);
    packet_info.dest = IPv4AddrFromBytes(dest_addr_bytes);

    return packet_info;
}


std::string IPv6AddrFromBytes(const char *addr_bytes)
{
    const std::bitset<8> fourbit_mask{0b11110000};
    char addr_chars[32];
    for(int i{0}; i<32; i++)
        addr_chars[i] = bin_to_hex[
        static_cast<std::bitset<4>>(((static_cast<std::bitset<8>>(addr_bytes[i/2]) & (fourbit_mask >> (i % 2) * 4)) >> (4 - (i % 2) * 4)).to_ulong())
        ];
    std::string addr{addr_chars};
    char sep{':'};
    for(int i{3}; i <= 27; i+=4)
        addr.insert(i, (char *)&sep);

    return addr;
}


IP IPv6FromBytes(const char *packet, IP &packet_info)
{
    const int HEADER_SIZE = 40;
    char src_addr_bytes[16], dest_addr_bytes[16];
    struct IPv6_catch packet_info_c;
    memcpy((void *)&packet_info_c, (void *)packet, HEADER_SIZE);
    packet_info.size = static_cast<long>(ntohs(packet_info_c.payload_length)) + 40;
    packet_info.ttl = static_cast<int>(packet_info_c.hop_limit);
    char32_t *addr_ptr{&packet_info_c.src_first_addr};
    for(int i{0}; i<=7; i++)
        *(addr_ptr+i) = ntohl(*(addr_ptr+i));
    memcpy((void *)src_addr_bytes, (void *)&packet_info_c.src_first_addr, 16);
    memcpy((void *)dest_addr_bytes, (void *)&packet_info_c.dest_first_addr, 16);
    packet_info.src = IPv6AddrFromBytes(src_addr_bytes);
    packet_info.dest = IPv6AddrFromBytes(dest_addr_bytes);
    return packet_info;
}


ARP ARPFromBytes(const char *packet, ARP &packet_info)
{
    struct ARP_catch packet_info_c;
    const int HEADER_SIZE = 8;
    memcpy((void *)&packet_info_c, (void *)packet, HEADER_SIZE);
    packet_info.hlen = packet_info_c.hlen;
    packet_info.plen = packet_info_c.plen;
    if(ntohs(packet_info_c.htype) == 0x0001)
    {
        packet_info.sha = MACAddrFromBytes(packet+HEADER_SIZE);
    }
    else
    {
        packet_info.sha = "/Unknown protocol/";
        packet_info.tha = "/Unknown protocol/";
    }

    return packet_info;
}


void PacketHandler(const char *packet, const int p_size)
{
    struct ethhdr ether_hdr;
    memcpy((void *)&ether_hdr, (void *)packet, ETH_HLEN);
    std::string eth_proto = Eth_protocols[ntohs(ether_hdr.h_proto)];
    if(eth_proto == "Address Resolution Protocol")
    {
        struct ARP packet_info;
        packet_info = ARPFromBytes((const char *)(packet+ETH_HLEN), packet_info);
        std::cout << packet_info.sha << '\n';
    }
    else if(eth_proto == "Internet Protocol version 4")
    {
        struct IP packet_info;
        packet_info = IPv4FromBytes((const char *)(packet+ETH_HLEN), packet_info);
        std::cout << packet_info.src << '\n';
    }
    else if(eth_proto == "Internet Protocol Version 6")
    {
        struct IP packet_info;
        packet_info = IPv6FromBytes((const char *)(packet+ETH_HLEN), packet_info);
    }
}
