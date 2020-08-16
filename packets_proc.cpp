#include <iostream>
#include <unordered_map>
#include <bitset>
#include <cstring>
#include "protocols.h"
#include "protocols_headers.h"


const std::bitset<8> version_mask{0b11110000};

const std::bitset<32> first_byte_IPv4{0b11111111000000000000000000000000};
const std::bitset<32> second_byte_IPv4{0b00000000111111110000000000000000};
const std::bitset<32> third_byte_IPv4{0b00000000000000001111111100000000};
const std::bitset<32> fourth_byte_IPv4{0b00000000000000000000000011111111};

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


void IPv4FromBytes(const char *packet, IP &packet_info)
{
    const int HEADER_SIZE = 20;
    struct IPv4_catch packet_info_c;
    memcpy((void *)&packet_info_c, (void *)packet, HEADER_SIZE);
    packet_info.size = static_cast<long>(packet_info_c.size);
    packet_info.ttl = static_cast<int>(packet_info_c.ttl);
    packet_info.protocol = IP_protocols[static_cast<int>(packet_info_c.protocol)];
    packet_info.src = std::to_string(static_cast<int>(((static_cast<std::bitset<32>>(packet_info_c.src) & first_byte_IPv4) >> 24).to_ulong())) + "." +
                std::to_string(static_cast<int>(((static_cast<std::bitset<32>>(packet_info_c.src) & second_byte_IPv4) >> 16).to_ulong())) + "." +
                std::to_string(static_cast<int>(((static_cast<std::bitset<32>>(packet_info_c.src) & third_byte_IPv4) >> 8).to_ulong())) + "." +
                std::to_string(static_cast<int>((static_cast<std::bitset<32>>(packet_info_c.src) & fourth_byte_IPv4).to_ulong()));
    packet_info.dest = std::to_string(static_cast<int>(((static_cast<std::bitset<32>>(packet_info_c.dest) & first_byte_IPv4) >> 24).to_ulong())) + "." +
                std::to_string(static_cast<int>(((static_cast<std::bitset<32>>(packet_info_c.dest) & second_byte_IPv4) >> 16).to_ulong())) + "." +
                std::to_string(static_cast<int>(((static_cast<std::bitset<32>>(packet_info_c.dest) & third_byte_IPv4) >> 8).to_ulong())) + "." +
                std::to_string(static_cast<int>((static_cast<std::bitset<32>>(packet_info_c.dest) & fourth_byte_IPv4).to_ulong()));
}


std::string IPv6AddrFromBytes(const char32_t &first, const char32_t &second, const char32_t &third, const char32_t &fourth)
{
    const std::bitset<32> fourbit_mask{0b11110000000000000000000000000000};
    const std::bitset<32> addr_bytes[4]{
        static_cast<std::bitset<32>>(first),
        static_cast<std::bitset<32>>(second),
        static_cast<std::bitset<32>>(third),
        static_cast<std::bitset<32>>(fourth)
    };
    std::bitset<4> addr_bits[32];

    char addr[39];
    addr[4] = ':';
    addr[9] = ':';
    addr[14] = ':';
    addr[19] = ':';
    addr[24] = ':';
    addr[29] = ':';
    addr[34] = ':';

    char addr_chars[32];

    for(int i{0}; i < 32; i++)
    {
        addr_bits[i] = static_cast<std::bitset<4>>(((addr_bytes[i/8] & (fourbit_mask >> (i % 8) * 4)) >> (28 - (i % 8) * 4)).to_ulong());
        addr_chars[i] = bin_to_hex[addr_bits[i]];
    }
    for(int i{0}; i <= 35; i+=5)
        memcpy((void *)&addr[i], (void *)&addr_chars[i-i/5], 4);

    std::string result{addr};
    return result;
}


void IPv6FromBytes(const char *packet, IP &packet_info)
{
    const int HEADER_SIZE = 40;
    struct IPv6_catch packet_info_c;
    memcpy((void *)&packet_info_c, (void *)&packet, HEADER_SIZE);
    packet_info.size = static_cast<long>(packet_info_c.payload_length) + 40;
    packet_info.ttl = static_cast<int>(packet_info_c.hop_limit);
    packet_info.src = IPv6AddrFromBytes(
        packet_info_c.src_first_addr,
        packet_info_c.src_second_addr,
        packet_info_c.src_third_addr,
        packet_info_c.src_fourth_addr
    );
    packet_info.dest = IPv6AddrFromBytes(
        packet_info_c.dest_first_addr,
        packet_info_c.dest_second_addr,
        packet_info_c.dest_third_addr,
        packet_info_c.dest_fourth_addr
    );
}


IP IPFromBytes(const char *packet)
{
    int version = static_cast<int>(((static_cast<std::bitset<8>>(packet[0]) & version_mask) >> 4).to_ulong());
    struct IP packet_info;
    packet_info.version = version;
    if(version == 6)
        IPv4FromBytes((const char *)&packet, packet_info);
    else
        IPv6FromBytes((const char *)&packet, packet_info);
    return packet_info;
}
