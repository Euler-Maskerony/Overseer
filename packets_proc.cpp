#include <iostream>
#include <unordered_map>
#include <bitset>
#include <cstring>
#include "protocols.h"
#include "protocols_headers.h"


IPv4 IPFromBytes(const char *packet)
{
    const int HEADER_SIZE = 160;
    struct IPv4_catch packet_info_c;
    const std::bitset<8> version_mask{0b11110000};
    const std::bitset<8> hsize_mask{0b00001111};
    const std::bitset<8> dscp_mask{0b11111100};
    const std::bitset<8> ecn_mask{0b00000011};
    const std::bitset<16> nFrag_mask{0b0100000000000000};
    const std::bitset<16> anFrags_mask{0b0010000000000000};
    const std::bitset<16> offset_mask{0b0001111111111};
    const std::bitset<32> first_byte_addr{0b11111111000000000000000000000000};
    const std::bitset<32> second_byte_addr{0b00000000111111110000000000000000};
    const std::bitset<32> third_byte_addr{0b00000000000000001111111100000000};
    const std::bitset<32> fourth_byte_addr{0b00000000000000000000000011111111};
    memcpy((void *)&packet_info_c, (void *)packet, HEADER_SIZE);
    struct IPv4 packet_info;
    packet_info.version = static_cast<int>(((static_cast<std::bitset<8>>(packet_info_c.version_hsize) & version_mask) >> 4).to_ulong());
    packet_info.hsize = static_cast<int>((static_cast<std::bitset<8>>(packet_info_c.version_hsize) & hsize_mask).to_ulong());
    packet_info.dscp = static_cast<int>(((static_cast<std::bitset<8>>(packet_info_c.dscp_ecp) & dscp_mask) >> 2).to_ulong());
    packet_info.ecn = static_cast<int>((static_cast<std::bitset<8>>(packet_info_c.dscp_ecp) & ecn_mask).to_ulong());
    packet_info.size = static_cast<int>(packet_info_c.size);
    packet_info.id = static_cast<int>(packet_info_c.id);
    packet_info.nFrag = (bool)(static_cast<std::bitset<16>>(packet_info_c.flags_offset) & nFrag_mask).to_ulong();
    packet_info.anFrags = (bool)(static_cast<std::bitset<16>>(packet_info_c.flags_offset) & anFrags_mask).to_ulong();
    packet_info.ttl = static_cast<int>(packet_info_c.ttl);
    packet_info.protocol = IP_protocols[static_cast<int>(packet_info_c.protocol)];
    packet_info.checksum = static_cast<int>(packet_info_c.checksum);
    packet_info.src = std::to_string(static_cast<int>(((static_cast<std::bitset<32>>(packet_info_c.src) & first_byte_addr) >> 24).to_ulong())) + "." +
                std::to_string(static_cast<int>(((static_cast<std::bitset<32>>(packet_info_c.src) & second_byte_addr) >> 16).to_ulong())) + "." +
                std::to_string(static_cast<int>(((static_cast<std::bitset<32>>(packet_info_c.src) & third_byte_addr) >> 8).to_ulong())) + "." +
                std::to_string(static_cast<int>((static_cast<std::bitset<32>>(packet_info_c.src) & fourth_byte_addr).to_ulong()));
    packet_info.dest = std::to_string(static_cast<int>(((static_cast<std::bitset<32>>(packet_info_c.dest) & first_byte_addr) >> 24).to_ulong())) + "." +
                std::to_string(static_cast<int>(((static_cast<std::bitset<32>>(packet_info_c.dest) & second_byte_addr) >> 16).to_ulong())) + "." +
                std::to_string(static_cast<int>(((static_cast<std::bitset<32>>(packet_info_c.dest) & third_byte_addr) >> 8).to_ulong())) + "." +
                std::to_string(static_cast<int>((static_cast<std::bitset<32>>(packet_info_c.dest) & fourth_byte_addr).to_ulong()));
    return packet_info;

}
