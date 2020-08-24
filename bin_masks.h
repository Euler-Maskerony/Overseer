#include <unordered_map>
#include <bitset>
#ifndef BIN_MSK
#define BIN_MSK

static std::unordered_map<std::bitset<4>, char> bin_to_hex = {
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

const std::bitset<8> version_mask(0b11110000);
const std::bitset<32> addr_byte_IPv4(0b11111111000000000000000000000000);
const std::bitset<32> payload_length_mask_IPv6(0b11111111111111110000000000000000);
const std::bitset<32> next_header_mask_IPv6(0b00000000000000001111111100000000);
const std::bitset<32> hop_limit_mask_IPv6(0b00000000000000000000000011111111);
const std::bitset<8> fourbit_mask(0b11110000);

#endif
