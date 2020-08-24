#include <bitset>
#include <iostream>
#include <unordered_map>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include "bin_masks.h"

std::string MACAddrFromBytes(const char *addr_bytes)
{
    std::string address{};
    for(int i{0}; i<=11; i+=1)
        address += bin_to_hex[
            static_cast<std::bitset<4>>(((static_cast<std::bitset<8>>(addr_bytes[i/2]) & (fourbit_mask >> i%2*4)) >> (4-i%2*4)).to_ulong())
        ];
    char sep{':'};
    for(int i{10}; i>=2; i-=2)
        address.insert(i, (const char *)&sep);

    return address;
}


std::string IPv4AddrFromBytes(const char *addr_bytes)
{
    struct in_addr address_s;
    memcpy((void *)&address_s.s_addr, (void *)addr_bytes, 4);
    std::string address{inet_ntoa(address_s)};

    return address;
}

std::string IPv6AddrFromBytes(const char *addr_bytes)
{
    struct in6_addr address_s;
    char address_c[INET6_ADDRSTRLEN];
    memcpy((void *)&address_s.s6_addr, (void *)addr_bytes, 16);
    inet_ntop(AF_INET6, (const void *)&address_s, (char *)address_c, INET6_ADDRSTRLEN);
    std::string address{address_c};

    return address;
}
