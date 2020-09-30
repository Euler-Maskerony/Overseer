#include <string>
#ifndef GET_ADDR
#define GET_ADDR

std::string IPv4AddrFromBytes(const unsigned char *addr_bytes);
std::string IPv6AddrFromBytes(const unsigned char *addr_bytes);
std::string MACAddrFromBytes(const unsigned char *addr_bytes);

#endif
