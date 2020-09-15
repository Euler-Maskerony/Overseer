#include <string>
#ifndef GET_ADDR
#define GET_ADDR

std::string IPv4AddrFromBytes(const char *addr_bytes);
std::string IPv6AddrFromBytes(const char *addr_bytes);
std::string MACAddrFromBytes(const char *addr_bytes);

#endif
