#include <string>

#ifndef PACK_PROC
#define PACK_PROC

class Packet
{
public:
    std::string          dump;
    std::string          protocol_name;
    std::string          mac_src;
    std::string          mac_dest;
    void*                protocol_info;
    
    Packet(const char *packet);     
};

#endif
