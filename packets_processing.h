#include <string>
#ifndef PACK_PROC
#define PACK_PROC

class Packet
{
private:
    std::string          dump;
public:
    std::string          protocol_name;
    std::string          mac_src;
    std::string          mac_dest;
    void*                protocol_info;
    void PacketHandler(const char *packet, const int p_size);
    std::string Dump();
};

#endif
