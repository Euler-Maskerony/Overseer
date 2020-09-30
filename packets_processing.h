#include <string>
#include "protocol_classes.h"

#ifndef PACK_PROC
#define PACK_PROC

class Packet
{
public:
    std::string          dump;
    std::string          protocol_name;
    std::string          mac_local;
    std::string          mac_server;
    Connection           connection;
    
    Packet(const unsigned char *packet);     
};

#endif
