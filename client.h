#include <string>
#include <vector>
#include "packets_processing.h"

#ifndef CLIENT
#define CLIENT

class Connection
{
public:
    std::string         net_protocol;
    std::string         trans_protocol;
    std::string         src;
    std::string         dest;
    std::string         state;
};

class Datagrams
{

};

class Client
{
public:
    std::string                  mac_addr;
    std::vector<Connection>      connections;
    std::vector<Datagrams>       datagrams;

    Client(const Packet packet_info) : mac_addr{packet_info.mac_src}{};
    Client operator+=(const Packet &packet);
};

void ClientHandler(const Packet packet_info, std::vector<Client> &clients);

#endif
