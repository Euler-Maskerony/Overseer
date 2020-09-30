#include <string>
#include <vector>
#include "packets_processing.h"
#include "protocol_classes.h"

#ifndef CLIENT
#define CLIENT

class Client
{
public:
    std::string                  mac_addr;
    std::vector<Connection>      connections;

    Client(const Packet packet_info) : mac_addr{packet_info.mac_local}{};
    std::string Branch();
    Client operator+=(const Packet packet);
private:
    int checkConnection(Connection connection);
};

void ClientHandler(const Packet packet_info, std::vector<Client> &clients);

#endif
