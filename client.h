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
    std::vector<Datagrams>       datagrams;

    Client(const Packet packet_info);
    std::string Tree();
    Client operator+=(const Packet &packet);
private:
    int checkConnection(Connection connection);
};

void ClientHandler(const Packet packet_info, std::vector<Client> &clients);

#endif
