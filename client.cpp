#include <algorithm>
#include <vector>
#include "packets_processing.h"
#include "client.h"

Client Client::operator+=(const Packet &packet)
{
    return *this;
}

void ClientHandler(const Packet packet_info, std::vector<Client> &clients)
{
    if(std::none_of(clients.begin(), clients.end(), [packet_info](Client client){return packet_info.mac_src == client.mac_addr;}))
    {
        Client client{packet_info};
        clients.push_back(client);
    }
    else
    {
        auto client_i{std::find_if(clients.begin(), clients.end(), [&packet_info](const Client &client){return packet_info.mac_src == client.mac_addr;})};
        clients[std::distance(clients.begin(), client_i)] += packet_info;
    }

    if(std::none_of(clients.begin(), clients.end(), [packet_info](Client client){return packet_info.mac_src == client.mac_addr;}))
    {

    }
}
