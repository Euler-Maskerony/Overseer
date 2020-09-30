#include <algorithm>
#include <vector>
#include <string>
#include "packets_processing.h"
#include "client.h"
#include "protocol_classes.h"

Client Client::operator+=(const Packet packet)
{
    if(packet.protocol_name == "Internet Protocol version 4")
    {
            int conn_i;
            if(conn_i = checkConnection(packet.connection) == -1)
                this->connections.push_back(packet.connection);
            else
                this->connections[conn_i] += packet.connection;
    }
    else if(packet.protocol_name == "Internet Protocol version 6")
    {
        this->connections.push_back(packet.connection);
    }
    return *this;
}

int Client::checkConnection(Connection connection)
{
    for(int i(this->connections.size()-1); i >= 0; i--)
        if(this->connections[i].local == connection.local and this->connections[i].server == connection.server){ return i; };

    return -1;
}

std::string Client::Branch()
{
    std::string branch("");
    std::vector<Connection> connections_p = connections;
    branch += "|\n" + mac_addr + '\n';
    for(int i(0); i < std::distance(connections_p.begin(), connections_p.end()); i++)
    {
        branch += "|\n|--->" + connections_p[i].local + "\n";
        branch += "|  |\n|  |--->" + connections_p[i].server + ": " + connections_p[i].description + ' ' + std::to_string(connections_p[i].packets_count) + '\n';
        for(int j(i+1); j < std::distance(connections_p.begin(), connections_p.end()); j++)
            if(connections_p[i].local == connections_p[j].local)
            {
                branch += "|  |\n|  |--->" + connections_p[j].server + ": " + connections_p[j].description + ' ' + std::to_string(connections_p[j].packets_count) + '\n';
                connections_p.erase(connections_p.begin()+j);
                j--;
            }
    }
    return branch;
}

void ClientHandler(const Packet packet_info, std::vector<Client> &clients)
{
    if(std::none_of(clients.begin(), clients.end(), [packet_info](Client client){return packet_info.mac_local == client.mac_addr;}))
    {
        Client client{packet_info};
        client += packet_info;
        clients.push_back(client);
    }
    else
    {
        auto client_i{std::find_if(clients.begin(), clients.end(), [&packet_info](const Client &client){return packet_info.mac_local == client.mac_addr;})};
        clients[std::distance(clients.begin(), client_i)] += packet_info;
    }
}
