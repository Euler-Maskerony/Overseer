#include <algorithm>
#include <vector>
#include "packets_processing.h"
#include "client.h"
#include "protocol_classes.h"

Client Client::operator+=(const Packet &packet)
{
    if(packet.protocol_name == "Address Resolution Protocol")
    {
        Datagrams *arp = reinterpret_cast<Datagrams*>(packet.protocol_info);
        this->datagrams.push_back(*arp);
    }
    else if(packet.protocol_name == "Internet Protocol version 4")
    {
        IPv4 *ipv4 = reinterpret_cast<IPv4*>(packet.protocol_info);
        if(ipv4->connection)
        {
            Connection *conn = reinterpret_cast<Connection*>(ipv4->info);
            int conn_i;
            if(conn_i = checkConnection(*conn) == -1)
                this->connections.push_back(*conn);
            else
                this->connections[conn_i] += *conn;
        }
        else
        {
            Datagrams *dg = reinterpret_cast<Datagrams*>(ipv4->info);
            this->datagrams.push_back(*dg);   
        }
        
    }
    else if(packet.protocol_name == "Internet Protocol version 6")
    {
        Connection *ipv6 = reinterpret_cast<Connection*>(packet.protocol_info);
        this->connections.push_back(*ipv6);
    }
    return *this;
}


int Client::checkConnection(Connection connection)
{
    for(int i; i < this->connections.size(); i++)
    {
        
    }
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
}
