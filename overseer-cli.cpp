#include <iostream>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include "packets_processing.h"
#include "client.h"


#define BUF_SIZE 65536
typedef int SOCKET;

int socket_setup();

int main()
{
    char    buffer[BUF_SIZE];
    SOCKET  sock{socket_setup()};
    std::vector<Client> clients;

    while(1)
    {
        if((recvfrom(sock, buffer, BUF_SIZE, 0, 0, 0)) < 0)
        {
            std::cout << "[!] Error while recieving packets: " << errno << '\n';
            close(sock);
            return -1;
        }
        else
        {
            Packet packet_info(buffer);
            ClientHandler(packet_info, clients);
        }
    }
    return 0;
}
