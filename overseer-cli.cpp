#include <iostream>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <thread>
#include "packets_processing.h"
#include "protocol_classes.h"
#include "client.h"


#define BUF_SIZE 65536
typedef int SOCKET;

bool kill_thread(false);
bool pause_thread(false);

int socket_setup();


void recievingThread(std::vector<Client> *clients, SOCKET sock)
{
    unsigned char buffer[BUF_SIZE];

    while(1)
    {
        if(kill_thread)
            std::terminate();
        
        if(pause_thread)
            while(pause_thread)
                sleep(1);

        if(recvfrom(sock, buffer, BUF_SIZE, 0, 0, 0) < 0)
        {
            std::cout << "[!] Error while recieving packets: " << errno << '\n';
            close(sock);
            break;
        }
        else
        {
            Packet packet_info(buffer);
            if(not packet_info.mac_local.empty())
                ClientHandler(packet_info, *clients);
            
        }
    }
}

void Tree(std::vector<Client> *clients)
{
    std::string tree{""};
    for(Client &client : *clients)
        tree += client.Branch();
    std::cout << tree << '\n';
}

int main()
{
    std::vector<Client> clients;
    std::string command;

    std::cout << "Overseer 0.1" << '\n';
    std::cout << "Type \"help\" for more information." << '\n';
    SOCKET sock{socket_setup()};
    std::thread recieving_packets(recievingThread, &clients, sock);
    std::cout << "Recieving packets thread has been started" << '\n';

    while(1)
    {
        std::cout << ">>> ";
        std::cin >> command;

        if(command == "tree")
            Tree(&clients);
        else if(command == "stop")
            kill_thread = true;
        else if(command == "clear")
            clients.erase(clients.begin());
        else if(command == "pause")
            pause_thread = true;
        else if(command == "resume")
            pause_thread = false;
        else if(command == "")
            continue;
        else
            std::cout << "[*] Command not found: " << command;
        
        std::cout << '\n';
    }

    return 0;
}
