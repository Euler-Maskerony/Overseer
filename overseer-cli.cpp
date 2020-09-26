#include <iostream>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <thread>
#include "packets_processing.h"
#include "client.h"


#define BUF_SIZE 65536
typedef int SOCKET;

std::vector<Client> clients; // TODO: Make it local
bool kill_thread(false);
bool pause_thread(false);

int socket_setup();

void recievingThread()
{
    char    buffer[BUF_SIZE];
    SOCKET  sock{socket_setup()};
    sleep(1);

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
            ClientHandler(packet_info, clients);
        }
    }
}

int main()
{
    std::cout << "Overseer 0.1" << '\n';
    std::cout << "Type \"help\" for more information." << '\n';
    std::thread recieving_packets(recievingThread);
    std::cout << "Recieving packets thread has been started" << '\n';

    while(1)
    {
        std::string command;
        std::cin >> command;

        std::cout << ">>> ";

        if(command == "tree")
            std::cout << "nothing yet)" << '\n';
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
