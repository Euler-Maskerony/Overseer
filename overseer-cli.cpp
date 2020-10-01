#include <iostream>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <thread>
#include <signal.h>
#include "packets_processing.h"
#include "protocol_classes.h"
#include "client.h"


#define BUF_SIZE 65536
typedef int SOCKET;

bool kill_thread(false);
bool pause_thread(false);

void togglePromisc(char *if_name, SOCKET sock, bool on);
int socket_setup(char *DEVICE);


void recievingThread(std::vector<Client> *clients, SOCKET sock)
{
    unsigned char buffer[BUF_SIZE];

    while(1)
    {
        if(kill_thread)
            break;
        
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

void signal_callback_handler(int signum)
{
    std::cout << '\n' << "Terminating..." << '\n';
    exit(signum);
}

int main()
{
    std::vector<Client> clients;
    std::string command;
    std::string device;
    signal(SIGINT, signal_callback_handler);

    std::cout << "Overseer" << '\n';
    std::cout << "Type \"help\" for more information." << '\n' << '\n';
    std::cout << "[?] Enter name of interface listen on: ";
    std::cin >> device;
    char DEVICE[sizeof(device)];
    strcpy(DEVICE, device.c_str());
    SOCKET sock{socket_setup(DEVICE)};
    std::thread recieving_packets(recievingThread, &clients, sock);
    std::cout << "[*] Recieving packets thread has been started" << '\n' << '\n';

    while(1)
    {
        std::cout << ">>> ";
        std::cin >> command;

        if(command == "tree")
            Tree(&clients);
        else if(command == "stop")
        {
            kill_thread = true;
            recieving_packets.join();
            togglePromisc(DEVICE, sock, false);
            close(sock);
            std::cout << "[*] <" << DEVICE << ">: Promiscous mode disabled." << '\n';
        }
        else if(command == "clear")
            clients.erase(clients.begin());
        else if(command == "pause")
        {
            if(not pause_thread)
                std::cout << "[*] Recieving paused. To unpause type \"resume\"" << '\n';
            else
                std::cout << "[*] Already paused" << '\n';
            pause_thread = true;
        }
        else if(command == "resume")
        {
            if(pause_thread)
                std::cout << "[*] Recieving thread is running now" << '\n';
            else
                std::cout << "[*] Already running" << '\n';
            pause_thread = false;
        }
        else if(command == "help")
        {
            std::cout << "Welcome to Overseer!\n" << "Tool for controlling connections over local network.\n\n";
            std::cout << "Available commands:\n";
            std::cout << "tree      Shows connections tree.\n";
            std::cout << "stop      Safe termination of recieving thread.\n";
            std::cout << "clear     Clears connections tree.\n";
            std::cout << "pause     Pauses recieving thread.\n";
            std::cout << "resume    Unpauses recieving thread.\n";
            std::cout << "help      Prints this help page\n";
        }
        else if(command == "help!")
            std::cout << "Don't panic!" << '\n';
        else
            std::cout << "[!] Command not found: " << command;
        
        std::cout << '\n';
    }

    return 0;
}
