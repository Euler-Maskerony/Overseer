#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <bits/stdc++.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <unistd.h>

int getIfIndex(char *if_name)
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, if_name);
    int sock{};
    struct sockaddr_in conn;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(ioctl(sock, SIOCGIFINDEX, (void *)&ifr) < 0)
    {
        std::cout << "[!] Could not get interface index: " << errno << "\n";
        std::cout << "[*] Packets will be recieving from all available interfaces." << '\n';
        close(sock);
        return 0;
    }
    close(sock);
    return ifr.ifr_ifindex;
}

int socket_setup()
{
    int sock;
    int err;
    std::string device{};
    struct sockaddr_in server;
    std::cout << "Enter name of interface listen on: ";
    std::cin >> device;
    char DEVICE[sizeof(device)];
    strcpy(DEVICE, device.c_str());
    int if_index = getIfIndex(DEVICE);

    if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        std::cout << "[!] Could not create socket: " << errno << '\n';
        close(sock);
        return -1;
    }

    struct sockaddr_ll s_ll;
    s_ll.sll_family = PF_PACKET;
    s_ll.sll_protocol = htons(ETH_P_ALL);
    s_ll.sll_ifindex = if_index;

    if((err = bind(sock, (const sockaddr *) &s_ll, sizeof(s_ll))) < 0)
    {
        std::cout << "[!] Error while binding to interface: " << errno << '\n';
        close(sock);
        return -1;
    }
    else if(if_index != 0 && err >= 0)
        std::cout << "[*] <" << DEVICE << ">: Promiscous mode enabled." << '\n';
    else
        std::cout << "[*] Promiscous mode enabled." << '\n';

    bool ipincl(true);
    struct ifreq interface;
    strcpy(interface.ifr_name, DEVICE);
    ioctl(sock, SIOCGIFFLAGS, &interface);
    interface.ifr_flags |= IFF_PROMISC;
    ioctl(sock, SIOCSIFFLAGS, &interface);

    return sock;
}
