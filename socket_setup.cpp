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

typedef int SOCKET;

int getIFIndex(char *if_name)
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, if_name);
    int sock{};
    struct sockaddr_in conn;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(ioctl(sock, SIOCGIFINDEX, (void *)&ifr) < 0)
    {
        std::cout << "[!] Could not get interface index: " << errno << "\n";
        std::cout << "[!] Packets will be recieving from all available interfaces." << '\n';
        close(sock);
        return 0;
    }
    close(sock);
    return ifr.ifr_ifindex;
}

void togglePromisc(char *if_name, SOCKET sock, bool on)
{
    if(on)
    {
        struct ifreq interface;
        strcpy(interface.ifr_name, if_name);
        ioctl(sock, SIOCGIFFLAGS, &interface);
        interface.ifr_flags |= IFF_PROMISC;
        ioctl(sock, SIOCSIFFLAGS, &interface);
    }
    else
    {
        struct ifreq interface;
        strcpy(interface.ifr_name, if_name);
        ioctl(sock, SIOCGIFFLAGS, &interface);
        interface.ifr_flags &= ~(IFF_PROMISC);
        ioctl(sock, SIOCSIFFLAGS, &interface);
    }
}

int socket_setup(char *DEVICE)
{
    SOCKET sock;
    int err;
    std::string device{};
    struct sockaddr_in server;
    int if_index = getIFIndex(DEVICE);

    if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        std::cout << "[!!] Could not create socket: " << errno << '\n';
        close(sock);
        return -1;
    }

    struct sockaddr_ll s_ll;
    s_ll.sll_family = PF_PACKET;
    s_ll.sll_protocol = htons(ETH_P_ALL);
    s_ll.sll_ifindex = if_index;

    if((err = bind(sock, (const sockaddr *) &s_ll, sizeof(s_ll))) < 0)
    {
        std::cout << "[!!] Error while binding to interface: " << errno << '\n';
        close(sock);
        return -1;
    }
    else if(if_index != 0 && err >= 0)
        std::cout << "[*] <" << DEVICE << ">: Promiscous mode enabled." << '\n';
    else
        std::cout << "[!] Promiscous mode cannot be enabled." << '\n';

    togglePromisc(DEVICE, sock, true);

    return sock;
}
