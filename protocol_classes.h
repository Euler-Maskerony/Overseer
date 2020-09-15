#include <string>

#ifndef CL_PROTO
#define CL_PROTO

struct Connection
{
    std::string         net_protocol;
    std::string         trans_protocol;
    std::string         src;
    std::string         dest;
    std::string         state;
    std::string         description;
};

struct Datagrams
{
    std::string         protocol_name;
    std::string         src;
    std::string         dest;
    std::string         description;
};

class IPv4: Connection
{
public:
    unsigned int         size;
    unsigned int         ttl;
    bool                 connection;
    IPv4(const char *packet);
    std::string Description();
    std::string Dump();
};

class IPv6: Connection
{
public:
    unsigned int         size;
    unsigned int         ttl;
    IPv6(const char *packet);
    std::string Description();
    std::string Dump();
};

class ARP: Datagrams
{
public:
    bool                 request;
    std::string          sha;
    std::string          tha;
    ARP(const char *packet);
    std::string Description();
    std::string Dump();
};

class TCP
{
public:
    int         src_port;
    int         dest_port;
    long        sn;
    long        ack_sn;
    
    struct Flags
    {
        bool    urg;
        bool    ack;
        bool    psh;
        bool    rst;
        bool    syn;
        bool    fin;
    };
    Flags flags;
    
    TCP(const char* packet);
    std::string getState();
    std::string getDescription();
};

#endif