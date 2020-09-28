#include <string>

#ifndef CL_PROTO
#define CL_PROTO

class Connection
{
public:
    std::string         net_protocol;
    std::string         trans_protocol;
    std::string         local;
    std::string         server;
    std::string         state;
    std::string         description;
    int                 packets_count;


    Connection operator+=(const Connection connection_dg);
private:
    void getDescription();

};

struct Datagrams
{
    std::string         protocol_name;
    std::string         src;
    std::string         dest;
    std::string         description;
};

class IPv4
{
public:
    unsigned int         size;
    unsigned int         ttl;
    unsigned int         hsize;         
    bool                 connection;
    void*                info;
    IPv4(const char *packet);
    std::string Description();
    std::string Dump();
};

class IPv6
{
public:
    unsigned int         size;
    unsigned int         ttl;
    void*                info;
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

class TCP: public Connection
{
public:
    unsigned int         src_port;
    unsigned int         dest_port;
    long                 sn;
    long                 ack_sn;
    
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