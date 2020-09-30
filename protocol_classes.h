#include <string>

#ifndef CL_PROTO
#define CL_PROTO

class Connection
{
public:
    std::string         net_protocol;
    std::string         local;
    std::string         server;
    std::string         description;
    long long           size;
    int                 init_time;
    int                 packets_count;

    Connection() : packets_count{ 1 }{};
    Connection operator+=(const Connection connection_dg);

private:
    void getDescription();

protected:
    std::string         state;
    std::string         trans_protocol;


};

class IPv4
{
private:
    unsigned int         size;
    unsigned int         ttl;
    unsigned int         hsize;   
 
public:     
    bool                 connection;
    bool                 is_src_local;
    Connection           info;
    IPv4(const unsigned char *packet);
    std::string Description();
    std::string Dump();
};

class IPv6
{
private:
    unsigned int         size;
    unsigned int         ttl;

public:
    bool                 connection;
    Connection           info;
    IPv6(const unsigned char *packet);
    std::string Description();
    std::string Dump();
};

class ARP
{
private:
    bool                request;
    std::string         protocol_name;
    std::string         src;
    std::string         dest;
    std::string         sha;
    std::string         tha;

public:
    ARP(const unsigned char *packet);
    std::string Description();
    std::string Dump();
};

class TCP: public Connection
{
private:
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

public:
    TCP(const unsigned char* packet);
    std::string getState();
    std::string getDescription();
};

#endif