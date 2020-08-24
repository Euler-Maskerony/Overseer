#include <string>

class IPv4
{
public:
    unsigned int         version;
    unsigned int         size;
    unsigned int         ttl;
    std::string          protocol;
    std::string          src;
    std::string          dest;
    void Parse(const char *packet);
    std::string Dump();
};

class IPv6
{
public:
    unsigned int         version;
    unsigned int         size;
    unsigned int         ttl;
    std::string          protocol;
    std::string          src;
    std::string          dest;
    void Parse(const char *packet);
    std::string Dump();
};

class ARP
{
public:
    std::string          sha;
    std::string          spa;
    std::string          tha;
    std::string          tpa;
    void Parse(const char *packet);
    std::string Dump();
};
