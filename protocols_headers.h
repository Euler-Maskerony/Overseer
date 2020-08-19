struct IPv4_catch
{
    unsigned char        version_hsize;
    unsigned char        dscp_ecp;
    char16_t             size;
    char16_t             id;
    char16_t             flags_offset;
    unsigned char        ttl;
    unsigned char        protocol;
    char16_t             checksum;
    uint32_t             src;
    uint32_t             dest;
};

struct IP
{
    unsigned int         version;
    unsigned long        size;
    unsigned int         ttl;
    std::string          protocol;
    std::string          src;
    std::string          dest;
};

struct IPv6_catch
{
    char32_t    ver_tc_fl;
    char16_t    payload_length;
    char        next_header;
    char        hop_limit;
    char32_t    src_first_addr;
    char32_t    src_second_addr;
    char32_t    src_third_addr;
    char32_t    src_fourth_addr;
    char32_t    dest_first_addr;
    char32_t    dest_second_addr;
    char32_t    dest_third_addr;
    char32_t    dest_fourth_addr;
};


struct ARP_catch
{
    uint16_t        htype;
    uint16_t        ptype;
    uint8_t         hlen;
    uint8_t         plen;
    uint16_t        oper;
};

struct ARP
{
    std::string     sha;
    std::string     spa;
    std::string     tha;
    std::string     tpa;
};

struct TCP_catch
{
    uint16_t        src_port;
    uint16_t        dest_port;
    uint32_t        sn;
    uint32_t        ack;
    char16_t        offs_res_flags;
    uint16_t        window_size;
    uint16_t        checksum;
    uint16_t        urg_point;
};

struct TCP
{
    unsigned int         src_port;
    unsigned int         dest_port;
    unsigned long        sn;
    unsigned long        ack_val;
    bool                 urg;
    bool                 ack;
    bool                 psh;
    bool                 rst;
    bool                 syn;
    bool                 fin;
};


