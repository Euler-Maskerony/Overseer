struct IPv4_catch
{
    char        version_hsize;
    char        dscp_ecp;
    char16_t    size;
    char16_t    id;
    char16_t    flags_offset;
    char        ttl;
    char        protocol;
    char16_t    checksum;
    char32_t    src;
    char32_t    dest;
};

struct IPv4
{
    int         version;
    int         hsize;
    std::string dscp;
    std::string ecn;
    int         size;
    int         id;
    bool        reserved{false};
    bool        nFrag;
    bool        anFrags;
    int         offset;
    int         ttl;
    std::string protocol;
    int         checksum;
    std::string src;
    std::string dest;
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

struct IPv6
{
    int         version;
    std::string dscp;
    std::string ecn;
    long        flow_label;
    int         payload_length;
    std::string protocol;
    int         hop_limit;
    std::string src;
    std::string dest;
};

