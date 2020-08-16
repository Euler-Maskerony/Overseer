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

struct IP
{
    int         version;
    long        size;
    int         ttl;
    std::string protocol;
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
