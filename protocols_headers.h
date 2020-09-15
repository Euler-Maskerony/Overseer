#ifndef PROTO_HDRS
#define PROTO_HDRS

struct IPv4_catch
{
    uint8_t              version_hsize;
    uint8_t              dscp_ecp;
    uint16_t             size;
    uint16_t             id;
    uint16_t             flags_offset;
    uint8_t              ttl;
    uint8_t              protocol;
    uint16_t             checksum;
    uint32_t             src;
    uint32_t             dest;
};

struct IPv6_catch
{
    uint32_t    ver_tc_fl;
    uint16_t    payload_length;
    uint8_t     next_header;
    uint8_t     hop_limit;
    uint32_t    src_first_addr;
    uint32_t    src_second_addr;
    uint32_t    src_third_addr;
    uint32_t    src_fourth_addr;
    uint32_t    dest_first_addr;
    uint32_t    dest_second_addr;
    uint32_t    dest_third_addr;
    uint32_t    dest_fourth_addr;
};


struct ARP_catch
{
    uint16_t        htype;
    uint16_t        ptype;
    uint8_t         hlen;
    uint8_t         plen;
    uint16_t        oper;
};

struct TCP_catch
{
    uint16_t        src_port;
    uint16_t        dest_port;
    uint32_t        sn;
    uint32_t        ack;
    uint16_t        offs_res_flags;
    uint16_t        window_size;
    uint16_t        checksum;
    uint16_t        urg_point;
};

#endif
