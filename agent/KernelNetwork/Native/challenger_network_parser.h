#ifndef CHALLENGER_NETWORK_PARSER_H
#define CHALLENGER_NETWORK_PARSER_H

#include <linux/types.h>

enum challenger_parse_result {
    CHALLENGER_PARSE_OK = 0,
    CHALLENGER_PARSE_MALFORMED = 1,
    CHALLENGER_PARSE_UNSUPPORTED = 2,
    CHALLENGER_PARSE_NOT_TCP_UDP = 3,
    CHALLENGER_PARSE_EXTENSION = 4,
};

struct challenger_parsed_ip {
    __u8 family;
    __u8 protocol;
    __u16 layer4_offset;
    __u8 source_address[16];
    __u8 destination_address[16];
};

static __inline void challenger_normalize_addresses(
    const struct challenger_parsed_ip *parsed,
    __u8 egress,
    __u8 local_address[16],
    __u8 remote_address[16])
{
    if (egress) {
        __builtin_memcpy(local_address, parsed->source_address, 16);
        __builtin_memcpy(remote_address, parsed->destination_address, 16);
    } else {
        __builtin_memcpy(local_address, parsed->destination_address, 16);
        __builtin_memcpy(remote_address, parsed->source_address, 16);
    }
}

static __inline enum challenger_parse_result challenger_parse_ipv4(
    const __u8 header[20],
    struct challenger_parsed_ip *parsed)
{
    if ((header[0] >> 4) != 4)
        return CHALLENGER_PARSE_MALFORMED;
    __u16 layer4_offset = (__u16)(header[0] & 0x0f) * 4;
    if (layer4_offset < 20 || layer4_offset > 60)
        return CHALLENGER_PARSE_MALFORMED;
    if ((header[6] & 0x3f) != 0 || header[7] != 0)
        return CHALLENGER_PARSE_UNSUPPORTED;
    if (header[9] != 6 && header[9] != 17)
        return CHALLENGER_PARSE_NOT_TCP_UDP;

    __builtin_memset(parsed, 0, sizeof(*parsed));
    parsed->family = 4;
    parsed->protocol = header[9];
    parsed->layer4_offset = layer4_offset;
    __builtin_memcpy(parsed->source_address, &header[12], 4);
    __builtin_memcpy(parsed->destination_address, &header[16], 4);
    return CHALLENGER_PARSE_OK;
}

static __inline enum challenger_parse_result challenger_parse_ipv6(
    const __u8 header[40],
    struct challenger_parsed_ip *parsed)
{
    if ((header[0] >> 4) != 6)
        return CHALLENGER_PARSE_MALFORMED;
    __builtin_memset(parsed, 0, sizeof(*parsed));
    parsed->family = 6;
    parsed->protocol = header[6];
    parsed->layer4_offset = 40;
    __builtin_memcpy(parsed->source_address, &header[8], 16);
    __builtin_memcpy(parsed->destination_address, &header[24], 16);
    if (header[6] == 6 || header[6] == 17)
        return CHALLENGER_PARSE_OK;
    if (header[6] == 0 || header[6] == 43 || header[6] == 44 || header[6] == 50
        || header[6] == 51 || header[6] == 60 || header[6] == 135)
        return CHALLENGER_PARSE_EXTENSION;
    return CHALLENGER_PARSE_NOT_TCP_UDP;
}

static __inline int challenger_is_ipv6_extension(__u8 protocol)
{
    return protocol == 0 || protocol == 43 || protocol == 44 || protocol == 50
        || protocol == 51 || protocol == 60 || protocol == 135;
}

static __inline enum challenger_parse_result challenger_parse_ipv6_extension(
    __u8 protocol,
    const __u8 prefix[8],
    __u8 *next_protocol,
    __u16 *header_length)
{
    *next_protocol = prefix[0];
    if (protocol == 44) {
        __u16 fragment_offset = ((__u16)prefix[2] << 8) | prefix[3];
        if ((fragment_offset & 0xfff8) != 0)
            return CHALLENGER_PARSE_UNSUPPORTED;
        *header_length = 8;
        return CHALLENGER_PARSE_OK;
    }
    if (protocol == 50)
        return CHALLENGER_PARSE_UNSUPPORTED;
    if (protocol == 51) {
        *header_length = (__u16)(prefix[1] + 2) * 4;
        return *header_length >= 8 ? CHALLENGER_PARSE_OK : CHALLENGER_PARSE_MALFORMED;
    }
    if (protocol == 0 || protocol == 43 || protocol == 60 || protocol == 135) {
        *header_length = (__u16)(prefix[1] + 1) * 8;
        return *header_length >= 8 ? CHALLENGER_PARSE_OK : CHALLENGER_PARSE_MALFORMED;
    }
    return CHALLENGER_PARSE_NOT_TCP_UDP;
}

#endif
