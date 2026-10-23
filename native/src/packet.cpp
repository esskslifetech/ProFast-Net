#include "profast/native.h"

#include <cstring>

namespace {

inline uint16_t rd16(const uint8_t *p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

inline uint64_t fnv1a(uint64_t hash, const uint8_t *p, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        hash ^= p[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

inline uint64_t fnv1a_u32(uint64_t hash, uint32_t v) {
    uint8_t b[4] = {static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16),
                    static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)};
    return fnv1a(hash, b, 4);
}

} // namespace

extern "C" {

int pf_parse_packet(const uint8_t *buf, size_t len, pf_packet_info *out) {
    if (!buf || !out || len < 20) {
        return PF_EINVAL;
    }
    std::memset(out, 0, sizeof(*out));

    const uint8_t version = static_cast<uint8_t>(buf[0] >> 4);

    if (version == 4) {
        const size_t ihl = static_cast<size_t>(buf[0] & 0x0f) * 4;
        if (ihl < 20 || len < ihl) {
            return PF_EINVAL;
        }
        out->ip_version = 4;
        out->tclass = buf[1];
        out->protocol = buf[9];
        out->ttl = buf[8];
        out->src[0] = (static_cast<uint32_t>(buf[12]) << 24) | (static_cast<uint32_t>(buf[13]) << 16) |
                      (static_cast<uint32_t>(buf[14]) << 8) | buf[15];
        out->dst[0] = (static_cast<uint32_t>(buf[16]) << 24) | (static_cast<uint32_t>(buf[17]) << 16) |
                      (static_cast<uint32_t>(buf[18]) << 8) | buf[19];

        const size_t total = rd16(buf + 2);
        out->payload_len = total > ihl ? static_cast<uint32_t>(total - ihl) : 0;

        if ((out->protocol == 6 || out->protocol == 17) && len >= ihl + 4) {
            out->sport = rd16(buf + ihl);
            out->dport = rd16(buf + ihl + 2);
        }
        return PF_OK;
    }

    if (version == 6) {
        if (len < 40) {
            return PF_EINVAL;
        }
        out->ip_version = 6;
        /* traffic class spans the low nibble of byte 0 and the high nibble of byte 1 */
        out->tclass = static_cast<uint8_t>(((buf[0] & 0x0f) << 4) | (buf[1] >> 4));
        out->protocol = buf[6];
        out->ttl = buf[7];
        for (int i = 0; i < 4; ++i) {
            out->src[i] = (static_cast<uint32_t>(buf[8 + i * 4]) << 24) |
                          (static_cast<uint32_t>(buf[9 + i * 4]) << 16) |
                          (static_cast<uint32_t>(buf[10 + i * 4]) << 8) | buf[11 + i * 4];
            out->dst[i] = (static_cast<uint32_t>(buf[24 + i * 4]) << 24) |
                          (static_cast<uint32_t>(buf[25 + i * 4]) << 16) |
                          (static_cast<uint32_t>(buf[26 + i * 4]) << 8) | buf[27 + i * 4];
        }

        const uint32_t payload = (static_cast<uint32_t>(buf[4]) << 8) | buf[5];
        out->payload_len = payload;

        if ((out->protocol == 6 || out->protocol == 17) && len >= 44) {
            out->sport = rd16(buf + 40);
            out->dport = rd16(buf + 42);
        }
        return PF_OK;
    }

    return PF_EINVAL;
}

uint64_t pf_flow_hash(const pf_packet_info *info) {
    if (!info) {
        return 0;
    }
    uint64_t h = 1469598103934665603ull;
    int words = info->ip_version == 6 ? 4 : 1;
    for (int i = 0; i < words; ++i) {
        h = fnv1a_u32(h, info->src[i]);
    }
    for (int i = 0; i < words; ++i) {
        h = fnv1a_u32(h, info->dst[i]);
    }
    uint8_t tail[5] = {info->protocol,
                       static_cast<uint8_t>(info->sport >> 8),
                       static_cast<uint8_t>(info->sport),
                       static_cast<uint8_t>(info->dport >> 8),
                       static_cast<uint8_t>(info->dport)};
    return fnv1a(h, tail, sizeof(tail));
}

uint8_t pf_recommend_dscp(const pf_packet_info *info, uint8_t traffic_class) {
    /* 46 = EF (expedited forwarding), 8 = CS1 (background), 0 = best effort */
    if (traffic_class == 1) {
        if (info && (info->protocol == 6 || info->protocol == 17)) {
            return 46;
        }
        return 40; /* CS5 for non-port traffic such as ICMPv6 */
    }
    if (traffic_class == 2) {
        return 8;
    }
    return 0;
}

} // extern "C"
