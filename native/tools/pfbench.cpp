/*
 * pfbench - native verification and inspection tool.
 *
 *   pfbench selftest              known-answer tests + cross-language vectors
 *   pfbench derive <secretHex> <nodeId> <epoch>
 *   pfbench spa    <secretHex> <nodeId> <epoch> <nonceHex>
 *   pfbench verify <secretHex> <tokenB64> <now> <epochSeconds>
 *   pfbench bench                 flow table throughput sanity check
 */
#include "profast/native.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> hex_decode(const std::string &hex) {
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0) {
        return out;
    }
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return {};
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string hex_encode(const uint8_t *data, size_t len) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

std::string format_v6(const uint8_t addr[16]) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                  addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8],
                  addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    return std::string(buf);
}

int slurp_secret(const char *hex, uint8_t out[32]) {
    std::vector<uint8_t> raw = hex_decode(hex ? hex : "");
    if (raw.size() != 32) {
        std::fprintf(stderr, "secret must be exactly 32 hex-encoded bytes\n");
        return 1;
    }
    std::memcpy(out, raw.data(), 32);
    return 0;
}

uint32_t parse_u32(const char *s) { return static_cast<uint32_t>(std::strtoul(s, nullptr, 10)); }
uint64_t parse_u64(const char *s) { return static_cast<uint64_t>(std::strtoull(s, nullptr, 10)); }

int cmd_derive(int argc, char **argv) {
    if (argc < 5) {
        std::fprintf(stderr, "usage: pfbench derive <secretHex> <nodeId> <epoch>\n");
        return 2;
    }
    uint8_t secret[32];
    if (slurp_secret(argv[2], secret) != 0) return 2;

    uint8_t addr[16];
    uint16_t port = 0;
    int rc = pf_mirage_derive(secret, parse_u32(argv[3]), parse_u64(argv[4]), addr, &port);
    if (rc != PF_OK) {
        std::fprintf(stderr, "derive failed: %s\n", pf_strerror(rc));
        return 1;
    }
    std::printf("{\"address\":\"%s\",\"port\":%u}\n", format_v6(addr).c_str(),
                static_cast<unsigned>(port));
    return 0;
}

int cmd_spa(int argc, char **argv) {
    if (argc < 6) {
        std::fprintf(stderr, "usage: pfbench spa <secretHex> <nodeId> <epoch> <nonceHex>\n");
        return 2;
    }
    uint8_t secret[32];
    if (slurp_secret(argv[2], secret) != 0) return 2;

    std::vector<uint8_t> nonce = hex_decode(argv[5]);
    if (nonce.size() != 16) {
        std::fprintf(stderr, "nonce must be 16 hex-encoded bytes\n");
        return 2;
    }

    uint8_t token[PF_MIRAGE_TOKEN_LEN];
    char b64[PF_MIRAGE_B64_LEN];
    int rc = pf_mirage_spa(secret, parse_u32(argv[3]), parse_u64(argv[4]), nonce.data(), token, b64,
                           sizeof(b64));
    if (rc != PF_OK) {
        std::fprintf(stderr, "spa failed: %s\n", pf_strerror(rc));
        return 1;
    }
    std::printf("{\"token\":\"%s\",\"raw\":\"%s\"}\n", b64, hex_encode(token, sizeof(token)).c_str());
    return 0;
}

int cmd_verify(int argc, char **argv) {
    if (argc < 6) {
        std::fprintf(stderr, "usage: pfbench verify <secretHex> <tokenB64> <now> <epochSeconds>\n");
        return 2;
    }
    uint8_t secret[32];
    if (slurp_secret(argv[2], secret) != 0) return 2;

    uint32_t node = 0;
    uint64_t epoch = 0;
    int rc = pf_mirage_verify_b64(secret, argv[3], std::strlen(argv[3]), parse_u64(argv[4]),
                                  parse_u32(argv[5]), &node, &epoch);
    if (rc != PF_OK) {
        std::printf("{\"ok\":false,\"error\":\"%s\"}\n", pf_strerror(rc));
        return 1;
    }
    std::printf("{\"ok\":true,\"node\":%u,\"epoch\":%llu}\n", node,
                static_cast<unsigned long long>(epoch));
    return 0;
}

void selftest() {
    const uint8_t secret[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    const uint8_t nonce[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    uint8_t addr[16];
    uint16_t port = 0;
    pf_mirage_derive(secret, 1, 1000, addr, &port);

    uint8_t token[PF_MIRAGE_TOKEN_LEN];
    char token_b64[PF_MIRAGE_B64_LEN];
    pf_mirage_spa(secret, 1, 1000, nonce, token, token_b64, sizeof(token_b64));

    uint32_t node = 0;
    uint64_t epoch = 0;
    int verify_rc = pf_mirage_verify_b64(secret, token_b64, std::strlen(token_b64), 10005, 10,
                                         &node, &epoch);

    /* A fixed IPv4/TCP SYN: 192.168.1.10:51515 -> 8.8.8.8:443 */
    const uint8_t frame[40] = {0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06,
                               0x00, 0x00, 0xc0, 0xa8, 0x01, 0x0a, 0x08, 0x08, 0x08, 0x08,
                               0xc9, 0x3b, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00};
    pf_packet_info info;
    int parse_rc = pf_parse_packet(frame, sizeof(frame), &info);
    uint64_t flow = pf_flow_hash(&info);

    std::printf("{\n");
    std::printf("  \"version\": \"%s\",\n", pf_version());
    std::printf("  \"mirage\": {\"secret\": \"%s\", \"node\": 1, \"epoch\": 1000, "
                "\"address\": \"%s\", \"port\": %u},\n",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                format_v6(addr).c_str(), static_cast<unsigned>(port));
    std::printf("  \"spa\": {\"nonce\": \"000102030405060708090a0b0c0d0e0f\", \"token\": \"%s\", "
                "\"raw\": \"%s\"},\n",
                token_b64, hex_encode(token, sizeof(token)).c_str());
    std::printf("  \"verify\": {\"rc\": %d, \"node\": %u, \"epoch\": %llu},\n", verify_rc, node,
                static_cast<unsigned long long>(epoch));
    std::printf("  \"packet\": {\"rc\": %d, \"sport\": %u, \"dport\": %u, \"dscp_focus\": %u, "
                "\"flow_hash\": \"%016llx\"}\n",
                parse_rc, info.sport, info.dport,
                pf_recommend_dscp(&info, 1), static_cast<unsigned long long>(flow));
    std::printf("}\n");
}

int cmd_priority(int argc, char **argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: pfbench priority <pid> <level -2..2>\n");
        return 2;
    }
    const uint32_t pid = parse_u32(argv[2]);
    const int level = static_cast<int>(std::strtol(argv[3], nullptr, 10));
    const int rc = pf_set_process_priority(pid, level);
    std::printf("{\"ok\":%s,\"pid\":%u,\"level\":%d,\"error\":\"%s\"}\n", rc == PF_OK ? "true" : "false",
                pid, level, pf_strerror(rc));
    return rc == PF_OK ? 0 : 1;
}

int cmd_power(int argc, char **argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: pfbench power <pid> <0|1>\n");
        return 2;
    }
    const uint32_t pid = parse_u32(argv[2]);
    const int disable = std::strtol(argv[3], nullptr, 10) != 0 ? 1 : 0;
    const int rc = pf_disable_power_throttling(pid, disable);
    std::printf("{\"ok\":%s,\"pid\":%u,\"throttling_disabled\":%s,\"error\":\"%s\"}\n",
                rc == PF_OK ? "true" : "false", pid, disable ? "true" : "false",
                pf_strerror(rc));
    return rc == PF_OK ? 0 : 1;
}

int cmd_bench() {
    pf_flowtable *t = pf_flowtable_new(1u << 16);
    if (!t) {
        std::fprintf(stderr, "allocation failed\n");
        return 1;
    }

    pf_packet_info info;
    std::memset(&info, 0, sizeof(info));
    info.ip_version = 4;
    info.protocol = 6;
    info.src[0] = 0xc0a8010a;
    info.dst[0] = 0x08080808;
    info.sport = 51515;
    info.dport = 443;

    const auto start = std::chrono::steady_clock::now();
    const int iterations = 1000000;
    for (int i = 0; i < iterations; ++i) {
        info.sport = static_cast<uint16_t>(1024 + (i % 40000));
        pf_flowtable_touch(t, &info, 128, nullptr);
    }
    const auto end = std::chrono::steady_clock::now();
    const double seconds = std::chrono::duration<double>(end - start).count();

    std::printf("flows=%zu operations=%d elapsed=%.3fs rate=%.0f ops/s\n", pf_flowtable_size(t),
                iterations, seconds, iterations / seconds);
    pf_flowtable_free(t);
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        std::fprintf(stderr,
                     "pfbench %s\n"
                     "usage: pfbench <selftest|bench|derive|spa|verify|priority|power> [args...]\n",
                     pf_version());
        return 2;
    }

    const std::string cmd = argv[1];
    if (cmd == "selftest") {
        selftest();
        return 0;
    }
    if (cmd == "bench") {
        return cmd_bench();
    }
    if (cmd == "derive") {
        return cmd_derive(argc, argv);
    }
    if (cmd == "spa") {
        return cmd_spa(argc, argv);
    }
    if (cmd == "verify") {
        return cmd_verify(argc, argv);
    }
    if (cmd == "priority") {
        return cmd_priority(argc, argv);
    }
    if (cmd == "power") {
        return cmd_power(argc, argv);
    }

    std::fprintf(stderr, "unknown command: %s\n", cmd.c_str());
    return 2;
}
