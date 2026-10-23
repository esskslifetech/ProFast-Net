/*
 * Native known-answer tests. These pin the wire format so that the Python and
 * Go implementations cannot drift from the C++ core without failing CI.
 */
#include "profast/native.h"

#include "sha256.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

void check(bool condition, const char *what) {
    if (!condition) {
        std::fprintf(stderr, "FAIL  %s\n", what);
        ++g_failures;
    } else {
        std::printf("ok    %s\n", what);
    }
}

std::string hex(const uint8_t *data, size_t len) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

void test_sha256() {
    uint8_t digest[32];

    pf::Sha256 h;
    h.update("abc", 3);
    h.final(digest);
    check(hex(digest, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "sha256(\"abc\") matches FIPS 180-4");

    pf::Sha256 empty;
    empty.final(digest);
    check(hex(digest, 32) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "sha256(\"\") matches FIPS 180-4");

    /* Long input crosses the 64-byte block and the padding boundary. */
    std::vector<uint8_t> big(1000, 'a');
    pf::Sha256 longhash;
    longhash.update(big.data(), big.size());
    longhash.final(digest);
    check(hex(digest, 32) == "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
          "sha256(1000 * 'a') matches");
}

void test_hmac() {
    uint8_t mac[32];
    const char *key = "Jefe";
    const char *msg = "what do ya want for nothing?";
    pf::hmac_sha256(reinterpret_cast<const uint8_t *>(key), 4,
                    reinterpret_cast<const uint8_t *>(msg), std::strlen(msg), mac);
    check(hex(mac, 32) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
          "hmac-sha256 matches RFC 4231 case 2");
}

void test_mirage() {
    uint8_t secret[32];
    for (int i = 0; i < 32; ++i) {
        secret[i] = static_cast<uint8_t>(i);
    }

    uint8_t a1[16], a2[16];
    uint16_t p1 = 0, p2 = 0;
    check(pf_mirage_derive(secret, 1, 1000, a1, &p1) == PF_OK, "derive returns ok");
    check(pf_mirage_derive(secret, 1, 1000, a2, &p2) == PF_OK, "derive is repeatable");
    check(std::memcmp(a1, a2, 16) == 0 && p1 == p2, "derive is deterministic");

    uint8_t a3[16];
    uint16_t p3 = 0;
    pf_mirage_derive(secret, 1, 1001, a3, &p3);
    check(std::memcmp(a1, a3, 16) != 0, "next epoch yields a new address");
    check(p1 >= PF_MIRAGE_PORT_BASE && p1 < PF_MIRAGE_PORT_BASE + PF_MIRAGE_PORT_SPAN,
          "derived port stays inside the mirage range");

    uint8_t other[16];
    uint16_t other_port = 0;
    pf_mirage_derive(secret, 2, 1000, other, &other_port);
    check(std::memcmp(a1, other, 16) != 0, "different node yields a different address");
}

void test_spa() {
    uint8_t secret[32];
    for (int i = 0; i < 32; ++i) {
        secret[i] = static_cast<uint8_t>(0xa0 + i);
    }
    uint8_t nonce[16];
    for (int i = 0; i < 16; ++i) {
        nonce[i] = static_cast<uint8_t>(i * 3);
    }

    uint8_t token[PF_MIRAGE_TOKEN_LEN];
    char b64[PF_MIRAGE_B64_LEN];
    check(pf_mirage_spa(secret, 7, 500, nonce, token, b64, sizeof(b64)) == PF_OK, "spa minted");

    uint32_t node = 0;
    uint64_t epoch = 0;
    check(pf_mirage_verify(secret, token, sizeof(token), 5000, 10, &node, &epoch) == PF_OK,
          "spa verifies in the current epoch");
    check(node == 7 && epoch == 500, "spa carries node and epoch");

    check(pf_mirage_verify(secret, token, sizeof(token), 5010, 10, &node, &epoch) == PF_OK,
          "spa tolerates one epoch of clock skew");
    check(pf_mirage_verify(secret, token, sizeof(token), 5100, 10, &node, &epoch) == PF_ECLOCK,
          "stale spa is rejected");

    uint8_t tampered[PF_MIRAGE_TOKEN_LEN];
    std::memcpy(tampered, token, sizeof(tampered));
    tampered[20] ^= 0x01;
    check(pf_mirage_verify(secret, tampered, sizeof(tampered), 5000, 10, &node, &epoch) == PF_EAUTH,
          "tampered spa is rejected");

    uint8_t wrong_secret[32];
    std::memcpy(wrong_secret, secret, 32);
    wrong_secret[0] ^= 0xff;
    check(pf_mirage_verify(wrong_secret, token, sizeof(token), 5000, 10, &node, &epoch) == PF_EAUTH,
          "foreign secret is rejected");

    pf_replay *replay = pf_replay_new(64);
    uint32_t n = 0;
    uint64_t e = 0;
    check(pf_mirage_verify(secret, token, sizeof(token), 5000, 10, &n, &e) == PF_OK, "first use ok");
    check(pf_replay_check(replay, 7, nonce) == PF_OK, "nonce recorded");
    check(pf_replay_check(replay, 7, nonce) == PF_EREPLAY, "nonce replay detected");
    pf_replay_free(replay);
}

void test_packet() {
    const uint8_t syn[40] = {0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06,
                             0x00, 0x00, 0xc0, 0xa8, 0x01, 0x0a, 0x08, 0x08, 0x08, 0x08,
                             0xc9, 0x3b, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00};
    pf_packet_info info;
    check(pf_parse_packet(syn, sizeof(syn), &info) == PF_OK, "ipv4 packet parses");
    check(info.ip_version == 4, "ipv4 version detected");
    check(info.protocol == 6, "tcp protocol detected");
    check(info.src[0] == 0xc0a8010a && info.dst[0] == 0x08080808, "addresses decoded");
    check(info.sport == 51515 && info.dport == 443, "ports decoded");
    check(pf_recommend_dscp(&info, 1) == 46, "focused traffic maps to EF");
    check(pf_recommend_dscp(&info, 2) == 8, "background traffic maps to CS1");

    const uint8_t short_frame[8] = {0x45, 0, 0, 0, 0, 0, 0, 0};
    check(pf_parse_packet(short_frame, sizeof(short_frame), &info) == PF_EINVAL,
          "truncated packet rejected");

    /* IPv6 / UDP / DNS */
    uint8_t v6[68];
    std::memset(v6, 0, sizeof(v6));
    v6[0] = 0x60;
    v6[4] = 0x00;
    v6[5] = 0x1c;
    v6[6] = 17;
    v6[7] = 64;
    v6[8 + 15] = 0x01;
    v6[24 + 15] = 0x02;
    v6[40] = 0x04;
    v6[41] = 0xd2; /* 1234 */
    v6[42] = 0x00;
    v6[43] = 0x35; /* 53 */
    check(pf_parse_packet(v6, sizeof(v6), &info) == PF_OK, "ipv6 packet parses");
    check(info.ip_version == 6 && info.protocol == 17, "ipv6 udp detected");
    check(info.sport == 1234 && info.dport == 53, "ipv6 ports decoded");
}

void test_bucket() {
    pf_bucket *b = pf_bucket_new(1000.0, 2000.0);
    check(b != nullptr, "bucket allocates");
    uint64_t wait = 0;
    check(pf_bucket_consume(b, 1500, 0.0, &wait) == PF_OK, "burst credit is spendable");
    check(pf_bucket_consume(b, 1500, 0.0, &wait) == PF_EBUSY, "over-burst is refused");
    check(wait == 1000, "wait time reflects the deficit and rate");
    check(pf_bucket_consume(b, 1000, 1.0, &wait) == PF_OK, "credit refills over time");
    pf_bucket_free(b);
}

void test_flowtable() {
    pf_flowtable *t = pf_flowtable_new(1024);
    check(t != nullptr, "flow table allocates");

    pf_packet_info info;
    std::memset(&info, 0, sizeof(info));
    info.ip_version = 4;
    info.protocol = 6;
    info.src[0] = 0x0100007f;
    info.dst[0] = 0x08080808;
    info.sport = 50000;
    info.dport = 443;

    uint64_t packets = 0;
    check(pf_flowtable_touch(t, &info, 100, &packets) == PF_OK, "flow inserted");
    check(packets == 1, "first packet counted");
    check(pf_flowtable_touch(t, &info, 100, &packets) == PF_OK && packets == 2,
          "same flow accumulates");
    check(pf_flowtable_size(t) == 1, "flow table deduplicates");

    for (int i = 0; i < 2000; ++i) {
        info.sport = static_cast<uint16_t>(1024 + i);
        pf_flowtable_touch(t, &info, 10, nullptr);
    }
    check(pf_flowtable_size(t) <= 1024, "flow table stays bounded");
    pf_flowtable_free(t);
}

} // namespace

int main() {
    test_sha256();
    test_hmac();
    test_mirage();
    test_spa();
    test_packet();
    test_bucket();
    test_flowtable();

    if (g_failures != 0) {
        std::fprintf(stderr, "\n%d native check(s) failed\n", g_failures);
        return 1;
    }
    std::printf("\nall native checks passed\n");
    return 0;
}
