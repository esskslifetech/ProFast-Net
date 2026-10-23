#include "sha256.h"

#include <cstring>

namespace pf {
namespace {

constexpr uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

} // namespace

Sha256::Sha256() : buflen_(0), total_(0) {
    h_[0] = 0x6a09e667u;
    h_[1] = 0xbb67ae85u;
    h_[2] = 0x3c6ef372u;
    h_[3] = 0xa54ff53au;
    h_[4] = 0x510e527fu;
    h_[5] = 0x9b05688cu;
    h_[6] = 0x1f83d9abu;
    h_[7] = 0x5be0cd19u;
}

void Sha256::compress(const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<uint32_t>(block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    uint32_t e = h_[4], f = h_[5], g = h_[6], hh = h_[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
    h_[5] += f;
    h_[6] += g;
    h_[7] += hh;
}

void Sha256::update(const void *data, size_t len) {
    const uint8_t *p = static_cast<const uint8_t *>(data);
    total_ += len;
    if (buflen_ > 0) {
        size_t need = 64 - buflen_;
        size_t take = len < need ? len : need;
        std::memcpy(buf_ + buflen_, p, take);
        buflen_ += take;
        p += take;
        len -= take;
        if (buflen_ == 64) {
            compress(buf_);
            buflen_ = 0;
        }
    }
    while (len >= 64) {
        compress(p);
        p += 64;
        len -= 64;
    }
    if (len > 0) {
        std::memcpy(buf_, p, len);
        buflen_ = len;
    }
}

void Sha256::final(uint8_t out[32]) {
    uint64_t bitlen = total_ * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);

    uint8_t zero = 0;
    while (buflen_ != 56) {
        update(&zero, 1);
    }

    uint8_t lenbuf[8];
    for (int i = 0; i < 8; ++i) {
        lenbuf[i] = static_cast<uint8_t>(bitlen >> (56 - i * 8));
    }
    // update() would bump total_ again; write the length block directly.
    std::memcpy(buf_ + 56, lenbuf, 8);
    compress(buf_);
    buflen_ = 0;

    for (int i = 0; i < 8; ++i) {
        out[i * 4] = static_cast<uint8_t>(h_[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(h_[i] >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(h_[i] >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(h_[i]);
    }
}

void hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen,
                 uint8_t out[32]) {
    uint8_t k[64];
    std::memset(k, 0, sizeof(k));
    if (keylen > 64) {
        Sha256 kh;
        kh.update(key, keylen);
        kh.final(k);
    } else {
        std::memcpy(k, key, keylen);
    }

    uint8_t ipad[64];
    uint8_t opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = static_cast<uint8_t>(k[i] ^ 0x36);
        opad[i] = static_cast<uint8_t>(k[i] ^ 0x5c);
    }

    uint8_t inner[32];
    Sha256 h1;
    h1.update(ipad, 64);
    h1.update(msg, msglen);
    h1.final(inner);

    Sha256 h2;
    h2.update(opad, 64);
    h2.update(inner, 32);
    h2.final(out);
}

bool ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

namespace {
const char kB64Url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}
} // namespace

size_t base64url_encode(const uint8_t *data, size_t len, char *out, size_t cap) {
    /* Unpadded output: a 44-byte token encodes to exactly 59 characters. */
    const size_t rem = len % 3;
    size_t need = (len / 3) * 4 + (rem == 1 ? 2 : (rem == 2 ? 3 : 0));
    if (cap < need + 1) {
        return 0;
    }
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) v |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) v |= data[i + 2];

        out[o++] = kB64Url[(v >> 18) & 0x3f];
        out[o++] = kB64Url[(v >> 12) & 0x3f];
        out[o++] = (i + 1 < len) ? kB64Url[(v >> 6) & 0x3f] : '=';
        out[o++] = (i + 2 < len) ? kB64Url[v & 0x3f] : '=';
    }
    // Strip padding: base64url on the wire is unpadded.
    while (o > 0 && out[o - 1] == '=') {
        --o;
    }
    out[o] = '\0';
    return o;
}

bool base64url_decode(const char *in, size_t len, uint8_t *out, size_t *out_len) {
    if (len % 4 == 1) {
        return false;
    }
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < len; ++i) {
        if (in[i] == '=') {
            break;
        }
        int v = b64_value(in[i]);
        if (v < 0) {
            return false;
        }
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = static_cast<uint8_t>((acc >> bits) & 0xff);
        }
    }
    *out_len = o;
    return true;
}

} // namespace pf
