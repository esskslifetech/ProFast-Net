#include "profast/native.h"

#include <cstring>
#include <vector>

#include "sha256.h"

namespace {

inline void put_be32(uint8_t *p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

inline uint32_t get_be32(const uint8_t *p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline void put_be64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<uint8_t>(v >> (56 - i * 8));
    }
}

inline uint64_t get_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<uint64_t>(p[i]);
    }
    return v;
}

/* key = HMAC(secret, "profast-mirage-v1" || node_be32) */
void derive_key(const uint8_t secret[32], uint32_t node_id, uint8_t key[32]) {
    static const char label[] = PF_MIRAGE_LABEL;
    const size_t label_len = sizeof(label) - 1;
    std::vector<uint8_t> msg(label_len + 4);
    std::memcpy(msg.data(), label, label_len);
    put_be32(msg.data() + label_len, node_id);
    pf::hmac_sha256(secret, 32, msg.data(), msg.size(), key);
}

/* mac input = "profast-spa-v1" || node_be32 || epoch_be64 || nonce16 */
void spa_mac_input(uint32_t node_id, uint64_t epoch, const uint8_t nonce[16], uint8_t *out,
                   size_t *out_len) {
    static const char label[] = PF_MIRAGE_SPA_LABEL;
    const size_t label_len = sizeof(label) - 1;
    std::memcpy(out, label, label_len);
    put_be32(out + label_len, node_id);
    put_be64(out + label_len + 4, epoch);
    std::memcpy(out + label_len + 12, nonce, 16);
    *out_len = label_len + 4 + 8 + 16;
}

} // namespace

extern "C" {

int pf_mirage_derive(const uint8_t secret[32], uint32_t node_id, uint64_t epoch,
                     uint8_t out_addr[16], uint16_t *out_port) {
    if (!secret || !out_addr || !out_port) {
        return PF_EINVAL;
    }

    uint8_t key[32];
    derive_key(secret, node_id, key);

    uint8_t epoch_be[8];
    put_be64(epoch_be, epoch);

    uint8_t material[32];
    pf::hmac_sha256(key, 32, epoch_be, 8, material);

    out_addr[0] = 0xfd;
    std::memcpy(out_addr + 1, material, 15);

    uint16_t raw = static_cast<uint16_t>((material[15] << 8) | material[16]);
    *out_port = static_cast<uint16_t>(PF_MIRAGE_PORT_BASE + (raw % PF_MIRAGE_PORT_SPAN));

    std::memset(key, 0, sizeof(key));
    std::memset(material, 0, sizeof(material));
    return PF_OK;
}

int pf_mirage_spa(const uint8_t secret[32], uint32_t node_id, uint64_t epoch,
                  const uint8_t nonce[16], uint8_t out_token[PF_MIRAGE_TOKEN_LEN], char *out_b64,
                  size_t b64_cap) {
    if (!secret || !nonce || !out_token) {
        return PF_EINVAL;
    }

    uint8_t key[32];
    derive_key(secret, node_id, key);

    put_be32(out_token, node_id);
    put_be64(out_token + 4, epoch);
    std::memcpy(out_token + 12, nonce, 16);

    uint8_t input[64];
    size_t input_len = 0;
    spa_mac_input(node_id, epoch, nonce, input, &input_len);

    uint8_t mac[32];
    pf::hmac_sha256(key, 32, input, input_len, mac);
    std::memcpy(out_token + 28, mac, 16);

    if (out_b64) {
        if (pf::base64url_encode(out_token, PF_MIRAGE_TOKEN_LEN, out_b64, b64_cap) == 0) {
            return PF_EINVAL;
        }
    }

    std::memset(key, 0, sizeof(key));
    std::memset(mac, 0, sizeof(mac));
    return PF_OK;
}

int pf_mirage_verify(const uint8_t secret[32], const uint8_t *token, size_t len, uint64_t now,
                     uint32_t epoch_s, uint32_t *out_node, uint64_t *out_epoch) {
    if (!secret || !token || len != PF_MIRAGE_TOKEN_LEN || epoch_s == 0) {
        return PF_EINVAL;
    }

    const uint32_t node_id = get_be32(token);
    const uint64_t epoch = get_be64(token + 4);
    const uint8_t *nonce = token + 12;
    const uint8_t *mac = token + 28;

    uint8_t key[32];
    derive_key(secret, node_id, key);

    uint8_t input[64];
    size_t input_len = 0;
    spa_mac_input(node_id, epoch, nonce, input, &input_len);

    uint8_t expect[32];
    pf::hmac_sha256(key, 32, input, input_len, expect);
    const bool mac_ok = pf::ct_equal(expect, mac, 16);
    std::memset(key, 0, sizeof(key));
    std::memset(expect, 0, sizeof(expect));

    if (!mac_ok) {
        return PF_EAUTH;
    }

    const uint64_t current = now / epoch_s;
    if (epoch + 1 < current || epoch > current + 1) {
        return PF_ECLOCK;
    }

    if (out_node) *out_node = node_id;
    if (out_epoch) *out_epoch = epoch;
    return PF_OK;
}

int pf_mirage_verify_b64(const uint8_t secret[32], const char *token_b64, size_t len, uint64_t now,
                         uint32_t epoch_s, uint32_t *out_node, uint64_t *out_epoch) {
    if (!token_b64) {
        return PF_EINVAL;
    }
    uint8_t raw[PF_MIRAGE_TOKEN_LEN];
    size_t raw_len = 0;
    if (!pf::base64url_decode(token_b64, len, raw, &raw_len) || raw_len != PF_MIRAGE_TOKEN_LEN) {
        return PF_EINVAL;
    }
    return pf_mirage_verify(secret, raw, raw_len, now, epoch_s, out_node, out_epoch);
}

/* ---------------------------------------------------------------- replay -- */

struct pf_replay {
    size_t capacity;
    size_t cursor;
    std::vector<uint32_t> nodes;
    std::vector<uint64_t> nonce_hi;
    std::vector<uint64_t> nonce_lo;
};

pf_replay *pf_replay_new(size_t capacity) {
    if (capacity < 16) {
        capacity = 16;
    }
    pf_replay *r = new (std::nothrow) pf_replay();
    if (!r) {
        return nullptr;
    }
    r->capacity = capacity;
    r->cursor = 0;
    r->nodes.assign(capacity, 0);
    r->nonce_hi.assign(capacity, 0);
    r->nonce_lo.assign(capacity, 0);
    return r;
}

void pf_replay_free(pf_replay *r) { delete r; }

int pf_replay_check(pf_replay *r, uint32_t node_id, const uint8_t nonce[16]) {
    if (!r || !nonce) {
        return PF_EINVAL;
    }

    uint64_t hi = 0;
    uint64_t lo = 0;
    std::memcpy(&hi, nonce, 8);
    std::memcpy(&lo, nonce + 8, 8);

    for (size_t i = 0; i < r->capacity; ++i) {
        if (r->nonce_hi[i] == hi && r->nonce_lo[i] == lo && r->nodes[i] == node_id) {
            return PF_EREPLAY;
        }
    }

    r->nodes[r->cursor] = node_id;
    r->nonce_hi[r->cursor] = hi;
    r->nonce_lo[r->cursor] = lo;
    r->cursor = (r->cursor + 1) % r->capacity;
    return PF_OK;
}

} // extern "C"
