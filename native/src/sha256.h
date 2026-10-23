#ifndef PROFAST_SHA256_H
#define PROFAST_SHA256_H

#include <cstddef>
#include <cstdint>

namespace pf {

class Sha256 {
public:
    Sha256();
    void update(const void *data, size_t len);
    void final(uint8_t out[32]);

private:
    void compress(const uint8_t block[64]);

    uint32_t h_[8];
    uint8_t buf_[64];
    size_t buflen_;
    uint64_t total_;
};

void hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen,
                 uint8_t out[32]);

/* Constant-time comparison; returns true when both buffers are equal. */
bool ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* Unpadded base64url. Returns the number of bytes written or 0 on overflow. */
size_t base64url_encode(const uint8_t *data, size_t len, char *out, size_t cap);
bool base64url_decode(const char *in, size_t len, uint8_t *out, size_t *out_len);

} // namespace pf

#endif
