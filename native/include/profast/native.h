/*
 * ProFast-Net native core - stable C ABI.
 *
 * The library is deliberately dependency-free so it can be linked into the
 * Go daemon (cgo), loaded by the Python control plane (ctypes) and embedded
 * in the kernel-tier packet paths.
 *
 * Every function is thread-safe unless documented otherwise.
 */
#ifndef PROFAST_NATIVE_H
#define PROFAST_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define PF_API __declspec(dllexport)
#define PF_CALL __cdecl
#else
#define PF_API __attribute__((visibility("default")))
#define PF_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PF_OK = 0,
    PF_EINVAL = -1,
    PF_ENOTSUP = -2,
    PF_EPERM = -3,
    PF_EIO = -4,
    PF_EBUSY = -5,
    PF_EAUTH = -6,
    PF_EREPLAY = -7,
    PF_ECLOCK = -8
} pf_status;

/* Wire constants shared by every language implementation. */
#define PF_MIRAGE_LABEL "profast-mirage-v1"
#define PF_MIRAGE_SPA_LABEL "profast-spa-v1"
#define PF_MIRAGE_TOKEN_LEN 44
#define PF_MIRAGE_B64_LEN 60
#define PF_MIRAGE_PORT_BASE 20000
#define PF_MIRAGE_PORT_SPAN 40000

typedef struct pf_packet_info {
    uint8_t ip_version; /* 4 or 6 */
    uint8_t protocol;   /* 6 tcp, 17 udp, 1 icmp, 58 icmpv6 */
    uint8_t tclass;     /* raw traffic class byte (DSCP << 2) */
    uint8_t ttl;
    uint32_t src[4]; /* host order, v4 uses src[0] only */
    uint32_t dst[4];
    uint16_t sport;
    uint16_t dport;
    uint32_t payload_len;
} pf_packet_info;

PF_API const char *pf_version(void);
PF_API const char *pf_strerror(int status);

/*
 * Mirage identity derivation.
 *
 *   key      = HMAC-SHA256(secret, "profast-mirage-v1" || node_id_be32)
 *   material = HMAC-SHA256(key, epoch_be64)
 *   address  = 0xfd || material[0..14]        (ULA-shaped, 128 bit)
 *   port     = 20000 + (material[15..16] as be16) % 40000
 *
 * Peers holding `secret` compute the same locator for the same epoch; an
 * observer only ever sees a moving target.
 */
PF_API int pf_mirage_derive(const uint8_t secret[32], uint32_t node_id, uint64_t epoch,
                            uint8_t out_addr[16], uint16_t *out_port);

/*
 * Single Packet Authorization token:
 *   node_be32 || epoch_be64 || nonce[16] || HMAC-SHA256(key, label||fields)[0..15]
 * Returns the raw token and its unpadded base64url encoding.
 */
PF_API int pf_mirage_spa(const uint8_t secret[32], uint32_t node_id, uint64_t epoch,
                         const uint8_t nonce[16], uint8_t out_token[PF_MIRAGE_TOKEN_LEN],
                         char *out_b64, size_t b64_cap);

/*
 * Validates a SPA token against `now` (unix seconds). Accepts the current and
 * the previous epoch to tolerate clock skew of one epoch. Replay suppression
 * is the caller's responsibility (see pf_replay_new / pf_replay_check).
 */
PF_API int pf_mirage_verify(const uint8_t secret[32], const uint8_t *token, size_t len,
                            uint64_t now, uint32_t epoch_s, uint32_t *out_node,
                            uint64_t *out_epoch);

PF_API int pf_mirage_verify_b64(const uint8_t secret[32], const char *token_b64, size_t len,
                                uint64_t now, uint32_t epoch_s, uint32_t *out_node,
                                uint64_t *out_epoch);

/* Replay cache: fixed capacity ring of recently accepted (node, nonce) pairs. */
typedef struct pf_replay pf_replay;
PF_API pf_replay *pf_replay_new(size_t capacity);
PF_API void pf_replay_free(pf_replay *r);
/* Returns PF_OK when fresh (and records it), PF_EREPLAY when already seen. */
PF_API int pf_replay_check(pf_replay *r, uint32_t node_id, const uint8_t nonce[16]);

/* Packet inspection and classification. */
PF_API int pf_parse_packet(const uint8_t *buf, size_t len, pf_packet_info *out);
PF_API uint64_t pf_flow_hash(const pf_packet_info *info);
/* 0 = best effort, 1 = focused (expedited forwarding), 2 = background */
PF_API uint8_t pf_recommend_dscp(const pf_packet_info *info, uint8_t traffic_class);

/* Process control. `level` is relative: -2 idle .. +2 high. */
PF_API int pf_set_process_priority(uint32_t pid, int level);
/* Windows: clears EcoQoS / power throttling for the process. No-op elsewhere. */
PF_API int pf_disable_power_throttling(uint32_t pid, int disable);

/* DSCP marking on an existing socket handle. ENOTSUP on Windows (use QoS policy). */
PF_API int pf_set_socket_dscp(intptr_t sock, uint8_t dscp, int ipv6);

/* Token bucket used by the user-space shaper. Times are monotonic seconds. */
typedef struct pf_bucket pf_bucket;
PF_API pf_bucket *pf_bucket_new(double rate_bytes_per_s, double burst_bytes);
PF_API void pf_bucket_free(pf_bucket *b);
/* PF_OK = pass now, PF_EBUSY = should be delayed, out_wait_ms holds the delay. */
PF_API int pf_bucket_consume(pf_bucket *b, uint64_t bytes, double now_s, uint64_t *out_wait_ms);

/* Flow table: open addressing, oldest-slowest eviction, used for focus mode. */
typedef struct pf_flowtable pf_flowtable;
PF_API pf_flowtable *pf_flowtable_new(size_t capacity);
PF_API void pf_flowtable_free(pf_flowtable *t);
PF_API int pf_flowtable_touch(pf_flowtable *t, const pf_packet_info *info, uint64_t bytes,
                              uint64_t *out_packets);
PF_API size_t pf_flowtable_size(const pf_flowtable *t);

#ifdef __cplusplus
}
#endif

#endif /* PROFAST_NATIVE_H */
