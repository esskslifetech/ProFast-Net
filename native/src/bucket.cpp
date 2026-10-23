#include "profast/native.h"

#include <cmath>
#include <cstring>
#include <new>
#include <vector>

struct pf_bucket {
    double rate;  /* bytes per second */
    double burst; /* maximum credit */
    double credit;
    double last;
    bool primed;
};

extern "C" {

pf_bucket *pf_bucket_new(double rate_bytes_per_s, double burst_bytes) {
    if (!(rate_bytes_per_s > 0.0) || !(burst_bytes > 0.0)) {
        return nullptr;
    }
    pf_bucket *b = new (std::nothrow) pf_bucket();
    if (!b) {
        return nullptr;
    }
    b->rate = rate_bytes_per_s;
    b->burst = burst_bytes;
    b->credit = burst_bytes;
    b->last = 0.0;
    b->primed = false;
    return b;
}

void pf_bucket_free(pf_bucket *b) { delete b; }

int pf_bucket_consume(pf_bucket *b, uint64_t bytes, double now_s, uint64_t *out_wait_ms) {
    if (!b) {
        return PF_EINVAL;
    }

    if (!b->primed) {
        b->last = now_s;
        b->primed = true;
    }

    const double elapsed = now_s > b->last ? now_s - b->last : 0.0;
    b->last = now_s;
    b->credit = std::fmin(b->burst, b->credit + elapsed * b->rate);

    if (b->credit >= static_cast<double>(bytes)) {
        b->credit -= static_cast<double>(bytes);
        if (out_wait_ms) *out_wait_ms = 0;
        return PF_OK;
    }

    const double deficit = static_cast<double>(bytes) - b->credit;
    if (out_wait_ms) {
        *out_wait_ms = static_cast<uint64_t>(std::ceil(deficit / b->rate * 1000.0));
    }
    return PF_EBUSY;
}

/* ------------------------------------------------------------ flowtable -- */

struct flow_entry {
    uint64_t hash;
    uint64_t bytes;
    uint64_t packets;
    double last_seen;
    bool used;
};

struct pf_flowtable {
    size_t capacity;
    size_t used;
    std::vector<flow_entry> slots;
};

pf_flowtable *pf_flowtable_new(size_t capacity) {
    size_t cap = 1024;
    while (cap < capacity) {
        cap <<= 1;
    }
    pf_flowtable *t = new (std::nothrow) pf_flowtable();
    if (!t) {
        return nullptr;
    }
    t->capacity = cap;
    t->used = 0;
    t->slots.assign(cap, flow_entry{0, 0, 0, 0.0, false});
    return t;
}

void pf_flowtable_free(pf_flowtable *t) { delete t; }

size_t pf_flowtable_size(const pf_flowtable *t) { return t ? t->used : 0; }

namespace {

/* Evict the least-transferred entry to keep the table bounded under floods. */
void evict_lightest(pf_flowtable *t) {
    size_t victim = 0;
    uint64_t lowest = UINT64_MAX;
    for (size_t i = 0; i < t->capacity; ++i) {
        if (t->slots[i].used && t->slots[i].bytes < lowest) {
            lowest = t->slots[i].bytes;
            victim = i;
        }
    }
    t->slots[victim] = flow_entry{0, 0, 0, 0.0, false};
    if (t->used > 0) {
        --t->used;
    }
}

} // namespace

int pf_flowtable_touch(pf_flowtable *t, const pf_packet_info *info, uint64_t bytes,
                       uint64_t *out_packets) {
    if (!t || !info) {
        return PF_EINVAL;
    }
    const uint64_t hash = pf_flow_hash(info);
    const size_t mask = t->capacity - 1;
    size_t idx = static_cast<size_t>(hash) & mask;
    const double now = static_cast<double>(info->ttl); /* caller-supplied monotonic stamp */

    for (size_t probe = 0; probe < t->capacity; ++probe) {
        flow_entry &e = t->slots[idx];
        if (!e.used) {
            if (t->used * 4 >= t->capacity * 3) {
                evict_lightest(t);
                idx = static_cast<size_t>(hash) & mask;
                while (t->slots[idx].used) {
                    idx = (idx + 1) & mask;
                }
            }
            e.hash = hash;
            e.bytes = bytes;
            e.packets = 1;
            e.last_seen = now;
            e.used = true;
            ++t->used;
            if (out_packets) *out_packets = 1;
            return PF_OK;
        }
        if (e.hash == hash) {
            e.bytes += bytes;
            ++e.packets;
            e.last_seen = now;
            if (out_packets) *out_packets = e.packets;
            return PF_OK;
        }
        idx = (idx + 1) & mask;
    }

    return PF_EBUSY;
}

} // extern "C"
