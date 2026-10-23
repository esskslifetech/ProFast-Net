# Protocol

Everything in this file is implemented three times — `native/src/mirage.cpp`,
`core/internal/mirage/mirage.go` and `python/src/profast/mirage.py` — and pinned
by the same known-answer vectors. Change one, change all three, and update the
vector table.

## 1. Rotating locator

```
key      = HMAC-SHA256(secret, "profast-mirage-v1" || node_id_be32)
material = HMAC-SHA256(key, epoch_be64)

address  = 0xfd || material[0..14]                    # ULA-shaped, 128 bits
port     = 20000 + be16(material[15..16]) % 40000     # [20000, 59999]
```

- `secret` is 32 bytes, shared by the nodes of a cluster.
- `node_id` is a big-endian `uint32` derived from the host name by default.
- `epoch = floor(unix_seconds / epoch_seconds)`, `epoch_seconds` defaults to 10
  and is clamped to [2, 300].

Consequences worth stating out loud:

- The address lives in `fd00::/8`. It is **not** assigned to an interface and is
  not routable on the public Internet; it is a locator that peers agree on, which
  is why "nearby users can still connect" — they can compute it.
- Every node in a cluster derives every other node's locator from the same
  secret. There is no per-pair negotiation and no round trip before the first
  packet.
- An observer without the secret sees a 128-bit value that changes every epoch.
  Because the input includes a 64-bit epoch, values never repeat in practice;
  there is no small cycle to wait out.

## 2. Single packet authorization (SPA)

A peer proves cluster membership with one UDP datagram. No SYN, no handshake, no
response on failure — an unauthorized sender learns nothing.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | `node_id` (big endian) |
| 4 | 8 | `epoch` (big endian) |
| 12 | 16 | `nonce` (random, unique per token) |
| 28 | 16 | `HMAC-SHA256(key, "profast-spa-v1" || body)[0..16]` |

Total 44 bytes, transported as **unpadded base64url** (59 characters).

Verification:

1. Decode base64url; reject anything that is not exactly 44 bytes.
2. Recompute the MAC over the first 28 bytes; compare in constant time.
3. Accept `epoch` in `[current - 1, current + 1]`.
4. Reject if `(node_id, nonce)` is already in the replay cache.

The replay cache is bounded (4096 entries by default) and evicts in FIFO order,
so memory is bounded under flood. A token is therefore single-use within the
cache window; because the epoch window is three epochs wide, an attacker who
captures a token has at most one epoch to replay it and will be rejected if the
legitimate peer's token arrived first.

## 3. Control channel

`profastd` publishes an endpoint file next to the runtime state:

- POSIX: `$TMPDIR/profast-$USER/endpoint.json`, socket `daemon.sock`, mode 0600.
- Windows: `%LOCALAPPDATA%\ProFast-Net\endpoint.json`, loopback TCP on an
  ephemeral port (named pipes are a later optimisation).

```json
{
  "network": "unix",
  "address": "/tmp/profast-alice/daemon.sock",
  "token": "64 hex characters",
  "pid": 12345,
  "version": "0.1.0",
  "protocol": "1.0"
}
```

The first line a client sends must be:

```json
{"jsonrpc":"2.0","id":0,"method":"auth","pf_auth":"<token>"}
```

The token is compared with `hmac.compare_digest` / `subtle.ConstantTimeCompare`.
Wrong token: the server replies with error `-32002` and closes. Every subsequent
line is newline-delimited JSON-RPC 2.0.

## 4. Method surface

| Method | Params | Result |
| --- | --- | --- |
| `core.ping` | – | `{ok, version, protocol}` |
| `core.status` | – | version, platform, uptime, mirage, focus, defense, firewall, scan |
| `core.capabilities` | – | native bridge, backend, features |
| `core.config` | – | effective configuration |
| `core.events` | `limit` | newest-first event list |
| `mirage.status` | – | the `mirage` section of `core.status` |
| `mirage.rotate` | – | recompute locator for the current epoch |
| `mirage.peers` | – | authorized peers |
| `mirage.spa` | `node_id`, `nonce_hex` | token + locator for that node |
| `mirage.accept` | `token`, `source` | accepted peer, or error `-32003` |
| `focus.start` | `target`, `pid`, `duration_s` | session |
| `focus.stop` | – | closed session |
| `focus.status` | – | session or `null` |
| `scan.services` | `min_risk`, `limit`, `refresh` | scored services |
| `scan.risky` | – | services at or above risk 55 |
| `consent.request` | `action`, `summary`, `targets` | grant with 90 s TTL |
| `consent.pending` | – | unredeemed grants |
| `consent.revoke` | `token` | `{revoked: true}` |
| `services.terminate` | `pids`, `token`, `force` | `{ok, terminated, failed}` |
| `firewall.plan` | `block_inbound`, `allow_lan`, `allow_ports` | rules + preview |
| `firewall.apply` | same, `dry_run` | applied/skipped/errors |
| `firewall.reset` | – | removed rules |
| `firewall.status` | – | rules the OS reports for `ProFast/*` |
| `defense.status` | – | counters |
| `defense.bans` | – | active bans |
| `defense.ban` | `ip`, `reason` | ban |
| `defense.unban` | `ip` | `{unbanned: bool}` |
| `defense.observe` | `source`, `port` | allow / tarpit / drop decision |

Error codes: standard JSON-RPC (`-32700`, `-32600`, `-32601`, `-32602`, `-32603`)
plus `-32001` consent required, `-32002` unauthorized, `-32003` unavailable,
`-32004` elevation required.

## 5. Consent grants

```
token      = 16 random bytes, hex (32 chars)
fingerprint= SHA-256("\x00".join(sorted(lowercased targets)))
```

A grant is valid when: the token exists, `now <= expires`, `action` matches, and
the fingerprint of the submitted target set matches. Redeeming removes the token
whether or not the action succeeds, so a failed attempt needs a fresh "yes".

`services.terminate` builds its target list as `sorted("pid:<n>")` from the pid
set it is about to signal. This is why the CLI and GUI must request the token
*after* the user confirms and with the *exact* pid set they are about to send.

## 6. Test vectors

Secret `000102…1f`, node id `1`, epoch `1000`:

```
address  fd41:ae7d:9004:782d:a2d2:c2ca:7166:0e99
port     35239
```

Nonce `000102030405060708090a0b0c0d0e0f`, same node and epoch:

```
token    AAAAAQAAAAAAAAPoAAECAwQFBgcICQoLDA0OD_xKMVWkDMvZK13nmJsm1YE
raw hex  0000000100000000000003e8000102030405060708090a0b0c0d0e0f
         fc4a3155a40ccbd92b5de7989b26d581
```

Reproduce with any implementation:

```bash
./build/native/bin/pfbench selftest
./build/native/bin/pfbench derive <secret-hex> 1 1000
./build/native/bin/pfbench spa <secret-hex> 1 1000 000102030405060708090a0b0c0d0e0f
python -m pytest python/tests/test_mirage.py -q
```

## 7. Versioning

`protocol` in the endpoint file is the IPC contract version. Breaking changes
bump the minor version (currently `1.0`) and both daemons and clients must reject
a mismatch loudly. The crypto labels (`profast-mirage-v1`, `profast-spa-v1`) are
immutable: a change means a new label, not a new value under the old one.
