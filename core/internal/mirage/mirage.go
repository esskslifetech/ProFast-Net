// Package mirage implements the rotating virtual identity.
//
// A node never exposes a stable address. Instead every peer derives the same
// locator from a shared secret and the current time epoch, and only proves
// knowledge of that secret through a Single Packet Authorization token. An
// observer sees a locator that changes every epoch and a port that hops with
// it; without the secret there is nothing to scan and nothing to connect to.
package mirage

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// Label domain-separates the locator derivation.
	Label = "profast-mirage-v1"
	// SPALabel domain-separates the authorization token.
	SPALabel = "profast-spa-v1"
	// TokenLen is fixed: 4 node + 8 epoch + 16 nonce + 16 MAC.
	TokenLen = 44
	// PortBase and PortSpan bound the derived listening port.
	PortBase = 20000
	PortSpan = 40000
)

var (
	// ErrAuth means the token MAC did not verify.
	ErrAuth = errors.New("mirage: authentication failed")
	// ErrClock means the token epoch is outside the accepted window.
	ErrClock = errors.New("mirage: epoch outside accepted window")
	// ErrToken means the token is structurally invalid.
	ErrToken = errors.New("mirage: malformed token")
)

// Epoch returns the current time slice.
func Epoch(now time.Time, seconds int) uint64 {
	if seconds <= 0 {
		seconds = 10
	}
	return uint64(now.Unix()) / uint64(seconds)
}

// UntilBoundary reports how long the current epoch still lasts.
func UntilBoundary(now time.Time, seconds int) time.Duration {
	if seconds <= 0 {
		seconds = 10
	}
	next := (now.Unix()/int64(seconds) + 1) * int64(seconds)
	return time.Duration(next-now.Unix()) * time.Second
}

// deriveKey binds the cluster secret to one node.
func deriveKey(secret []byte, nodeID uint32) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(Label))
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], nodeID)
	mac.Write(id[:])
	return mac.Sum(nil)
}

// Derive returns the locator (ULA-shaped address and port) for an epoch.
func Derive(secret []byte, nodeID uint32, epoch uint64) (net.IP, uint16, error) {
	if len(secret) < 32 {
		return nil, 0, fmt.Errorf("mirage: secret must be 32 bytes, got %d", len(secret))
	}

	key := deriveKey(secret, nodeID)
	mac := hmac.New(sha256.New, key)
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], epoch)
	mac.Write(epochBytes[:])
	material := mac.Sum(nil)

	addr := make(net.IP, 16)
	addr[0] = 0xfd // fd00::/8 unique local address space
	copy(addr[1:], material[:15])

	raw := binary.BigEndian.Uint16(material[15:17])
	port := uint16(PortBase + int(raw)%PortSpan)

	return addr, port, nil
}

// Format renders an address as eight zero-padded groups.
//
// net.IP.String() drops leading zeros inside a group (…:7166:e99), while the
// C++ core and the Python control plane keep them (…:7166:0e99). Since a peer
// may pin or compare the textual locator, every implementation emits the padded
// form; the derived bytes are the same either way.
func Format(ip net.IP) string {
	if len(ip) != net.IPv6len {
		return ip.String()
	}

	var b strings.Builder
	b.Grow(39)
	for i := 0; i < net.IPv6len; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02x%02x", ip[i], ip[i+1])
	}
	return b.String()
}

// Mint builds a single packet authorization token and its wire form.
func Mint(secret []byte, nodeID uint32, epoch uint64, nonce []byte) ([]byte, string, error) {
	if len(nonce) != 16 {
		return nil, "", fmt.Errorf("mirage: nonce must be 16 bytes, got %d", len(nonce))
	}
	if len(secret) < 32 {
		return nil, "", fmt.Errorf("mirage: secret must be 32 bytes, got %d", len(secret))
	}

	token := make([]byte, TokenLen)
	binary.BigEndian.PutUint32(token[0:4], nodeID)
	binary.BigEndian.PutUint64(token[4:12], epoch)
	copy(token[12:28], nonce)

	mac := hmac.New(sha256.New, deriveKey(secret, nodeID))
	mac.Write([]byte(SPALabel))
	mac.Write(token[0:28])
	copy(token[28:44], mac.Sum(nil)[:16])

	return token, base64.RawURLEncoding.EncodeToString(token), nil
}

// MintFor is a convenience wrapper that generates a random nonce.
func MintFor(secret []byte, nodeID uint32, epoch uint64) ([]byte, string, []byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", nil, err
	}
	token, encoded, err := Mint(secret, nodeID, epoch, nonce)
	return token, encoded, nonce, err
}

// Verify checks a raw token against the current clock. It accepts one epoch of
// skew in each direction so that peers with slightly different clocks still
// connect, while replay suppression remains the caller's job.
func Verify(secret, token []byte, now time.Time, epochSeconds int) (uint32, uint64, error) {
	if len(token) != TokenLen {
		return 0, 0, ErrToken
	}
	if epochSeconds <= 0 {
		epochSeconds = 10
	}

	nodeID := binary.BigEndian.Uint32(token[0:4])
	epoch := binary.BigEndian.Uint64(token[4:12])
	nonce := token[12:28]

	mac := hmac.New(sha256.New, deriveKey(secret, nodeID))
	mac.Write([]byte(SPALabel))
	mac.Write(token[0:28])
	expected := mac.Sum(nil)[:16]

	if subtle.ConstantTimeCompare(expected, token[28:44]) != 1 {
		return 0, 0, ErrAuth
	}

	current := Epoch(now, epochSeconds)
	if epoch+1 < current || epoch > current+1 {
		return 0, 0, ErrClock
	}
	_ = nonce
	return nodeID, epoch, nil
}

// VerifyB64 is Verify for the text form carried in UDP SPA datagrams.
func VerifyB64(secret []byte, encoded string, now time.Time, epochSeconds int) (uint32, uint64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return 0, 0, ErrToken
	}
	return Verify(secret, raw, now, epochSeconds)
}

// Replay is a fixed-size cache of accepted nonces. Mirage tokens are single
// use; a captured SPA packet must never open a second connection.
type Replay struct {
	mu       sync.Mutex
	capacity int
	order    [][20]byte
	seen     map[[20]byte]struct{}
}

// NewReplay builds a replay cache with the given capacity.
func NewReplay(capacity int) *Replay {
	if capacity < 16 {
		capacity = 16
	}
	return &Replay{
		capacity: capacity,
		order:    make([][20]byte, 0, capacity),
		seen:     make(map[[20]byte]struct{}, capacity),
	}
}

// Check records the token and reports whether it had already been seen.
func (r *Replay) Check(token []byte) bool {
	if len(token) < 28 {
		return true
	}
	var key [20]byte
	copy(key[0:4], token[0:4])
	copy(key[4:20], token[12:28])

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.seen[key]; ok {
		return true
	}

	if len(r.order) >= r.capacity {
		evict := r.order[0]
		r.order = r.order[1:]
		delete(r.seen, evict)
	}
	r.order = append(r.order, key)
	r.seen[key] = struct{}{}
	return false
}

// Size reports the number of cached nonces.
func (r *Replay) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}
