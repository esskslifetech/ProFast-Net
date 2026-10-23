package mirage

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"
)

// These constants are the canonical vector. The same bytes are asserted by the
// C++ core (pfbench selftest) and the Python control plane (test_mirage.py), so
// a failure here means one of the three implementations drifted.
const (
	canonicalSecret = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	canonicalNonce  = "000102030405060708090a0b0c0d0e0f"
	canonicalRaw    = "0000000100000000000003e8000102030405060708090a0b0c0d0e0ffc4a3155a40ccbd92b5de7989b26d581"
	canonicalToken  = "AAAAAQAAAAAAAAPoAAECAwQFBgcICQoLDA0OD_xKMVWkDMvZK13nmJsm1YE"
	canonicalAddr   = "fd41:ae7d:9004:782d:a2d2:c2ca:7166:0e99"
	canonicalPort   = uint16(35239)
	canonicalNode   = uint32(1)
	canonicalEpoch  = uint64(1000)
	epochSeconds    = 10
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}
	return raw
}

// epochTime maps an epoch back onto the wall clock that produced it.
func epochTime(epoch uint64) time.Time {
	return time.Unix(int64(epoch)*epochSeconds, 0)
}

func TestDeriveMatchesCanonicalVector(t *testing.T) {
	addr, port, err := Derive(mustHex(t, canonicalSecret), canonicalNode, canonicalEpoch)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if got := Format(addr); got != canonicalAddr {
		t.Errorf("formatted address = %s, want %s", got, canonicalAddr)
	}
	if want := net.ParseIP(canonicalAddr); want == nil || !addr.Equal(want) {
		t.Errorf("address bytes = %v, want %v", []byte(addr), []byte(want))
	}
	if port != canonicalPort {
		t.Errorf("port = %d, want %d", port, canonicalPort)
	}
}

// TestFormatKeepsLeadingZeros covers the one place where net.IP.String() and
// the other two implementations disagree: a group whose high byte is zero.
func TestFormatKeepsLeadingZeros(t *testing.T) {
	ip := net.ParseIP("fd41:0:0:0:0:0:0:e99").To16()
	if got := Format(ip); got != "fd41:0000:0000:0000:0000:0000:0000:0e99" {
		t.Errorf("format = %s, want zero-padded groups", got)
	}
	short := net.IP{127, 0, 0, 1}
	if got := Format(short); got != "127.0.0.1" {
		t.Errorf("format of a short address = %s, want the stdlib form", got)
	}
}

func TestDeriveRejectsShortSecret(t *testing.T) {
	if _, _, err := Derive(make([]byte, 16), canonicalNode, canonicalEpoch); err == nil {
		t.Fatal("a 16-byte secret must not be accepted")
	}
}

func TestEpochBoundaries(t *testing.T) {
	if got := Epoch(epochTime(canonicalEpoch), epochSeconds); got != canonicalEpoch {
		t.Errorf("epoch = %d, want %d", got, canonicalEpoch)
	}
	if got := Epoch(time.Unix(10005, 0), epochSeconds); got != canonicalEpoch {
		t.Errorf("epoch at the middle of a slice = %d, want %d", got, canonicalEpoch)
	}
	// A non-positive period must fall back to the documented default.
	if got := Epoch(time.Unix(10005, 0), 0); got != canonicalEpoch {
		t.Errorf("default period epoch = %d, want %d", got, canonicalEpoch)
	}
	if got := UntilBoundary(time.Unix(10005, 0), epochSeconds); got != 5*time.Second {
		t.Errorf("until boundary = %v, want 5s", got)
	}
}

func TestMintMatchesCanonicalVector(t *testing.T) {
	raw, encoded, err := Mint(mustHex(t, canonicalSecret), canonicalNode, canonicalEpoch, mustHex(t, canonicalNonce))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if encoded != canonicalToken {
		t.Errorf("token = %s, want %s", encoded, canonicalToken)
	}
	if got := hex.EncodeToString(raw); got != canonicalRaw {
		t.Errorf("raw = %s, want %s", got, canonicalRaw)
	}
	if len(encoded) != 59 {
		t.Errorf("text length = %d, want 59 (44 bytes, unpadded base64url)", len(encoded))
	}
}

func TestMintRejectsBadInputs(t *testing.T) {
	secret := mustHex(t, canonicalSecret)
	if _, _, err := Mint(secret, canonicalNode, canonicalEpoch, make([]byte, 15)); err == nil {
		t.Error("a 15-byte nonce must not be accepted")
	}
	if _, _, err := Mint(make([]byte, 16), canonicalNode, canonicalEpoch, make([]byte, 16)); err == nil {
		t.Error("a 16-byte secret must not be accepted")
	}
}

func TestVerifyAcceptsCanonicalToken(t *testing.T) {
	node, epoch, err := Verify(mustHex(t, canonicalSecret), mustHex(t, canonicalRaw), epochTime(canonicalEpoch), epochSeconds)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if node != canonicalNode || epoch != canonicalEpoch {
		t.Errorf("token claims node %d epoch %d, want %d/%d", node, epoch, canonicalNode, canonicalEpoch)
	}
}

func TestVerifyB64AcceptsTextForm(t *testing.T) {
	node, epoch, err := VerifyB64(mustHex(t, canonicalSecret), canonicalToken, epochTime(canonicalEpoch), epochSeconds)
	if err != nil {
		t.Fatalf("verify b64: %v", err)
	}
	if node != canonicalNode || epoch != canonicalEpoch {
		t.Errorf("token claims node %d epoch %d, want %d/%d", node, epoch, canonicalNode, canonicalEpoch)
	}
}

func TestVerifyRejectsTamperedToken(t *testing.T) {
	raw := mustHex(t, canonicalRaw)
	raw[12] ^= 0xff // flip the first nonce byte; the MAC no longer covers it
	if _, _, err := Verify(mustHex(t, canonicalSecret), raw, epochTime(canonicalEpoch), epochSeconds); !errors.Is(err, ErrAuth) {
		t.Errorf("tampered token: err = %v, want ErrAuth", err)
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	raw := mustHex(t, canonicalRaw)
	if _, _, err := Verify(make([]byte, 32), raw, epochTime(canonicalEpoch), epochSeconds); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong secret: err = %v, want ErrAuth", err)
	}
}

func TestVerifyAcceptsOneEpochOfSkew(t *testing.T) {
	raw := mustHex(t, canonicalRaw)
	secret := mustHex(t, canonicalSecret)
	base := epochTime(canonicalEpoch)
	for _, delta := range []int64{-1, 1} {
		now := base.Add(time.Duration(delta) * epochSeconds * time.Second)
		if _, _, err := Verify(secret, raw, now, epochSeconds); err != nil {
			t.Errorf("skew %+d epoch: err = %v, want nil", delta, err)
		}
	}
}

func TestVerifyRejectsStaleToken(t *testing.T) {
	raw := mustHex(t, canonicalRaw)
	stale := epochTime(canonicalEpoch + 2)
	if _, _, err := Verify(mustHex(t, canonicalSecret), raw, stale, epochSeconds); !errors.Is(err, ErrClock) {
		t.Errorf("stale token: err = %v, want ErrClock", err)
	}
	future := epochTime(canonicalEpoch - 2)
	if _, _, err := Verify(mustHex(t, canonicalSecret), raw, future, epochSeconds); !errors.Is(err, ErrClock) {
		t.Errorf("future token: err = %v, want ErrClock", err)
	}
}

func TestVerifyRejectsMalformedToken(t *testing.T) {
	if _, _, err := Verify(mustHex(t, canonicalSecret), []byte{1, 2, 3}, epochTime(canonicalEpoch), epochSeconds); !errors.Is(err, ErrToken) {
		t.Errorf("short token: err = %v, want ErrToken", err)
	}
	if _, _, err := VerifyB64(mustHex(t, canonicalSecret), "not base64!!", epochTime(canonicalEpoch), epochSeconds); !errors.Is(err, ErrToken) {
		t.Errorf("bad base64: err = %v, want ErrToken", err)
	}
}

// pseudoToken builds a structurally valid token whose nonce varies with seed.
func pseudoToken(seed byte) []byte {
	token := make([]byte, TokenLen)
	binary.BigEndian.PutUint32(token[0:4], canonicalNode)
	binary.BigEndian.PutUint64(token[4:12], canonicalEpoch)
	token[12] = seed
	return token
}

func TestReplayRejectsSecondUse(t *testing.T) {
	replay := NewReplay(64)
	raw := mustHex(t, canonicalRaw)
	if replay.Check(raw) {
		t.Fatal("first use must be accepted")
	}
	if !replay.Check(raw) {
		t.Fatal("second use must be rejected")
	}
	if replay.Size() != 1 {
		t.Errorf("cache size = %d, want 1", replay.Size())
	}
}

func TestReplayIsBounded(t *testing.T) {
	replay := NewReplay(16)
	first := pseudoToken(0)
	if replay.Check(first) {
		t.Fatal("first token must be accepted")
	}
	for i := 1; i < 32; i++ {
		if replay.Check(pseudoToken(byte(i))) {
			t.Fatalf("token %d must be new", i)
		}
	}
	if replay.Size() != 16 {
		t.Errorf("cache size = %d, want the 16-entry bound", replay.Size())
	}
	if replay.Check(first) {
		t.Error("the oldest entry must have been evicted, so the first token is new again")
	}
}
