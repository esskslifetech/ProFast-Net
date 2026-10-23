package ipc

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/esskslifetech/profast-net/core/internal/version"
)

const maxMessage = 4 << 20 // 4 MiB is plenty for a status document.

// Server owns the local control socket. It is deliberately unreachable from
// the network: a unix socket on POSIX and a loopback socket guarded by a
// per-boot token on Windows.
type Server struct {
	handler  Handler
	ln       net.Listener
	endpoint Endpoint
	path     string
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	closing  chan struct{}
	once     sync.Once
}

// Listen binds the control socket and publishes the endpoint file.
func Listen(endpointPath string, handler Handler) (*Server, error) {
	dir := filepath.Dir(endpointPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	network := "unix"
	address := filepath.Join(dir, "daemon.sock")
	if runtime.GOOS == "windows" {
		network = "tcp"
		address = "127.0.0.1:0"
	} else {
		_ = os.Remove(address) // drop a stale socket from a killed daemon
	}

	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, fmt.Errorf("listen %s://%s: %w", network, address, err)
	}
	if network == "unix" {
		if err := os.Chmod(address, 0o600); err != nil {
			_ = ln.Close()
			return nil, err
		}
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		_ = ln.Close()
		return nil, err
	}

	s := &Server{
		handler: handler,
		ln:      ln,
		path:    endpointPath,
		conns:   make(map[net.Conn]struct{}),
		closing: make(chan struct{}),
		endpoint: Endpoint{
			Network:  network,
			Address:  ln.Addr().String(),
			Token:    hex.EncodeToString(tokenBytes),
			PID:      os.Getpid(),
			Version:  version.Version,
			Protocol: version.ProtocolVersion,
		},
	}

	if err := s.writeEndpoint(); err != nil {
		_ = ln.Close()
		return nil, err
	}

	go s.acceptLoop()
	return s, nil
}

// Endpoint returns the discovery document for logging.
func (s *Server) Endpoint() Endpoint { return s.endpoint }

func (s *Server) writeEndpoint() error {
	raw, err := json.MarshalIndent(s.endpoint, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.closing:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}

		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()

		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64<<10), maxMessage)
	enc := json.NewEncoder(conn)

	if !scanner.Scan() {
		return
	}

	var hello Request
	if err := json.Unmarshal(scanner.Bytes(), &hello); err != nil {
		_ = enc.Encode(Response{JSONRPC: "2.0", Error: Coded(CodeParseError, "malformed handshake")})
		return
	}
	if subtle.ConstantTimeCompare([]byte(hello.Auth), []byte(s.endpoint.Token)) != 1 {
		_ = enc.Encode(Response{
			JSONRPC: "2.0",
			ID:      hello.ID,
			Error:   Coded(CodeUnauthorized, "invalid control token"),
		})
		return
	}
	_ = enc.Encode(Response{
		JSONRPC: "2.0",
		ID:      hello.ID,
		Result: map[string]any{
			"ok":       true,
			"version":  version.Version,
			"protocol": version.ProtocolVersion,
		},
	})

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(Response{JSONRPC: "2.0", Error: Coded(CodeParseError, "malformed JSON")})
			continue
		}

		resp := Response{JSONRPC: "2.0", ID: req.ID}
		result, err := s.call(req)
		if err != nil {
			var rpcErr *RPCError
			if errors.As(err, &rpcErr) {
				resp.Error = rpcErr
			} else {
				resp.Error = Coded(CodeInternal, "%s", err.Error())
			}
		} else {
			resp.Result = result
		}

		if len(req.ID) == 0 {
			continue // notification: no reply expected
		}
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

func (s *Server) call(req Request) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = Coded(CodeInternal, "handler panic: %v", r)
		}
	}()

	if req.Method == "" {
		return nil, Coded(CodeInvalidRequest, "missing method")
	}
	return s.handler(req.Method, req.Params)
}

// Close tears down the socket and removes the discovery file.
func (s *Server) Close() error {
	var err error
	s.once.Do(func() {
		close(s.closing)
		err = s.ln.Close()

		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.conns = map[net.Conn]struct{}{}
		s.mu.Unlock()

		_ = os.Remove(s.path)
		if s.endpoint.Network == "unix" {
			_ = os.Remove(s.endpoint.Address)
		}
	})
	return err
}
