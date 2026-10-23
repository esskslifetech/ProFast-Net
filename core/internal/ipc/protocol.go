// Package ipc defines the JSON-RPC 2.0 contract spoken by every client.
package ipc

import (
	"encoding/json"
	"fmt"
)

// JSON-RPC 2.0 server error codes plus ProFast specific ones.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
	// CodeConsentRequired means the operation is destructive and the caller
	// must obtain a confirmation token first.
	CodeConsentRequired = -32001
	CodeUnauthorized    = -32002
	CodeUnavailable     = -32003
	CodeElevation       = -32004
)

// Request is a single JSON-RPC call.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	Auth    string          `json:"pf_auth,omitempty"`
}

// Response is a single JSON-RPC reply.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is the wire representation of a failure.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Error implements the error interface so handlers can return it directly.
func (e *RPCError) Error() string {
	return fmt.Sprintf("%s (%d)", e.Message, e.Code)
}

// Coded builds an RPCError with a formatted message.
func Coded(code int, format string, args ...any) *RPCError {
	return &RPCError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Endpoint is the discovery file written by the daemon.
type Endpoint struct {
	Network  string `json:"network"`
	Address  string `json:"address"`
	Token    string `json:"token"`
	PID      int    `json:"pid"`
	Version  string `json:"version"`
	Protocol string `json:"protocol"`
}

// Handler processes one method call. Returning an error produces an error
// response; return a *RPCError to control the code.
type Handler func(method string, params json.RawMessage) (any, error)

// Notification is pushed by the daemon for long-running work.
type Notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}
