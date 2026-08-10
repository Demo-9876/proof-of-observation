package helper

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Demo-9876/proof-of-observation/aliyun-enclave/internal/proof"
)

const ioDeadline = 30 * time.Second

type Server struct {
	socketPath string
	attester   proof.Attester
	privateKey ed25519.PrivateKey
	mu         sync.Mutex
}

func NewServer(socketPath string, attester proof.Attester) (*Server, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	if attester == nil {
		return nil, errors.New("attester is required")
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &Server{
		socketPath: socketPath,
		attester:   attester,
		privateKey: privateKey,
	}, nil
}

func (s *Server) Serve() error {
	ln, err := listenUnixSocket(s.socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(s.socketPath)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func listenUnixSocket(socketPath string) (net.Listener, error) {
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen unix socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("chmod unix socket: %w", err)
	}
	return ln, nil
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioDeadline))

	payload, err := ReadFrame(conn, MaxRequestPayload)
	if err != nil {
		_ = writeResponse(conn, failure("bad_request", err.Error()))
		return
	}
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		_ = writeResponse(conn, failure("bad_request", "request JSON: "+err.Error()))
		return
	}
	resp := s.HandleRequest(req)
	_ = writeResponse(conn, resp)
}

func (s *Server) HandleRequest(req Request) Response {
	if req.Version != Version {
		return failure("bad_request", fmt.Sprintf("unsupported protocol version: %d", req.Version))
	}
	if req.Op == "health" {
		return Response{Version: Version, OK: true}
	}
	if req.Op != "" && req.Op != "proof" {
		return failure("bad_request", "unsupported op: "+req.Op)
	}
	if req.HTTPStatus <= 0 {
		return failure("bad_request", "http_status must be positive")
	}
	if err := proof.ValidateRequiredFields(proof.GenerateHashedInput{
		NonceB64:            req.NonceB64,
		UpstreamHost:        req.UpstreamHost,
		UpstreamPath:        req.UpstreamPath,
		HTTPMethod:          req.HTTPMethod,
		ResponseContentType: req.ResponseContentType,
	}); err != nil {
		return failure("bad_request", err.Error())
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := proof.GenerateFromHashes(proof.GenerateHashedInput{
		NonceB64:              req.NonceB64,
		UpstreamHost:          req.UpstreamHost,
		UpstreamPath:          req.UpstreamPath,
		HTTPMethod:            req.HTTPMethod,
		HTTPStatus:            req.HTTPStatus,
		ResponseContentType:   req.ResponseContentType,
		RequestBodySHA256Hex:  req.RequestSHA256Hex,
		ResponseBodySHA256Hex: req.ResponseSHA256Hex,
		FieldClaims:           req.FieldClaims,
	}, proof.GenerateOptions{
		PrivateKey: s.privateKey,
		Attester:   s.attester,
	})
	if err != nil {
		return classifyError(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return failure("proof_generation_failed", "marshal proof: "+err.Error())
	}
	return Response{Version: Version, OK: true, Proof: raw}
}

func writeResponse(conn net.Conn, resp Response) error {
	if resp.Version == 0 {
		resp.Version = Version
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return WriteFrame(conn, payload, MaxResponsePayload)
}

func failure(code string, message string) Response {
	return Response{
		Version: Version,
		OK:      false,
		Error: &Error{
			Code:    code,
			Message: message,
		},
	}
}

func classifyError(err error) Response {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "is required"):
		return failure("bad_request", msg)
	case strings.Contains(msg, "nonce must be base64"):
		return failure("invalid_nonce", msg)
	case strings.Contains(msg, "request_body_sha256") || strings.Contains(msg, "response_body_sha256"):
		return failure("invalid_hash", msg)
	case strings.Contains(msg, "field_claims"):
		return failure("bad_request", msg)
	case strings.Contains(msg, "get vtpm quote"):
		return failure("vtpm_quote_failed", msg)
	default:
		return failure("proof_generation_failed", msg)
	}
}
