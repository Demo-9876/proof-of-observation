package helper

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Demo-9876/proof-of-observation/aliyun-enclave/internal/proof"
)

type fakeAttester struct {
	err error
}

func (f fakeAttester) GetQuote(qualifyingData []byte) (proof.QuoteReport, proof.AttesterMetadata, error) {
	if f.err != nil {
		return proof.QuoteReport{}, proof.AttesterMetadata{}, f.err
	}
	return proof.QuoteReport{
			Quoted:          []byte("quoted"),
			Signature:       []byte("sig"),
			Cert:            []byte("cert"),
			PCRValues:       []byte("values"),
			PCRSelectionOut: []byte("selection"),
		}, proof.AttesterMetadata{
			SDK:         "test",
			SDKCommit:   "test",
			QuoteHandle: "test",
		}, nil
}

func TestReadWriteFrameRejectsOversize(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("abcdef"), 6); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(&buf, 5); err == nil {
		t.Fatalf("expected oversize read to fail")
	}
}

func TestListenUnixSocketSets0600(t *testing.T) {
	socketPath := t.TempDir() + "/helper.sock"
	ln, err := listenUnixSocket(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("socket perms = %v, want %v", got, want)
	}
}

func TestHandleHealth(t *testing.T) {
	s := newTestServer(t, fakeAttester{})
	resp := s.HandleRequest(Request{Version: Version, Op: "health"})
	if !resp.OK || len(resp.Proof) != 0 {
		t.Fatalf("unexpected health response: %#v", resp)
	}
}

func TestHandleProof(t *testing.T) {
	s := newTestServer(t, fakeAttester{})
	resp := s.HandleRequest(Request{
		Version:             Version,
		NonceB64:            base64.StdEncoding.EncodeToString([]byte("nonce")),
		UpstreamHost:        "API.Example.Com",
		UpstreamPath:        "/v1/messages?ignored=true",
		HTTPMethod:          "post",
		HTTPStatus:          200,
		ResponseContentType: "text/event-stream",
		RequestSHA256Hex:    proof.SHA256Hex([]byte("request")),
		ResponseSHA256Hex:   proof.SHA256Hex([]byte("response")),
	})
	if !resp.OK {
		t.Fatalf("proof failed: %#v", resp.Error)
	}
	var p proof.TeeProof
	if err := json.Unmarshal(resp.Proof, &p); err != nil {
		t.Fatal(err)
	}
	if p.Profile != "aliyun-vtpm" || p.UpstreamHost != "API.Example.Com" {
		t.Fatalf("unexpected proof: %#v", p)
	}
	if !strings.Contains(string(proof.BuildV2Statement(proof.StatementFacts{
		NonceB64:              p.Nonce,
		UpstreamHost:          p.UpstreamHost,
		UpstreamPath:          p.UpstreamPath,
		HTTPMethod:            p.HTTPMethod,
		HTTPStatus:            p.HTTPStatus,
		ResponseContentType:   p.ResponseType,
		RequestBodySHA256Hex:  p.RequestSHA256Hex,
		ResponseBodySHA256Hex: p.ResponseSHA256Hex,
	})), "upstream-path=/v1/messages\n") {
		t.Fatalf("expected compatibility path normalization")
	}
}

func TestHandleInvalidHash(t *testing.T) {
	s := newTestServer(t, fakeAttester{})
	resp := s.HandleRequest(Request{
		Version:             Version,
		NonceB64:            base64.StdEncoding.EncodeToString([]byte("nonce")),
		UpstreamHost:        "api.example.com",
		UpstreamPath:        "/v1/messages",
		HTTPMethod:          "POST",
		HTTPStatus:          200,
		ResponseContentType: "text/event-stream",
		RequestSHA256Hex:    "nope",
		ResponseSHA256Hex:   proof.SHA256Hex([]byte("response")),
	})
	if resp.OK || resp.Error == nil || resp.Error.Code != "invalid_hash" {
		t.Fatalf("unexpected invalid hash response: %#v", resp)
	}
}

func TestHandleMissingRequiredField(t *testing.T) {
	s := newTestServer(t, fakeAttester{})
	resp := s.HandleRequest(Request{
		Version:             Version,
		NonceB64:            base64.StdEncoding.EncodeToString([]byte("nonce")),
		UpstreamHost:        "api.example.com",
		UpstreamPath:        "",
		HTTPMethod:          "POST",
		HTTPStatus:          200,
		ResponseContentType: "text/event-stream",
		RequestSHA256Hex:    proof.SHA256Hex([]byte("request")),
		ResponseSHA256Hex:   proof.SHA256Hex([]byte("response")),
	})
	if resp.OK || resp.Error == nil || resp.Error.Code != "bad_request" {
		t.Fatalf("unexpected missing field response: %#v", resp)
	}
	if !strings.Contains(resp.Error.Message, "upstream_path is required") {
		t.Fatalf("unexpected missing field error: %#v", resp.Error)
	}
}

func TestHandleQuoteError(t *testing.T) {
	s := newTestServer(t, fakeAttester{err: errors.New("boom")})
	resp := s.HandleRequest(Request{
		Version:             Version,
		NonceB64:            base64.StdEncoding.EncodeToString([]byte("nonce")),
		UpstreamHost:        "api.example.com",
		UpstreamPath:        "/v1/messages",
		HTTPMethod:          "POST",
		HTTPStatus:          200,
		ResponseContentType: "text/event-stream",
		RequestSHA256Hex:    proof.SHA256Hex([]byte("request")),
		ResponseSHA256Hex:   proof.SHA256Hex([]byte("response")),
	})
	if resp.OK || resp.Error == nil || resp.Error.Code != "vtpm_quote_failed" {
		t.Fatalf("unexpected quote error response: %#v", resp)
	}
}

func newTestServer(t *testing.T, att proof.Attester) *Server {
	t.Helper()
	s, err := NewServer("", att)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
