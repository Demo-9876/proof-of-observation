package helper

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	Version            = 1
	DefaultSocketPath  = "/run/aliyun-proof-helper.sock"
	MaxRequestPayload  = 64 * 1024
	MaxResponsePayload = 4 * 1024 * 1024
)

type Request struct {
	Version             int             `json:"v"`
	Op                  string          `json:"op,omitempty"`
	NonceB64            string          `json:"nonce_b64,omitempty"`
	UpstreamHost        string          `json:"upstream_host,omitempty"`
	UpstreamPath        string          `json:"upstream_path,omitempty"`
	HTTPMethod          string          `json:"http_method,omitempty"`
	HTTPStatus          int             `json:"http_status,omitempty"`
	ResponseContentType string          `json:"resp_content_type,omitempty"`
	RequestSHA256Hex    string          `json:"request_body_sha256,omitempty"`
	ResponseSHA256Hex   string          `json:"response_body_sha256,omitempty"`
	FieldClaims         json.RawMessage `json:"field_claims,omitempty"`
}

type Response struct {
	Version int             `json:"v"`
	OK      bool            `json:"ok"`
	Proof   json.RawMessage `json:"proof,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n > max {
		return nil, fmt.Errorf("payload too large: %d > %d", n, max)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func WriteFrame(w io.Writer, payload []byte, max int) error {
	if len(payload) > max {
		return fmt.Errorf("payload too large: %d > %d", len(payload), max)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
