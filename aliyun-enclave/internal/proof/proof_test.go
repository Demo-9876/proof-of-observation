package proof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

type fakeAttester struct {
	seenQualifyingData []byte
}

func (f *fakeAttester) GetQuote(qualifyingData []byte) (QuoteReport, AttesterMetadata, error) {
	f.seenQualifyingData = append([]byte(nil), qualifyingData...)
	return QuoteReport{
			Quoted:           []byte("quoted"),
			Signature:        []byte("signature"),
			Cert:             []byte("cert"),
			PCRValues:        []byte("pcr-values"),
			PCRSelectionOut:  []byte("pcr-selection"),
			PCRUpdateCounter: 7,
		}, AttesterMetadata{
			SDK:         "test-sdk",
			SDKCommit:   "test-commit",
			QuoteHandle: "test-handle",
		}, nil
}

func TestBuildV2StatementMatchesExistingVector(t *testing.T) {
	got := string(BuildV2Statement(StatementFacts{
		NonceB64:              "MDEyMzQ1Njc4OWFiY2RlZg==",
		UpstreamHost:          "API.Example.Com",
		UpstreamPath:          "/v1/chat?beta=true",
		HTTPMethod:            "post",
		HTTPStatus:            200,
		ResponseContentType:   "text/event-stream; charset=utf-8",
		RequestBodySHA256Hex:  "924067dfbe4731a8f87d4dbc96078edf774685c9c5fb22a50bf210e6fcd2a0a6",
		ResponseBodySHA256Hex: "371d3454662f0d86541fec1c3202000ce425c8c3be9ca0de0e10e5d0225ad8f1",
	}))
	want := "tee-exchange-v2\nnonce=MDEyMzQ1Njc4OWFiY2RlZg==\nupstream-host=api.example.com\nupstream-path=/v1/chat\nhttp-method=POST\nhttp-status=200\nresp-content-type=text/event-stream; charset=utf-8\nrequest-body-sha256=924067dfbe4731a8f87d4dbc96078edf774685c9c5fb22a50bf210e6fcd2a0a6\nresponse-body-sha256=371d3454662f0d86541fec1c3202000ce425c8c3be9ca0de0e10e5d0225ad8f1\n"
	if got != want {
		t.Fatalf("statement mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestBuildAliyunVTPMChallengePayloadIsVerifierCompatible(t *testing.T) {
	got, err := BuildAliyunVTPMChallengePayload(ChallengeFacts{
		Profile:                  "aliyun-vtpm",
		NonceB64:                 "bm9uY2U=",
		StatementPublicKeySHA256: "001122",
		RequestBodySHA256Hex:     "aa",
		ResponseBodySHA256Hex:    "bb",
		UpstreamHost:             "api.example.com",
		UpstreamPath:             "/v1/chat",
		HTTPMethod:               "POST",
		HTTPStatus:               200,
		ResponseContentType:      "text/event-stream",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"http_method":"POST","http_status":200,"nonce":"bm9uY2U=","profile":"aliyun-vtpm","request_body_sha256":"aa","resp_content_type":"text/event-stream","response_body_sha256":"bb","statement_public_key_sha256":"001122","upstream_host":"api.example.com","upstream_path":"/v1/chat"}`
	if string(got) != want {
		t.Fatalf("challenge payload mismatch\nwant: %s\n got: %s", want, got)
	}
}

func TestGenerateBuildsAliyunVTPMProofEnvelope(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	att := &fakeAttester{}
	p, err := Generate(GenerateInput{
		NonceB64:            base64.StdEncoding.EncodeToString([]byte("nonce")),
		UpstreamHost:        "api.example.com",
		UpstreamPath:        "/v1/chat?ignored=true",
		HTTPMethod:          "post",
		HTTPStatus:          200,
		ResponseContentType: "text/event-stream",
		RequestBody:         []byte(`{"model":"example"}`),
		ResponseBody:        []byte("data: ok\n\n"),
	}, GenerateOptions{PrivateKey: priv, Attester: att})
	if err != nil {
		t.Fatal(err)
	}
	if p.Profile != "aliyun-vtpm" || p.Version != 2 || p.Algorithm != "ed25519" {
		t.Fatalf("unexpected proof header: %#v", p)
	}
	if p.PublicKey != base64.StdEncoding.EncodeToString(spki) {
		t.Fatalf("public key mismatch")
	}
	payload, err := base64.StdEncoding.DecodeString(p.Evidence.Challenge.PayloadB64)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(att.seenQualifyingData) != p.Evidence.Challenge.QualifyingDataHex {
		t.Fatalf("attester did not receive challenge hash")
	}
	if p.Attestation == "" {
		t.Fatalf("attestation transport field is empty")
	}
	var fromTransport EvidenceEnvelope
	rawEvidence, err := base64.StdEncoding.DecodeString(p.Attestation)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawEvidence, &fromTransport); err != nil {
		t.Fatal(err)
	}
	if string(payload) != string(mustChallengeForProof(t, p)) {
		t.Fatalf("challenge payload is not rebuilt from proof fields")
	}
	if fromTransport.QuoteReport.PCRInfo.PCRUpdateCounter != 7 {
		t.Fatalf("transport evidence lost PCR update counter")
	}
}

func TestGenerateFromHashesSupportsStreamingCallers(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &fakeAttester{}
	p, err := GenerateFromHashes(GenerateHashedInput{
		NonceB64:              base64.StdEncoding.EncodeToString([]byte("nonce")),
		UpstreamHost:          "api.example.com",
		UpstreamPath:          "/v1/chat",
		HTTPMethod:            "POST",
		HTTPStatus:            200,
		ResponseContentType:   "text/event-stream",
		RequestBodySHA256Hex:  SHA256Hex([]byte("request")),
		ResponseBodySHA256Hex: SHA256Hex([]byte("response")),
	}, GenerateOptions{PrivateKey: priv, Attester: att})
	if err != nil {
		t.Fatal(err)
	}
	if p.RequestSHA256Hex != SHA256Hex([]byte("request")) || p.ResponseSHA256Hex != SHA256Hex([]byte("response")) {
		t.Fatalf("proof did not preserve caller-provided hashes")
	}
	if len(att.seenQualifyingData) != 32 {
		t.Fatalf("attester did not receive a sha256 qualifying data digest")
	}
}

func TestGenerateFromHashesRejectsMissingRequiredFields(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = GenerateFromHashes(GenerateHashedInput{
		NonceB64:              base64.StdEncoding.EncodeToString([]byte("nonce")),
		UpstreamHost:          "api.example.com",
		UpstreamPath:          "",
		HTTPMethod:            "POST",
		HTTPStatus:            200,
		ResponseContentType:   "text/event-stream",
		RequestBodySHA256Hex:  SHA256Hex([]byte("request")),
		ResponseBodySHA256Hex: SHA256Hex([]byte("response")),
	}, GenerateOptions{PrivateKey: priv, Attester: &fakeAttester{}})
	if err == nil || !strings.Contains(err.Error(), "upstream_path is required") {
		t.Fatalf("expected missing field error, got %v", err)
	}
}

func mustChallengeForProof(t *testing.T, p TeeProof) []byte {
	t.Helper()
	pub, err := base64.StdEncoding.DecodeString(p.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := BuildAliyunVTPMChallengePayload(ChallengeFacts{
		Profile:                  "aliyun-vtpm",
		NonceB64:                 p.Nonce,
		StatementPublicKeySHA256: SHA256Hex(pub),
		RequestBodySHA256Hex:     p.RequestSHA256Hex,
		ResponseBodySHA256Hex:    p.ResponseSHA256Hex,
		UpstreamHost:             p.UpstreamHost,
		UpstreamPath:             p.UpstreamPath,
		HTTPMethod:               p.HTTPMethod,
		HTTPStatus:               p.HTTPStatus,
		ResponseContentType:      p.ResponseType,
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
