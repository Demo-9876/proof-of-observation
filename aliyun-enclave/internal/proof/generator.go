package proof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type GenerateInput struct {
	NonceB64            string
	UpstreamHost        string
	UpstreamPath        string
	HTTPMethod          string
	HTTPStatus          int
	ResponseContentType string
	RequestBody         []byte
	ResponseBody        []byte
}

type GenerateHashedInput struct {
	NonceB64              string
	UpstreamHost          string
	UpstreamPath          string
	HTTPMethod            string
	HTTPStatus            int
	ResponseContentType   string
	RequestBodySHA256Hex  string
	ResponseBodySHA256Hex string
}

type GenerateOptions struct {
	PrivateKey ed25519.PrivateKey
	Attester   Attester
}

func Generate(input GenerateInput, opts GenerateOptions) (TeeProof, error) {
	return GenerateFromHashes(GenerateHashedInput{
		NonceB64:              input.NonceB64,
		UpstreamHost:          input.UpstreamHost,
		UpstreamPath:          input.UpstreamPath,
		HTTPMethod:            input.HTTPMethod,
		HTTPStatus:            input.HTTPStatus,
		ResponseContentType:   input.ResponseContentType,
		RequestBodySHA256Hex:  SHA256Hex(input.RequestBody),
		ResponseBodySHA256Hex: SHA256Hex(input.ResponseBody),
	}, opts)
}

func GenerateFromHashes(input GenerateHashedInput, opts GenerateOptions) (TeeProof, error) {
	if opts.Attester == nil {
		return TeeProof{}, fmt.Errorf("attester is required")
	}
	if err := ValidateRequiredFields(input); err != nil {
		return TeeProof{}, err
	}
	if err := ValidateNoCRLF(map[string]string{
		"nonce":             input.NonceB64,
		"upstream_host":     input.UpstreamHost,
		"upstream_path":     input.UpstreamPath,
		"http_method":       input.HTTPMethod,
		"resp_content_type": input.ResponseContentType,
	}); err != nil {
		return TeeProof{}, err
	}
	if _, err := base64.StdEncoding.DecodeString(input.NonceB64); err != nil {
		return TeeProof{}, fmt.Errorf("nonce must be base64: %w", err)
	}
	requestHash, err := normalizeSHA256Hex(input.RequestBodySHA256Hex, "request_body_sha256")
	if err != nil {
		return TeeProof{}, err
	}
	responseHash, err := normalizeSHA256Hex(input.ResponseBodySHA256Hex, "response_body_sha256")
	if err != nil {
		return TeeProof{}, err
	}

	privateKey := opts.PrivateKey
	if privateKey == nil {
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return TeeProof{}, fmt.Errorf("generate ed25519 key: %w", err)
		}
		privateKey = generated
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return TeeProof{}, fmt.Errorf("private key did not expose ed25519 public key")
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return TeeProof{}, fmt.Errorf("marshal ed25519 public key spki: %w", err)
	}
	publicKeyB64 := base64.StdEncoding.EncodeToString(spki)
	publicKeyDigest := sha256.Sum256(spki)

	challengePayload, err := BuildAliyunVTPMChallengePayload(ChallengeFacts{
		Profile:                  "aliyun-vtpm",
		NonceB64:                 input.NonceB64,
		StatementPublicKeySHA256: hex.EncodeToString(publicKeyDigest[:]),
		RequestBodySHA256Hex:     requestHash,
		ResponseBodySHA256Hex:    responseHash,
		UpstreamHost:             input.UpstreamHost,
		UpstreamPath:             input.UpstreamPath,
		HTTPMethod:               input.HTTPMethod,
		HTTPStatus:               input.HTTPStatus,
		ResponseContentType:      input.ResponseContentType,
	})
	if err != nil {
		return TeeProof{}, err
	}
	challenge := ChallengeEnvelopeForPayload(challengePayload)
	qualifyingData, err := hex.DecodeString(challenge.QualifyingDataHex)
	if err != nil {
		return TeeProof{}, err
	}
	report, meta, err := opts.Attester.GetQuote(qualifyingData)
	if err != nil {
		return TeeProof{}, fmt.Errorf("get vtpm quote: %w", err)
	}

	evidence := EvidenceEnvelope{
		Profile:  "aliyun-vtpm",
		Version:  1,
		Attester: meta,
		QuoteReport: QuoteReportEnvelope{
			QuotedB64:    base64.StdEncoding.EncodeToString(report.Quoted),
			SignatureB64: base64.StdEncoding.EncodeToString(report.Signature),
			PCRInfo: PCRInfoWire{
				PCRValuesB64:       base64.StdEncoding.EncodeToString(report.PCRValues),
				PCRSelectionOutB64: base64.StdEncoding.EncodeToString(report.PCRSelectionOut),
				PCRUpdateCounter:   report.PCRUpdateCounter,
			},
			CertB64: base64.StdEncoding.EncodeToString(report.Cert),
		},
		Challenge: challenge,
		PlatformAttestation: PlatformAttestation{
			Mode:         "missing",
			CertChainPEM: []string{},
			Revocation: RevocationStatus{
				Checked: false,
			},
		},
	}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return TeeProof{}, fmt.Errorf("marshal evidence envelope: %w", err)
	}

	statement := BuildV2Statement(StatementFacts{
		NonceB64:              input.NonceB64,
		UpstreamHost:          input.UpstreamHost,
		UpstreamPath:          input.UpstreamPath,
		HTTPMethod:            input.HTTPMethod,
		HTTPStatus:            input.HTTPStatus,
		ResponseContentType:   input.ResponseContentType,
		RequestBodySHA256Hex:  requestHash,
		ResponseBodySHA256Hex: responseHash,
	})
	signature := ed25519.Sign(privateKey, statement)

	return TeeProof{
		Version:           2,
		Profile:           "aliyun-vtpm",
		Algorithm:         "ed25519",
		PublicKey:         publicKeyB64,
		Nonce:             input.NonceB64,
		UpstreamHost:      input.UpstreamHost,
		UpstreamPath:      input.UpstreamPath,
		HTTPMethod:        input.HTTPMethod,
		HTTPStatus:        input.HTTPStatus,
		ResponseType:      input.ResponseContentType,
		RequestSHA256Hex:  requestHash,
		ResponseSHA256Hex: responseHash,
		Signature:         base64.StdEncoding.EncodeToString(signature),
		Attestation:       base64.StdEncoding.EncodeToString(evidenceJSON),
		Evidence:          evidence,
	}, nil
}

func normalizeSHA256Hex(value string, label string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if len(normalized) != sha256.Size*2 {
		return "", fmt.Errorf("%s must be 64 lowercase/uppercase hex characters", label)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("%s must be hex: %w", label, err)
	}
	return normalized, nil
}
