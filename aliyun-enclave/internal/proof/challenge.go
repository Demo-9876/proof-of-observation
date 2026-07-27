package proof

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func BuildAliyunVTPMChallengePayload(f ChallengeFacts) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	hasFieldClaims := len(f.FieldClaims) > 0
	if hasFieldClaims {
		h, err := FieldClaimsSHA256Hex(f.FieldClaims)
		if err != nil {
			return nil, err
		}
		writeJSONPair(&buf, "field_claims_sha256", h, false)
	}
	writeJSONPair(&buf, "http_method", f.HTTPMethod, hasFieldClaims)
	buf.WriteByte(',')
	buf.WriteString(`"http_status":`)
	buf.WriteString(fmt.Sprintf("%d", f.HTTPStatus))
	writeJSONPair(&buf, "nonce", f.NonceB64, true)
	writeJSONPair(&buf, "profile", f.Profile, true)
	writeJSONPair(&buf, "request_body_sha256", f.RequestBodySHA256Hex, true)
	writeJSONPair(&buf, "resp_content_type", f.ResponseContentType, true)
	writeJSONPair(&buf, "response_body_sha256", f.ResponseBodySHA256Hex, true)
	writeJSONPair(&buf, "statement_public_key_sha256", f.StatementPublicKeySHA256, true)
	writeJSONPair(&buf, "upstream_host", f.UpstreamHost, true)
	writeJSONPair(&buf, "upstream_path", f.UpstreamPath, true)
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func QualifyingData(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return sum[:]
}

func ChallengeEnvelopeForPayload(payload []byte) ChallengeEnvelope {
	qd := QualifyingData(payload)
	return ChallengeEnvelope{
		Algorithm:         "sha256",
		PayloadB64:        base64.StdEncoding.EncodeToString(payload),
		QualifyingDataHex: hex.EncodeToString(qd),
	}
}

func writeJSONPair(buf *bytes.Buffer, key string, value string, withLeadingComma bool) {
	if withLeadingComma {
		buf.WriteByte(',')
	}
	buf.WriteString(quoteJSONString(key))
	buf.WriteByte(':')
	buf.WriteString(quoteJSONString(value))
}

func quoteJSONString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		panic(err)
	}
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return string(out)
}
