package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const SigningDomainV2 = "tee-exchange-v2"

func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func PathWithoutQuery(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

func FieldClaimsSHA256Hex(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("field_claims JSON: %w", err)
	}
	canonical, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	return SHA256Hex(canonical), nil
}

func BuildV2Statement(f StatementFacts) []byte {
	lines := []string{
		SigningDomainV2,
		"nonce=" + f.NonceB64,
		"upstream-host=" + strings.ToLower(f.UpstreamHost),
		"upstream-path=" + PathWithoutQuery(f.UpstreamPath),
		"http-method=" + strings.ToUpper(f.HTTPMethod),
		fmt.Sprintf("http-status=%d", f.HTTPStatus),
		"resp-content-type=" + f.ResponseContentType,
		"request-body-sha256=" + strings.ToLower(f.RequestBodySHA256Hex),
		"response-body-sha256=" + strings.ToLower(f.ResponseBodySHA256Hex),
	}
	if h, err := FieldClaimsSHA256Hex(f.FieldClaims); err == nil && h != "" {
		lines = append(lines, "field-claims-sha256="+h)
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func ValidateNoCRLF(values map[string]string) error {
	for name, value := range values {
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("%s contains CR/LF", name)
		}
	}
	return nil
}
