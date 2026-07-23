package proof

import (
	"fmt"
	"strings"
)

func ValidateRequiredFields(input GenerateHashedInput) error {
	required := map[string]string{
		"nonce_b64":         input.NonceB64,
		"upstream_host":     input.UpstreamHost,
		"upstream_path":     input.UpstreamPath,
		"http_method":       input.HTTPMethod,
		"resp_content_type": input.ResponseContentType,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	return nil
}
