package proof

type TeeProof struct {
	Version           int              `json:"v"`
	Profile           string           `json:"profile"`
	Algorithm         string           `json:"alg"`
	PublicKey         string           `json:"public_key"`
	Nonce             string           `json:"nonce"`
	UpstreamHost      string           `json:"upstream_host"`
	UpstreamPath      string           `json:"upstream_path"`
	HTTPMethod        string           `json:"http_method"`
	HTTPStatus        int              `json:"http_status"`
	ResponseType      string           `json:"resp_content_type"`
	RequestSHA256Hex  string           `json:"request_body_sha256"`
	ResponseSHA256Hex string           `json:"response_body_sha256"`
	Signature         string           `json:"signature"`
	Attestation       string           `json:"attestation"`
	Evidence          EvidenceEnvelope `json:"evidence"`
}

type StatementFacts struct {
	NonceB64              string
	UpstreamHost          string
	UpstreamPath          string
	HTTPMethod            string
	HTTPStatus            int
	ResponseContentType   string
	RequestBodySHA256Hex  string
	ResponseBodySHA256Hex string
}

type ChallengeFacts struct {
	Profile                  string
	NonceB64                 string
	StatementPublicKeySHA256 string
	RequestBodySHA256Hex     string
	ResponseBodySHA256Hex    string
	UpstreamHost             string
	UpstreamPath             string
	HTTPMethod               string
	HTTPStatus               int
	ResponseContentType      string
}

type EvidenceEnvelope struct {
	Profile             string              `json:"profile"`
	Version             int                 `json:"version"`
	Attester            AttesterMetadata    `json:"attester"`
	QuoteReport         QuoteReportEnvelope `json:"quote_report"`
	Challenge           ChallengeEnvelope   `json:"challenge"`
	PlatformAttestation PlatformAttestation `json:"platform_attestation"`
}

type AttesterMetadata struct {
	SDK         string `json:"sdk"`
	SDKCommit   string `json:"sdk_commit"`
	QuoteHandle string `json:"quote_handle"`
}

type QuoteReportEnvelope struct {
	QuotedB64    string      `json:"quoted_b64"`
	SignatureB64 string      `json:"signature_b64"`
	PCRInfo      PCRInfoWire `json:"pcr_info"`
	CertB64      string      `json:"cert_b64"`
}

type PCRInfoWire struct {
	PCRValuesB64       string `json:"pcr_values_b64"`
	PCRSelectionOutB64 string `json:"pcr_selection_out_b64"`
	PCRUpdateCounter   uint32 `json:"pcr_update_counter"`
}

type ChallengeEnvelope struct {
	Algorithm         string `json:"alg"`
	PayloadB64        string `json:"payload_b64"`
	QualifyingDataHex string `json:"qualifying_data_hex"`
}

type PlatformAttestation struct {
	Mode          string           `json:"mode"`
	CertChainPEM  []string         `json:"cert_chain_pem"`
	TrustAnchorID *string          `json:"trust_anchor_id"`
	Revocation    RevocationStatus `json:"revocation"`
}

type RevocationStatus struct {
	Checked bool    `json:"checked"`
	Method  *string `json:"method"`
}

type QuoteReport struct {
	Quoted           []byte
	Signature        []byte
	Cert             []byte
	PCRValues        []byte
	PCRSelectionOut  []byte
	PCRUpdateCounter uint32
}

type Attester interface {
	GetQuote(qualifyingData []byte) (QuoteReport, AttesterMetadata, error)
}
