package attester

import "github.com/Demo-9876/proof-of-observation/aliyun-enclave/internal/proof"

type Attester = proof.Attester
type QuoteReport = proof.QuoteReport

func NewAliyunVTPM() (Attester, error) {
	return newAliyunVTPM()
}
