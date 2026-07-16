//go:build aliyun_enclave

package attester

import (
	"fmt"

	"github.com/Demo-9876/proof-of-observation/aliyun-enclave/internal/proof"
	aliyunattest "github.com/aliyun/acs-apsara-enclave/sdk/attest"
)

type aliyunVTPM struct {
	guest *aliyunattest.TPMGuest
}

func newAliyunVTPM() (Attester, error) {
	guest, err := aliyunattest.NewTPMGuest()
	if err != nil {
		return nil, fmt.Errorf("new tpm guest: %w", err)
	}
	if err := guest.CreateEK(aliyunattest.SigningEKRSATemplate, aliyunattest.SigningEKRSAHandle); err != nil {
		guest.Close()
		return nil, fmt.Errorf("create signing ek: %w", err)
	}
	return &aliyunVTPM{guest: guest}, nil
}

func (a *aliyunVTPM) GetQuote(qualifyingData []byte) (proof.QuoteReport, proof.AttesterMetadata, error) {
	report, err := a.guest.GetQuote(aliyunattest.SigningEKRSAHandle, qualifyingData)
	if err != nil {
		return proof.QuoteReport{}, proof.AttesterMetadata{}, err
	}
	return proof.QuoteReport{
			Quoted:           report.Quoted,
			Signature:        report.Signature,
			Cert:             report.Cert,
			PCRValues:        report.PCRInfo.PCRValues,
			PCRSelectionOut:  report.PCRInfo.PCRSelectionOut,
			PCRUpdateCounter: report.PCRInfo.PCRUpdateCounter,
		}, proof.AttesterMetadata{
			SDK:         "github.com/aliyun/acs-apsara-enclave/sdk/attest",
			SDKCommit:   "f81674a6b341e7b835d33ee5da9cb2add6a24379",
			QuoteHandle: "SigningEKRSAHandle",
		}, nil
}

func (a *aliyunVTPM) Close() error {
	if a.guest == nil {
		return nil
	}
	return a.guest.Close()
}
