//go:build aliyun_enclave

package attester

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"

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
	if err := validateSigningEK(guest); err != nil {
		guest.Close()
		return nil, err
	}
	return &aliyunVTPM{guest: guest}, nil
}

func validateSigningEK(guest *aliyunattest.TPMGuest) error {
	if _, err := guest.GetPrimaryKeyInfo(aliyunattest.SigningEKRSAHandle); err != nil {
		return fmt.Errorf("read signing ek public area: %w", err)
	}
	certDER, err := guest.ReadNV(aliyunattest.SigningEKCertNVHandle)
	if err != nil {
		return fmt.Errorf("read signing ek cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse signing ek cert: %w", err)
	}
	sum := sha256.Sum256(certDER)
	log.Printf(
		"aliyun vtpm signing ek cert subject=%q issuer=%q serial=%s sha256=%s",
		cert.Subject.String(),
		cert.Issuer.String(),
		cert.SerialNumber.String(),
		hex.EncodeToString(sum[:]),
	)
	return nil
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
