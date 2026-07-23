package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Demo-9876/proof-of-observation/aliyun-enclave/internal/attester"
	"github.com/Demo-9876/proof-of-observation/aliyun-enclave/internal/proof"
)

func main() {
	var nonceB64 string
	var upstreamHost string
	var upstreamPath string
	var httpMethod string
	var httpStatus int
	var responseContentType string
	var requestBodyFile string
	var responseBodyFile string
	var requestSHA256Hex string
	var responseSHA256Hex string
	var outFile string

	flag.StringVar(&nonceB64, "nonce-b64", "", "verifier nonce encoded as base64; generated only when --generate-nonce is set")
	generateNonce := flag.Bool("generate-nonce", false, "generate a fresh 32-byte nonce for local experiments")
	flag.StringVar(&upstreamHost, "upstream-host", "", "signed upstream host")
	flag.StringVar(&upstreamPath, "upstream-path", "", "signed upstream path")
	flag.StringVar(&httpMethod, "http-method", "POST", "signed HTTP method")
	flag.IntVar(&httpStatus, "http-status", 200, "signed HTTP status")
	flag.StringVar(&responseContentType, "resp-content-type", "", "signed response content-type")
	flag.StringVar(&requestBodyFile, "request-body-file", "", "request body bytes; empty means zero-length body")
	flag.StringVar(&responseBodyFile, "response-body-file", "", "response body bytes")
	flag.StringVar(&requestSHA256Hex, "request-sha256", "", "request body sha256 hex for streaming callers")
	flag.StringVar(&responseSHA256Hex, "response-sha256", "", "response body sha256 hex for streaming callers")
	flag.StringVar(&outFile, "out", "", "proof JSON output path; stdout when empty")
	flag.Parse()

	if *generateNonce {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			exitf("generate nonce: %v", err)
		}
		nonceB64 = base64.StdEncoding.EncodeToString(nonce)
	}
	if nonceB64 == "" || upstreamHost == "" || upstreamPath == "" {
		exitf("--nonce-b64, --upstream-host, and --upstream-path are required")
	}

	hasHashInputs := requestSHA256Hex != "" || responseSHA256Hex != ""
	if hasHashInputs && (requestSHA256Hex == "" || responseSHA256Hex == "") {
		exitf("--request-sha256 and --response-sha256 must be provided together")
	}
	if !hasHashInputs && responseBodyFile == "" {
		exitf("either --response-body-file or --response-sha256 is required")
	}

	vtpm, err := attester.NewAliyunVTPM()
	if err != nil {
		exitf("create aliyun vtpm attester: %v", err)
	}
	if closer, ok := vtpm.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	var p proof.TeeProof
	if hasHashInputs {
		p, err = proof.GenerateFromHashes(proof.GenerateHashedInput{
			NonceB64:              nonceB64,
			UpstreamHost:          upstreamHost,
			UpstreamPath:          upstreamPath,
			HTTPMethod:            httpMethod,
			HTTPStatus:            httpStatus,
			ResponseContentType:   responseContentType,
			RequestBodySHA256Hex:  requestSHA256Hex,
			ResponseBodySHA256Hex: responseSHA256Hex,
		}, proof.GenerateOptions{Attester: vtpm})
	} else {
		requestBody, err := readOptionalFile(requestBodyFile)
		if err != nil {
			exitf("read request body: %v", err)
		}
		responseBody, err := os.ReadFile(responseBodyFile)
		if err != nil {
			exitf("read response body: %v", err)
		}
		p, err = proof.Generate(proof.GenerateInput{
			NonceB64:            nonceB64,
			UpstreamHost:        upstreamHost,
			UpstreamPath:        upstreamPath,
			HTTPMethod:          httpMethod,
			HTTPStatus:          httpStatus,
			ResponseContentType: responseContentType,
			RequestBody:         requestBody,
			ResponseBody:        responseBody,
		}, proof.GenerateOptions{Attester: vtpm})
	}
	if err != nil {
		exitf("generate proof: %v", err)
	}

	out, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		exitf("marshal proof: %v", err)
	}
	out = append(out, '\n')
	if outFile == "" {
		if _, err := os.Stdout.Write(out); err != nil {
			exitf("write stdout: %v", err)
		}
		return
	}
	if err := os.WriteFile(outFile, out, 0600); err != nil {
		exitf("write output: %v", err)
	}
}

func readOptionalFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aliyun-proof: "+format+"\n", args...)
	os.Exit(2)
}
