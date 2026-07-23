package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Demo-9876/proof-of-observation/aliyun-enclave/internal/attester"
	"github.com/Demo-9876/proof-of-observation/aliyun-enclave/internal/helper"
)

func main() {
	var socketPath string
	var healthCheck bool
	flag.StringVar(&socketPath, "socket", helper.DefaultSocketPath, "Unix domain socket path")
	flag.BoolVar(&healthCheck, "health-check", false, "perform one helper health check and exit")
	flag.Parse()

	if healthCheck {
		if err := helper.HealthCheck(socketPath); err != nil {
			exitf("health check: %v", err)
		}
		return
	}

	vtpm, err := attester.NewAliyunVTPM()
	if err != nil {
		exitf("create aliyun vtpm attester: %v", err)
	}
	if closer, ok := vtpm.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	srv, err := helper.NewServer(socketPath, vtpm)
	if err != nil {
		exitf("create helper server: %v", err)
	}
	if err := srv.Serve(); err != nil {
		exitf("serve: %v", err)
	}
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aliyun-proof-helper: "+format+"\n", args...)
	os.Exit(2)
}
