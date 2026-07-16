//go:build !aliyun_enclave

package attester

import "fmt"

func newAliyunVTPM() (Attester, error) {
	return nil, fmt.Errorf("aliyun vTPM attester requires building with -tags aliyun_enclave inside Alibaba Cloud Enclave")
}
