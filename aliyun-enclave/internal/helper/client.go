package helper

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

func HealthCheck(socketPath string) error {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	payload, err := json.Marshal(Request{Version: Version, Op: "health"})
	if err != nil {
		return err
	}
	if err := WriteFrame(conn, payload, MaxRequestPayload); err != nil {
		return err
	}
	raw, err := ReadFrame(conn, MaxResponsePayload)
	if err != nil {
		return err
	}
	var resp Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	if resp.Version != Version {
		return fmt.Errorf("unexpected response version: %d", resp.Version)
	}
	if !resp.OK {
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return fmt.Errorf("health check failed")
	}
	return nil
}
