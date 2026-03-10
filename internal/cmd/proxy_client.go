package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// proxyClientExec sends CLI args to the proxy server and prints the response.
// This is called from Execute() when GOG_PROXY_SOCKET is set.
func proxyClientExec(socketPath string, args []string) error {
	noncePath := proxyNoncePath(args, socketPath)

	nonceData, err := os.ReadFile(noncePath)
	if err != nil {
		return fmt.Errorf("read proxy nonce from %s: %w", noncePath, err)
	}
	nonce := strings.TrimSpace(string(nonceData))

	// Strip proxy-related flags from args before forwarding
	cleanArgs := stripProxyFlags(args)

	// Connect to proxy
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("connect to proxy at %s: %w", socketPath, err)
	}
	defer conn.Close()

	// Send request
	req := proxyRequest{
		Nonce: nonce,
		Args:  cleanArgs,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal proxy request: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write to proxy: %w", err)
	}

	// Close write side to signal end of request
	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite()
	}

	// Read response
	respData, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("read proxy response: %w", err)
	}

	var resp proxyResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("parse proxy response: %w", err)
	}

	// Print stdout/stderr
	if resp.Stdout != "" {
		fmt.Fprint(os.Stdout, resp.Stdout)
	}
	if resp.Stderr != "" {
		fmt.Fprint(os.Stderr, resp.Stderr)
	}

	if resp.ExitCode != 0 {
		return &ExitError{Code: resp.ExitCode, Err: fmt.Errorf("proxy command exited with code %d", resp.ExitCode)}
	}
	return nil
}

func proxyNoncePath(args []string, socketPath string) string {
	for i, a := range args {
		if a == "--proxy-nonce-file" && i+1 < len(args) {
			return strings.TrimSpace(args[i+1])
		}
		if strings.HasPrefix(a, "--proxy-nonce-file=") {
			return strings.TrimSpace(strings.TrimPrefix(a, "--proxy-nonce-file="))
		}
	}

	if noncePath := strings.TrimSpace(os.Getenv("GOG_PROXY_NONCE_FILE")); noncePath != "" {
		return noncePath
	}

	return strings.TrimSuffix(socketPath, ".sock") + ".nonce"
}

// stripProxyFlags removes --proxy-socket, --proxy-nonce-file, and related
// env-override flags from the argument list since the proxy handles these.
func stripProxyFlags(args []string) []string {
	var out []string
	skip := false
	for i, a := range args {
		if skip {
			skip = false
			continue
		}
		switch {
		case a == "--proxy-socket", a == "--proxy-nonce-file":
			if i+1 < len(args) {
				skip = true
			}
			continue
		case strings.HasPrefix(a, "--proxy-socket="), strings.HasPrefix(a, "--proxy-nonce-file="):
			continue
		}
		out = append(out, a)
	}
	return out
}
