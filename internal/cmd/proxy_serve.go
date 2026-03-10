package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/steipete/gogcli/internal/accessctl"
)

// execMu serializes in-process command execution because executeInProcess
// temporarily replaces os.Stdout/os.Stderr and uses a package-level variable
// (proxyPolicy). Concurrent execution would cause data races.
var execMu sync.Mutex

// ProxyServeCmd starts the proxy server process.
// The account is taken from the global --account flag.
type ProxyServeCmd struct {
	Policy   string `name:"policy" help:"Path to access policy file" default:""`
	Socket   string `name:"socket" help:"Unix socket path" default:""`
	NonceFile string `name:"nonce-file" help:"Nonce output path" default:""`
}

// proxyRequest is the JSON request from client to proxy.
type proxyRequest struct {
	Nonce string   `json:"nonce"`
	Args  []string `json:"args"`
}

// proxyResponse is the JSON response from proxy to client.
type proxyResponse struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// blockedProxyCommands are top-level commands that cannot be run through the proxy.
var blockedProxyCommands = map[string]bool{
	"auth":    true,
	"config":  true,
	"login":   true,
	"logout":  true,
	"status":  true,
	"proxy":   true,
	"version": true,
}

func (c *ProxyServeCmd) Run(ctx context.Context, flags *RootFlags) error {
	account, err := requireAccount(flags)
	if err != nil {
		return err
	}

	// Resolve defaults
	socketPath := strings.TrimSpace(c.Socket)
	if socketPath == "" {
		policyDefault, err := accessctl.DefaultPolicyPath()
		if err != nil {
			return err
		}
		// Use same directory as policy, but proxy.sock filename
		socketPath = filepath.Join(filepath.Dir(policyDefault), "proxy.sock")
	}

	noncePath := strings.TrimSpace(c.NonceFile)
	if noncePath == "" {
		noncePath = strings.TrimSuffix(socketPath, ".sock") + ".nonce"
	}

	// Load access policy into memory (once, immutable)
	var policy *accessctl.Policy
	policyPath := strings.TrimSpace(c.Policy)
	if policyPath == "" {
		defaultPath, err := accessctl.DefaultPolicyPath()
		if err != nil {
			return err
		}
		// Only load if file exists at the default path
		if _, statErr := os.Stat(defaultPath); statErr == nil {
			policyPath = defaultPath
		}
	}
	if policyPath != "" {
		pf, err := accessctl.LoadPolicyFile(policyPath)
		if err != nil {
			return fmt.Errorf("load access policy: %w", err)
		}
		policy = pf.ForAccount(account)
		if policy != nil {
			slog.Info("loaded access policy", "path", policyPath, "account", account, "mode", policy.Mode)
		} else {
			slog.Info("no policy entry for account", "path", policyPath, "account", account)
		}
	}

	// Generate session nonce
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	// Write nonce file (0600 permissions)
	if err := os.WriteFile(noncePath, []byte(nonce), 0o600); err != nil {
		return fmt.Errorf("write nonce file: %w", err)
	}
	defer os.Remove(noncePath)

	// Remove stale socket file
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	// Set socket permissions
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Proxy listening on %s\n", socketPath)
	fmt.Fprintf(os.Stderr, "Nonce written to %s\n", noncePath)
	fmt.Fprintf(os.Stderr, "Account: %s\n", account)
	if policy != nil {
		fmt.Fprintf(os.Stderr, "Access policy: %s mode, %d addresses, %d domains\n",
			policy.Mode, len(policy.Addresses), len(policy.Domains))
	}

	// Handle graceful shutdown
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-sigCtx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-sigCtx.Done():
				fmt.Fprintln(os.Stderr, "\nProxy shutting down")
				return nil
			default:
				slog.Warn("accept error", "error", err)
				continue
			}
		}

		go c.handleConn(ctx, conn, nonce, account, policy)
	}
}

func (c *ProxyServeCmd) handleConn(ctx context.Context, conn net.Conn, nonce string, account string, policy *accessctl.Policy) {
	defer conn.Close()

	// Read request
	data, err := io.ReadAll(io.LimitReader(conn, 1<<20)) // 1MB max
	if err != nil {
		writeProxyResponse(conn, proxyResponse{ExitCode: 1, Stderr: "read error: " + err.Error()})
		return
	}

	var req proxyRequest
	if err := json.Unmarshal(data, &req); err != nil {
		writeProxyResponse(conn, proxyResponse{ExitCode: 1, Stderr: "invalid request: " + err.Error()})
		return
	}

	// Verify nonce (constant-time comparison)
	if subtle.ConstantTimeCompare([]byte(req.Nonce), []byte(nonce)) != 1 {
		writeProxyResponse(conn, proxyResponse{ExitCode: 1, Stderr: "invalid nonce"})
		return
	}

	// Check for blocked commands (find first non-flag argument)
	if topCmd := firstNonFlagArg(req.Args); topCmd != "" {
		if blockedProxyCommands[topCmd] {
			writeProxyResponse(conn, proxyResponse{
				ExitCode: 1,
				Stderr:   fmt.Sprintf("command %q is blocked through the proxy", topCmd),
			})
			return
		}
	}

	// Check for blocked flags (--access-token, --access-policy, --account)
	for _, arg := range req.Args {
		if strings.HasPrefix(arg, "--access-token") ||
			strings.HasPrefix(arg, "--access-policy") ||
			arg == "--account" || strings.HasPrefix(arg, "--account=") ||
			arg == "--acct" || strings.HasPrefix(arg, "--acct=") ||
			arg == "-a" {
			blocked := arg
			if idx := strings.Index(blocked, "="); idx != -1 {
				blocked = blocked[:idx]
			}
			writeProxyResponse(conn, proxyResponse{
				ExitCode: 1,
				Stderr:   fmt.Sprintf("%s is blocked through the proxy", blocked),
			})
			return
		}
	}

	// Inject the account flag
	args := append([]string{"--account", account}, req.Args...)

	// Execute the command in-process, capturing stdout/stderr
	resp := c.executeInProcess(ctx, args, policy)
	writeProxyResponse(conn, resp)
}

func (c *ProxyServeCmd) executeInProcess(ctx context.Context, args []string, policy *accessctl.Policy) proxyResponse {
	execMu.Lock()
	defer execMu.Unlock()

	// Capture stdout and stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return proxyResponse{ExitCode: 1, Stderr: "pipe error: " + err.Error()}
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		stdoutR.Close()
		stdoutW.Close()
		return proxyResponse{ExitCode: 1, Stderr: "pipe error: " + err.Error()}
	}

	os.Stdout = stdoutW
	os.Stderr = stderrW

	// Build a dedicated execution that injects the policy into the context.
	// We temporarily modify the env to pass the policy path — but the policy
	// is held in memory and injected into context, not re-read from disk.
	var stdoutBuf, stderrBuf bytes.Buffer
	done := make(chan struct{})
	go func() {
		io.Copy(&stdoutBuf, stdoutR)
		close(done)
	}()
	done2 := make(chan struct{})
	go func() {
		io.Copy(&stderrBuf, stderrR)
		close(done2)
	}()

	execErr := executeWithPolicy(args, policy)

	stdoutW.Close()
	stderrW.Close()
	<-done
	<-done2
	stdoutR.Close()
	stderrR.Close()

	os.Stdout = oldStdout
	os.Stderr = oldStderr

	exitCode := 0
	if execErr != nil {
		exitCode = ExitCode(execErr)
		if exitCode == 0 {
			exitCode = 1
		}
	}

	return proxyResponse{
		ExitCode: exitCode,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
	}
}

// executeWithPolicy runs Execute() but injects the policy into the context.
// It clears proxy env vars to prevent recursive proxy connections.
func executeWithPolicy(args []string, policy *accessctl.Policy) error {
	// Clear proxy env to prevent recursion when Execute checks GOG_PROXY_SOCKET
	old := os.Getenv("GOG_PROXY_SOCKET")
	os.Unsetenv("GOG_PROXY_SOCKET")
	defer func() {
		if old != "" {
			os.Setenv("GOG_PROXY_SOCKET", old)
		}
	}()

	// We use a package-level variable to pass the policy to the Execute function.
	// This avoids having to modify Execute's signature.
	proxyPolicy = policy
	defer func() { proxyPolicy = nil }()

	return Execute(args)
}

// proxyPolicy holds the policy injected by the proxy server, used during
// in-process Execute calls. This is only set during proxy serve execution.
var proxyPolicy *accessctl.Policy

// firstNonFlagArg returns the first argument that doesn't start with "-",
// skipping flag values. This finds the top-level command even when global
// flags like --json precede it.
func firstNonFlagArg(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			// If this global flag takes a value, skip the next arg too
			if globalFlagTakesValue(a) && !strings.Contains(a, "=") && i+1 < len(args) {
				i++
			}
			continue
		}
		return strings.ToLower(strings.TrimSpace(a))
	}
	return ""
}

func writeProxyResponse(conn net.Conn, resp proxyResponse) {
	data, _ := json.Marshal(resp)
	conn.Write(data)
}
