//go:build integration

package cmptestsuite

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tsaarni/go-pkicmp/examples/mockserver"
	"github.com/tsaarni/go-pkicmp/server"
)

const sharedSecret = "test-shared-secret"

func TestCMPTestSuite(t *testing.T) {
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv not found in PATH")
	}

	port := startMockServer(t)

	configDir := renderConfig(t, configData{Port: port})

	reportsDir, err := filepath.Abs("reports")
	require.NoError(t, err)

	t.Logf("running cmp-test-suite against port %d (reports: %s)", port, reportsDir)

	runErr := runCMPTestSuite(t, runOpts{
		ConfigDir:  configDir,
		ReportsDir: reportsDir,
	})

	t.Log("--- cmp-test-suite results ---")
	reportResults(t, reportsDir)
	require.NoError(t, runErr, "cmp-test-suite run failed")
}

// startMockServer starts the CMP mock server in a goroutine and returns the port.
func startMockServer(t *testing.T) int {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(newPrefixWriter(os.Stdout, "[mockserver] "), &slog.HandlerOptions{Level: slog.LevelDebug}))

	ca, err := mockserver.New(map[string][]byte{
		"CN=CMP Client": []byte(sharedSecret),
	}, logger)
	require.NoError(t, err)

	srv := server.NewCAServer(ca, ca.Key(), ca.Cert(),
		[]server.Middleware{server.LightweightPolicy()},
		server.WithImplicitConfirm(),
		server.WithSecretLookup(ca),
		server.WithCertificateLookup(ca),
	)

	mux := http.NewServeMux()
	mux.Handle("/cmp", srv)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	port := ln.Addr().(*net.TCPAddr).Port

	logger.Info("listening", "addr", ln.Addr().String())

	httpSrv := &http.Server{Handler: mux}
	go httpSrv.Serve(ln)
	t.Cleanup(func() { httpSrv.Close() })

	// Wait for readiness.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return port
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("mockserver did not become ready")
	return 0
}
