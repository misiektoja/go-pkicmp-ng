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
	"github.com/tsaarni/go-pkicmp/internal/mockserver"
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

	// Known upstream test suite bugs — skipped via pre-run modifier.
	knownFailures := []string{
		// Test suite bug (tests/cert_conf_tests.robot): expects badRequest but RFC 9483 §3.5
		// mandates badDataFormat for missing transactionID. The correct test in
		// tests/lwcmp.robot ("FailInfo Bit Must Be badDataFormat For Missing transactionID") passes.
		"CA MUST Reject CertConf with omitted transactionID",
		// pyasn1 bug (pyasn1/pyasn1#53) in tests/lwcmp.robot: encoder.encode() mutates
		// objects, crashing subsequent __eq__.
		"CA Must Validate The Received PKI Message",
	}

	runErr := runCMPTestSuite(t, runOpts{
		ConfigDir:  configDir,
		ReportsDir: reportsDir,
		Tags:       []string{"minimal", "pbmac1"},
		Excludes:   []string{"revocation", "kga", "genm", "nested", "pq", "sha3", "deprecated"},
		SkipTests:  knownFailures,
	})

	t.Log("--- cmp-test-suite results ---")
	reportResults(t, reportsDir)
	require.NoError(t, runErr, "cmp-test-suite run failed")
}

// startMockServer starts the CMP mock server in a goroutine and returns the port.
func startMockServer(t *testing.T) int {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(newPrefixWriter(os.Stdout, "[mockserver] "), &slog.HandlerOptions{Level: slog.LevelDebug}))

	ca, err := mockserver.New(
		mockserver.WithLogger(logger),
		mockserver.WithSecret([]byte("CN=CMP Client"), []byte(sharedSecret)),
	)
	require.NoError(t, err)

	srv := ca.NewServer()

	mux := http.NewServeMux()
	mux.Handle("/cmp", srv)

	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	port := ln.Addr().(*net.TCPAddr).Port

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
