// Command mockserver is a minimal CMP server for testing.
package main

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/tsaarni/go-pkicmp/examples/mockserver"
	"github.com/tsaarni/go-pkicmp/server"
)

func main() {
	// Create a logger for the server.
	log := slog.Default()

	// Create a CA with shared secrets for MAC-based enrollment.
	// Each entry maps a senderKID (reference number) to an Initial Authentication
	// Key (IAK). In production these would be loaded from a database or a
	// secrets manager.
	ca, err := mockserver.New(map[string][]byte{
		"my-device": []byte("test-shared-secret"),
	}, log)
	if err != nil {
		log.Error("creating CA", "error", err)
		return
	}
	log.Info("CA ready", "subject", ca.Cert().Subject.String(), "serial", ca.Cert().SerialNumber)

	// Connect the CA into a CMP server.
	//
	//   - ca.Key()/ca.Cert(): sign every outgoing response; key is a crypto.Signer
	//     so an HSM-backed signer can be used in production.
	//   - LightweightPolicy: enforces the mandatory checks from RFC 9483.
	//   - WithImplicitConfirm: skips the certConf/PKIConf round-trip.
	//   - WithSecretLookup: enables MAC (shared-secret) protection for IR/CR.
	//   - WithCertificateLookup: enables signature protection for KUR/certConf.
	srv := server.NewCAServer(ca, ca.Key(), ca.Cert(),
		[]server.Middleware{server.LightweightPolicy()},
		server.WithImplicitConfirm(),
		server.WithSecretLookup(ca),
		server.WithCertificateLookup(ca),
	)

	mux := http.NewServeMux()
	mux.Handle("/cmp", srv)

	log.Info("mockserver listening", "addr", "localhost:8080", "path", "/cmp")
	httpSrv := &http.Server{
		Addr:         "localhost:8080",
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Error("server error", "error", err)
	}
}
