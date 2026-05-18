// Command mockserver is a minimal CMP server for testing.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/tsaarni/go-pkicmp/internal/mockserver"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	ca, err := mockserver.New(
		mockserver.WithSecret(nil, []byte("test-shared-secret")),
	)
	if err != nil {
		log.Fatalf("creating CA: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/cmp", ca.NewServer())

	log.Printf("mockserver listening on %s", *addr)
	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
