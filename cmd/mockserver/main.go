// Command mockserver is a minimal CMP server for testing.
package main

import (
	"flag"
	"log"
	"net/http"

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
	log.Fatal(http.ListenAndServe(*addr, mux))
}
