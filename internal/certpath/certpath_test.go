package certpath

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/stretchr/testify/require"
)

// party is a certificate together with the key it certifies.
type party struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// compositeKey generates a composite ML-DSA key with the fastest traditional component.
func compositeKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := compositemldsa.GenerateKey(compositemldsa.MLDSA44ECDSAP256SHA256)
	require.NoError(t, err)
	return key
}

// ecdsaKey generates an ECDSA P-256 key.
func ecdsaKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// caTemplate returns a CA certificate template valid for one hour around now.
func caTemplate(name string) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

// leafTemplate returns an end-entity certificate template valid for one hour around now.
func leafTemplate() *x509.Certificate {
	return &x509.Certificate{
		Subject:   pkix.Name{CommonName: "Leaf"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
}

// issue certifies key with tmpl, signed by issuer or self-signed when issuer is nil.
func issue(t *testing.T, tmpl *x509.Certificate, key crypto.Signer, issuer *party) *party {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl.SerialNumber = serial
	parent, signer := tmpl, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := compositex509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &party{cert: cert, key: key}
}

// pool returns a certificate pool holding certs.
func pool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, cert := range certs {
		p.AddCert(cert)
	}
	return p
}

// TestVerifyAcceptsPaths covers classical paths and paths with composite links.
func TestVerifyAcceptsPaths(t *testing.T) {
	t.Run("classical", func(t *testing.T) {
		root := issue(t, caTemplate("Root"), ecdsaKey(t), nil)
		inter := issue(t, caTemplate("Intermediate"), ecdsaKey(t), root)
		leaf := issue(t, leafTemplate(), ecdsaKey(t), inter)
		require.NoError(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{inter.cert}, time.Now()))
	})
	t.Run("composite root", func(t *testing.T) {
		root := issue(t, caTemplate("Root"), compositeKey(t), nil)
		leaf := issue(t, leafTemplate(), ecdsaKey(t), root)
		require.NoError(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{root.cert}, time.Now()))
	})
	t.Run("composite root and intermediate", func(t *testing.T) {
		root := issue(t, caTemplate("Root"), compositeKey(t), nil)
		inter := issue(t, caTemplate("Intermediate"), compositeKey(t), root)
		leaf := issue(t, leafTemplate(), ecdsaKey(t), inter)
		require.NoError(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{inter.cert, root.cert}, time.Now()))
	})
	t.Run("composite intermediate below classical root", func(t *testing.T) {
		root := issue(t, caTemplate("Root"), ecdsaKey(t), nil)
		inter := issue(t, caTemplate("Intermediate"), compositeKey(t), root)
		leaf := issue(t, leafTemplate(), ecdsaKey(t), inter)
		require.NoError(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{inter.cert}, time.Now()))
	})
	t.Run("path length permits intermediate", func(t *testing.T) {
		tmpl := caTemplate("Root")
		tmpl.MaxPathLen = 1
		root := issue(t, tmpl, compositeKey(t), nil)
		inter := issue(t, caTemplate("Intermediate"), compositeKey(t), root)
		leaf := issue(t, leafTemplate(), ecdsaKey(t), inter)
		require.NoError(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{inter.cert, root.cert}, time.Now()))
	})
	t.Run("name constraints on classical path", func(t *testing.T) {
		tmpl := caTemplate("Root")
		tmpl.PermittedDNSDomains = []string{"example.com"}
		root := issue(t, tmpl, ecdsaKey(t), nil)
		leafTmpl := leafTemplate()
		leafTmpl.DNSNames = []string{"device.example.com"}
		leaf := issue(t, leafTmpl, ecdsaKey(t), root)
		require.NoError(t, Verify(leaf.cert, pool(root.cert), nil, time.Now()))
	})
}

// TestVerifyRejectsPaths covers composite paths that must not be trusted.
func TestVerifyRejectsPaths(t *testing.T) {
	t.Run("anchor missing from candidates", func(t *testing.T) {
		root := issue(t, caTemplate("Root"), compositeKey(t), nil)
		leaf := issue(t, leafTemplate(), ecdsaKey(t), root)
		require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), nil, time.Now()), errUntrusted)
	})
	t.Run("issuer not trusted", func(t *testing.T) {
		root := issue(t, caTemplate("Root"), compositeKey(t), nil)
		other := issue(t, caTemplate("Other"), compositeKey(t), nil)
		leaf := issue(t, leafTemplate(), ecdsaKey(t), root)
		require.ErrorIs(t, Verify(leaf.cert, pool(other.cert), []*x509.Certificate{root.cert}, time.Now()), errUntrusted)
	})
	t.Run("impostor with the anchor name", func(t *testing.T) {
		root := issue(t, caTemplate("Root"), compositeKey(t), nil)
		impostor := issue(t, caTemplate("Root"), compositeKey(t), nil)
		leaf := issue(t, leafTemplate(), ecdsaKey(t), impostor)
		candidates := []*x509.Certificate{impostor.cert, root.cert}
		require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), candidates, time.Now()), errUntrusted)
	})
	t.Run("issuer is not a CA", func(t *testing.T) {
		tmpl := caTemplate("Root")
		tmpl.IsCA = false
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		root := issue(t, tmpl, compositeKey(t), nil)
		leaf := issue(t, leafTemplate(), ecdsaKey(t), root)
		require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{root.cert}, time.Now()), errUntrusted)
	})
	t.Run("expired", func(t *testing.T) {
		root := issue(t, caTemplate("Root"), compositeKey(t), nil)
		leaf := issue(t, leafTemplate(), ecdsaKey(t), root)
		later := time.Now().Add(2 * time.Hour)
		require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{root.cert}, later), errUntrusted)
	})
	t.Run("unhandled critical extension", func(t *testing.T) {
		root := issue(t, caTemplate("Root"), compositeKey(t), nil)
		tmpl := leafTemplate()
		tmpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{5, 0}}}
		leaf := issue(t, tmpl, ecdsaKey(t), root)
		require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{root.cert}, time.Now()), errUntrusted)
	})
	t.Run("composite path length exceeded", func(t *testing.T) {
		tmpl := caTemplate("Root")
		tmpl.MaxPathLenZero = true
		root := issue(t, tmpl, compositeKey(t), nil)
		inter := issue(t, caTemplate("Intermediate"), compositeKey(t), root)
		leaf := issue(t, leafTemplate(), ecdsaKey(t), inter)
		require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{inter.cert, root.cert}, time.Now()), errUntrusted)
	})
	t.Run("classical path length exceeded below", func(t *testing.T) {
		tmpl := caTemplate("Root")
		tmpl.MaxPathLenZero = true
		root := issue(t, tmpl, ecdsaKey(t), nil)
		inter := issue(t, caTemplate("Intermediate"), compositeKey(t), root)
		leaf := issue(t, leafTemplate(), ecdsaKey(t), inter)
		require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{inter.cert}, time.Now()), errUntrusted)
	})
	t.Run("composite name constraints", func(t *testing.T) {
		tmpl := caTemplate("Root")
		tmpl.PermittedDNSDomains = []string{"example.com"}
		root := issue(t, tmpl, compositeKey(t), nil)
		leafTmpl := leafTemplate()
		leafTmpl.DNSNames = []string{"device.example.com"}
		leaf := issue(t, leafTmpl, ecdsaKey(t), root)
		require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{root.cert}, time.Now()), errUntrusted)
	})
	t.Run("classical name constraints above composite link", func(t *testing.T) {
		tmpl := caTemplate("Root")
		tmpl.PermittedDNSDomains = []string{"example.com"}
		root := issue(t, tmpl, ecdsaKey(t), nil)
		inter := issue(t, caTemplate("Intermediate"), compositeKey(t), root)
		leafTmpl := leafTemplate()
		leafTmpl.DNSNames = []string{"device.other.test"}
		leaf := issue(t, leafTmpl, ecdsaKey(t), inter)
		require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), []*x509.Certificate{inter.cert}, time.Now()), errUntrusted)
	})
}

// TestVerifyBoundsSearch keeps candidates that all certify each other from
// forcing an exponential search.
func TestVerifyBoundsSearch(t *testing.T) {
	root := issue(t, caTemplate("Root"), compositeKey(t), nil)
	loopKey := compositeKey(t)
	first := issue(t, caTemplate("Loop"), loopKey, nil)
	candidates := make([]*x509.Certificate, 1, 21)
	candidates[0] = first.cert
	for range 20 {
		candidates = append(candidates, issue(t, caTemplate("Loop"), loopKey, first).cert)
	}
	leaf := issue(t, leafTemplate(), ecdsaKey(t), first)
	require.ErrorIs(t, Verify(leaf.cert, pool(root.cert), candidates, time.Now()), errUntrusted)

	s := &search{
		candidates: candidates,
		opts:       x509.VerifyOptions{Roots: pool(root.cert), Intermediates: pool(candidates...), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, CurrentTime: time.Now()},
		checksLeft: maxSignatureChecks,
		upper:      make(map[string][][]*x509.Certificate),
		onPath:     make(map[string]bool),
	}
	require.False(t, s.trusted(leaf.cert, 0))
	require.Zero(t, s.checksLeft)
	require.Empty(t, s.onPath)
}
