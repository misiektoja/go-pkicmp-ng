package pkicmp_test

import (
	"crypto/x509/pkix"
	"fmt"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

func ExampleNewPKIMessage() {
	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{
		Sender:    pkicmp.NewDirectoryName(pkix.Name{CommonName: "client"}.ToRDNSequence()),
		Recipient: pkicmp.NewDirectoryName(pkix.Name{CommonName: "ca"}.ToRDNSequence()),
	})

	fmt.Println("Body type:", msg.Body.Type == pkicmp.BodyTypePKIConf)
	fmt.Println("Sender set:", len(msg.Header.Sender.DirectoryName) > 0)
	fmt.Println("Recipient set:", len(msg.Header.Recipient.DirectoryName) > 0)
	// Output:
	// Body type: true
	// Sender set: true
	// Recipient set: true
}

func ExamplePKIMessage_ProtectWithMAC() {
	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{
		Sender:    pkicmp.NewDirectoryName(pkix.Name{CommonName: "client"}.ToRDNSequence()),
		Recipient: pkicmp.NewDirectoryName(pkix.Name{CommonName: "ca"}.ToRDNSequence()),
	})

	err := msg.ProtectWithMAC([]byte("my-shared-secret"))
	fmt.Println("Error:", err)
	fmt.Println("Has protection:", len(msg.Protection) > 0)
	fmt.Println("Has protectionAlg:", msg.Header.ProtectionAlg != nil)
	// Output:
	// Error: <nil>
	// Has protection: true
	// Has protectionAlg: true
}

func ExamplePKIMessage_Verify() {
	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{
		Sender:    pkicmp.NewDirectoryName(pkix.Name{CommonName: "client"}.ToRDNSequence()),
		Recipient: pkicmp.NewDirectoryName(pkix.Name{CommonName: "ca"}.ToRDNSequence()),
	})

	secret := []byte("my-shared-secret")
	_ = msg.ProtectWithMAC(secret)

	creds, _ := pkicmp.NewMACCredentials(secret)
	result, err := msg.Verify(pkicmp.VerifyOptions{Credentials: creds})
	fmt.Println("Error:", err)
	fmt.Println("MAC verified:", result.MACVerified)
	// Output:
	// Error: <nil>
	// MAC verified: true
}

func ExampleParsePKIMessage() {
	// Create and marshal a message.
	body := pkicmp.NewPKIConfBody()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{
		Sender:    pkicmp.NewDirectoryName(pkix.Name{CommonName: "client"}.ToRDNSequence()),
		Recipient: pkicmp.NewDirectoryName(pkix.Name{CommonName: "ca"}.ToRDNSequence()),
	})

	der, _ := msg.MarshalBinary()

	// Parse the DER-encoded message.
	parsed, err := pkicmp.ParsePKIMessage(der)
	fmt.Println("Error:", err)
	fmt.Println("Body type matches:", parsed.Body.Type == pkicmp.BodyTypePKIConf)
	fmt.Println("DER length > 0:", len(der) > 0)
	// Output:
	// Error: <nil>
	// Body type matches: true
	// DER length > 0: true
}
