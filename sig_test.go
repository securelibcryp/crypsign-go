package sig_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/securelibcryp/crypsign-go/sig"
)

func TestCreateAndVerifySignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload := "this is a secure message"
	signature, err := sig.CreateSignature(payload, privateKey)
	if err != nil {
		t.Errorf("Signature creation failed: %v", err)
	}

	if !sig.VerifySignature(signature, payload, publicKey) {
		t.Error("Signature verification failed")
	}
}
