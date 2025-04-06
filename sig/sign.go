package sig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"log"
)

func CreateSignature(payload string, privateKey *rsa.PrivateKey) (string, error) {
	hashed := sha256.Sum256([]byte(payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		log.Println("CreateSignature: failed -", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}
