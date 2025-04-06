package sig

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
)

func VerifySignature(signature string, payload string, publicKey *rsa.PublicKey) bool {
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	hashed := sha256.Sum256([]byte(payload))
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], sigBytes)
	return err == nil
}
