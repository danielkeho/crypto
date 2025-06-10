package algo

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

type ED25519Algo struct{}

func (c ED25519Algo) GenerateKeys() ([]byte, []byte, error) {

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	privateKeyPEMBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	privateKeyPEM := pem.EncodeToMemory(privateKeyPEMBlock)

	pub, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	publicKeySSH := ssh.MarshalAuthorizedKey(pub)

	return privateKeyPEM, publicKeySSH, nil
}

func (c ED25519Algo) CreatePrivateKeyAndSave(path string, n int) error {

	return nil
}
