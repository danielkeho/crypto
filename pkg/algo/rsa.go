package algo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

type RSAAlgo struct{}

func CreateRSAPrivateKey(n int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, n)
}

func RSAPrivateKeyToPEM(privateKey *rsa.PrivateKey) *pem.Block {
	return &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
}

func PrivateKeyPemToRSA(input []byte) (*rsa.PrivateKey, error) {
	var parsedKey *rsa.PrivateKey
	var err error

	privPem, _ := pem.Decode(input)

	if privPem.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("RSA private key is of the wrong type: %s", privPem.Type)
	}

	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes); err != nil {
		return nil, fmt.Errorf("unable to parse RSA private key: %v", err)
	}

	return parsedKey, nil
}

func (c RSAAlgo) GenerateKeys() ([]byte, []byte, error) {
	privateKey, err := CreateRSAPrivateKey(4096)
	if err != nil {
		return nil, nil, err
	}

	privateKeyPEM := RSAPrivateKeyToPEM(privateKey)

	pubKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(privateKeyPEM), ssh.MarshalAuthorizedKey(pubKey), nil
}

func (c RSAAlgo) CreatePrivateKeyAndSave(path string, n int) error {
	privateKey, err := CreateRSAPrivateKey(n)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, RSAPrivateKeyToPEM(privateKey)); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}
