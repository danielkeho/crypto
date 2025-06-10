package algo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

type ECDSAAlgo struct{}

func CreateECDSAPrivateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func ECDSAPrivateKeyToPEM(privateKey *ecdsa.PrivateKey) (*pem.Block, error) {
	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}, nil
}

func PrivateKeyPemToECDSA(input []byte) (*ecdsa.PrivateKey, error) {
	privPem, _ := pem.Decode(input)
	if privPem == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	if privPem.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("ECDSA private key is of the wrong type: %s", privPem.Type)
	}

	parsedKey, err := x509.ParseECPrivateKey(privPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse ECDSA private key: %v", err)
	}

	return parsedKey, nil
}

func (c ECDSAAlgo) GenerateKeys() ([]byte, []byte, error) {
	// Generate ECDSA private key using P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})

	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	publicKeySSH := ssh.MarshalAuthorizedKey(pub)

	return privateKeyPEM, publicKeySSH, nil
}

// CreatePrivateKeyAndSave generates an ECDSA private key and saves it to the given path.
func (c ECDSAAlgo) CreatePrivateKeyAndSave(path string) error {
	privateKey, err := CreateECDSAPrivateKey(elliptic.P256())
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	pemBlock, err := ECDSAPrivateKeyToPEM(privateKey)
	if err != nil {
		return err
	}

	if err := pem.Encode(f, pemBlock); err != nil {
		return err
	}

	return nil
}
