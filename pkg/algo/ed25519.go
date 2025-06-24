package algo

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

type ED25519Algo struct{}

func CreateEd25519PrivateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

func Ed25519PrivateKeyToPEM(privateKey ed25519.PrivateKey) (*pem.Block, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}, nil
}

func PrivateKeyPemToEd25519(input []byte) (ed25519.PrivateKey, error) {
	privPem, _ := pem.Decode(input)
	if privPem == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	if privPem.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("expected PEM block type 'PRIVATE KEY', got %q", privPem.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(privPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse PKCS#8 private key: %v", err)
	}

	ed25519Key, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an Ed25519 private key")
	}

	return ed25519Key, nil
}

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

func (c ED25519Algo) CreatePrivateKeyAndSave(path string) error {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := pem.Encode(f, pemBlock); err != nil {
		return err
	}

	return nil
}

func (c ED25519Algo) PrivateKeyPemToAlgo(input []byte) (interface{}, error) {
	return PrivateKeyPemToEd25519(input)
}

func (c ED25519Algo) CreateCert(template *x509.Certificate, caKey interface{}, caCert *x509.Certificate) ([]byte, []byte, error) {
	var (
		derBytes []byte
		certOut  bytes.Buffer
		keyOut   bytes.Buffer
	)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if template.IsCA {
		derBytes, err = x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
		if err != nil {
			return nil, nil, err
		}
	} else {
		caKey = caKey.(ed25519.PrivateKey)
		derBytes, err = x509.CreateCertificate(rand.Reader, template, caCert, publicKey, caKey)
		if err != nil {
			return nil, nil, err
		}
	}

	if err = pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, err
	}

	pemBlock, err := Ed25519PrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, nil, err
	}
	if err = pem.Encode(&keyOut, pemBlock); err != nil {
		return nil, nil, err
	}

	return keyOut.Bytes(), certOut.Bytes(), nil
}
