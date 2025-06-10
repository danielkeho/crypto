package algo

import "crypto/x509"

type Algo interface {
	GenerateKeys() ([]byte, []byte, error)
	CreatePrivateKeyAndSave(path string) error
	PrivateKeyPemToAlgo(input []byte) (interface{}, error)
	CreateCert(template *x509.Certificate, caKey interface{}, caCert *x509.Certificate) ([]byte, []byte, error)
}
