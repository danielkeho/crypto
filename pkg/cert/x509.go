package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"time"
)

func (pool *CertPool) CreateCACert(ca *CACert, keyFilePath, caCertFilePath string) error {
	template := &x509.Certificate{
		SerialNumber: ca.Serial,
		Subject: pkix.Name{
			Country:            removeEmptyString([]string{ca.Subject.Country}),
			Organization:       removeEmptyString([]string{ca.Subject.Organization}),
			OrganizationalUnit: removeEmptyString([]string{ca.Subject.OrganizationalUnit}),
			Locality:           removeEmptyString([]string{ca.Subject.Locality}),
			Province:           removeEmptyString([]string{ca.Subject.Province}),
			StreetAddress:      removeEmptyString([]string{ca.Subject.StreetAddress}),
			PostalCode:         removeEmptyString([]string{ca.Subject.PostalCode}),
			CommonName:         ca.Subject.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(ca.ValidForYears, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	keyBytes, certBytes, err := pool.Algo.CreateCert(template, nil, nil)
	if err != nil {
		return err
	}

	if err := os.WriteFile(keyFilePath, keyBytes, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(caCertFilePath, certBytes, 0644); err != nil {
		return err
	}

	return nil
}

func (pool *CertPool) CreateCert(cert *Cert, caKey []byte, caCert []byte, keyFilePath, certFilePath string) error {
	template := &x509.Certificate{
		SerialNumber: cert.Serial,
		Subject: pkix.Name{
			Country:            removeEmptyString([]string{cert.Subject.Country}),
			Organization:       removeEmptyString([]string{cert.Subject.Organization}),
			OrganizationalUnit: removeEmptyString([]string{cert.Subject.OrganizationalUnit}),
			Locality:           removeEmptyString([]string{cert.Subject.Locality}),
			Province:           removeEmptyString([]string{cert.Subject.Province}),
			StreetAddress:      removeEmptyString([]string{cert.Subject.StreetAddress}),
			PostalCode:         removeEmptyString([]string{cert.Subject.PostalCode}),
			CommonName:         cert.Subject.CommonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(cert.ValidForYears, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		DNSNames:    removeEmptyString(cert.DNSNames),
	}

	caKeyParsed, err := pool.Algo.PrivateKeyPemToAlgo(caKey)
	if err != nil {
		return err
	}
	caCertParsed, err := PemToX509(caCert)
	if err != nil {
		return err
	}

	keyBytes, certBytes, err := pool.Algo.CreateCert(template, caKeyParsed, caCertParsed)
	if err != nil {
		return err
	}

	if err := os.WriteFile(keyFilePath, keyBytes, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(certFilePath, certBytes, 0644); err != nil {
		return err
	}

	return nil
}

func removeEmptyString(input []string) []string {
	if len(input) == 1 && input[0] == "" {
		return []string{}
	}
	return input
}
