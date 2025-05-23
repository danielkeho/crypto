package cmd

import (
	"fmt"
	"os"

	"github.com/danielkeho/crypto/pkg/cert"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

type Config struct {
	CACert *cert.CACert          `yaml:"caCert"`
	Cert   map[string]*cert.Cert `yaml:"certs"`
}

var certPool cert.CertPool
var algorithm string
var cfgFilePath string
var config Config

var rootCmd = &cobra.Command{
	Use:   "crypto",
	Short: "crypto is a command line tool for TLS, SSH, and certificate management.",
	Long: `crypto is a command line tool for cryptographic key and certificate management.

It supports:
  • Generation of private and public keys (RSA, ECDSA, Ed25519)
  • Creation of certificate authorities (CAs)
  • Signing of X.509 certificates and SSH keys
  • TLS and SSH key pair generation
  • Inspection of keys and certificates
  • Configuration via YAML files (e.g., cert.yml)

Examples:
  crypto key gen --type rsa --bits 2048
  crypto cert ca --config cert.yml
  crypto cert sign --csr cert.csr --ca ca.pem --key ca-key.pem
  crypto ssh keygen --type ed25519
`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&algorithm, "algo", "a", "", "algorithm (default is rsa)")
	rootCmd.PersistentFlags().StringVarP(&cfgFilePath, "config", "c", "", "config file (default is cert.yaml)")
}

func initConfig() {

	// config algo
	if algorithm == "" {
		algorithm = "rsa"
	}
	certPool = cert.NewCertPool(algorithm)

	// config cert
	if cfgFilePath == "" {
		cfgFilePath = "cert.yaml"
	}
	cfgFileBytes, err := os.ReadFile(cfgFilePath)
	if err != nil {
		fmt.Printf("Error while reading config file: %s\n", err)
		return
	}
	err = yaml.Unmarshal(cfgFileBytes, &config)
	if err != nil {
		fmt.Printf("Error while parsing config file: %s\n", err)
		return
	}
}
