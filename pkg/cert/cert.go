package cert

import "github.com/danielkeho/crypto/pkg/algo"

type CertPool struct {
	Algo algo.Algo
}

func NewCertPool(algorithm string) CertPool {
	switch algorithm {
	case "ed25519":
		return CertPool{
			Algo: algo.ED25519Algo{},
		}
	case "ecdsa":
		return CertPool{
			Algo: algo.ECDSAAlgo{},
		}
	default:
		return CertPool{
			Algo: algo.RSAAlgo{},
		}
	}

}
