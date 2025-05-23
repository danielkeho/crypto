package algo

type Algo interface {
	GenerateKeys() ([]byte, []byte, error)
	CreatePrivateKeyAndSave(path string, n int) error
}

type RSAAlgo struct {
}
type ECDSAAlgo struct {
}
type ED25519Algo struct {
}
