package algo

type Algo interface {
	GenerateKeys() ([]byte, []byte, error)
	CreatePrivateKeyAndSave(path string, n int) error
}
