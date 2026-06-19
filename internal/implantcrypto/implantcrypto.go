package implantcrypto

import "errors"

type CryptoManager struct{}

func NewCryptoManager() (*CryptoManager, error) {
	return nil, errors.New("implantcrypto not available in open-source build")
}
