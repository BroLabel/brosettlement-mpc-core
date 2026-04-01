package file

import (
	"errors"

	"brosettlement-mpc-signer/brosettlement-mpc-core/internal/shares"
)

var (
	ErrInvalidConfig = errors.New("invalid file share store config")
)

type Config struct {
	Path   string
	Cipher shares.Cipher
}

func (c Config) validate() error {
	if c.Path == "" || c.Cipher == nil {
		return ErrInvalidConfig
	}
	return nil
}
