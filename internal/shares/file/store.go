package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"brosettlement-mpc-signer/brosettlement-mpc-core/internal/shares"
)

const fileMode os.FileMode = 0o600

type Store struct {
	cfg Config
}

type onDiskShare struct {
	Ref        shares.KeyRef    `json:"ref"`
	Meta       shares.ShareMeta `json:"meta"`
	Ciphertext []byte           `json:"ciphertext"`
}

var (
	_ shares.Source = (*Store)(nil)
	_ shares.Sink   = (*Store)(nil)
)

func NewStore(cfg Config) *Store {
	return &Store{cfg: cfg}
}

func (s *Store) SaveShare(ctx context.Context, in shares.ShareToSave) error {
	if err := s.cfg.validate(); err != nil {
		return err
	}
	ciphertext, err := s.cfg.Cipher.Encrypt(ctx, in.Plaintext)
	if err != nil {
		return fmt.Errorf("encrypt share: %w", err)
	}

	blob, err := json.Marshal(onDiskShare{
		Ref:        in.Ref,
		Meta:       in.Meta,
		Ciphertext: ciphertext,
	})
	if err != nil {
		return fmt.Errorf("encode encrypted share: %w", err)
	}

	if err := atomicWrite(s.cfg.Path, blob, fileMode); err != nil {
		return fmt.Errorf("save encrypted share: %w", err)
	}
	return nil
}

func (s *Store) LoadShare(ctx context.Context, ref shares.KeyRef) (*shares.LoadedShare, error) {
	if err := s.cfg.validate(); err != nil {
		return nil, err
	}

	blob, err := os.ReadFile(s.cfg.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, shares.ErrShareNotFound
		}
		return nil, fmt.Errorf("read encrypted share: %w", err)
	}

	var disk onDiskShare
	if err := json.Unmarshal(blob, &disk); err != nil {
		return nil, fmt.Errorf("%w: decode encrypted share: %v", shares.ErrInvalidSharePayload, err)
	}
	if disk.Ref.KeyID != ref.KeyID || disk.Ref.OrgID != ref.OrgID || disk.Ref.Role != ref.Role {
		return nil, shares.ErrMetadataMismatch
	}

	plaintext, err := s.cfg.Cipher.Decrypt(ctx, disk.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt share: %w", err)
	}

	return &shares.LoadedShare{
		Ref:       disk.Ref,
		Plaintext: plaintext,
		Meta:      disk.Meta,
	}, nil
}
