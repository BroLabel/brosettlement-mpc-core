package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/BroLabel/brosettlement-mpc-core/internal/shares"
)

const fileMode os.FileMode = 0o600

type Store struct {
	cfg Config
}

type onDiskShare struct {
	SessionID                   string `json:"session_id"`
	KeyID                       string `json:"key_id"`
	LocalPartyID                string `json:"local_party_id"`
	OpaqueDescriptorFingerprint []byte `json:"opaque_descriptor_fingerprint"`
	Ciphertext                  []byte `json:"ciphertext"`
}

var (
	_ shares.ShareReader = (*Store)(nil)
	_ shares.ShareWriter = (*Store)(nil)
)

func NewStore(cfg Config) *Store {
	return &Store{cfg: cfg}
}

func (s *Store) SaveShare(ctx context.Context, in shares.SaveShareInput) error {
	if err := s.cfg.validate(); err != nil {
		return err
	}
	ciphertext, err := s.cfg.Cipher.Encrypt(ctx, in.CodecBlob)
	if err != nil {
		return fmt.Errorf("encrypt share: %w", err)
	}

	blob, err := json.Marshal(onDiskShare{
		SessionID:                   in.SessionID,
		KeyID:                       in.KeyID,
		LocalPartyID:                in.LocalPartyID,
		OpaqueDescriptorFingerprint: append([]byte(nil), in.OpaqueDescriptorFingerprint...),
		Ciphertext:                  ciphertext,
	})
	if err != nil {
		return fmt.Errorf("encode encrypted share: %w", err)
	}

	if err := atomicWrite(s.cfg.Path, blob, fileMode); err != nil {
		return fmt.Errorf("save encrypted share: %w", err)
	}
	return nil
}

func (s *Store) LoadShare(ctx context.Context, keyID string) (*shares.StoredShare, error) {
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
	if disk.KeyID != keyID {
		return nil, shares.ErrMetadataMismatch
	}

	plaintext, err := s.cfg.Cipher.Decrypt(ctx, disk.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt share: %w", err)
	}

	return &shares.StoredShare{
		Blob: plaintext,
	}, nil
}
