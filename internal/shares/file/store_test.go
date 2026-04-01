package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"brosettlement-mpc-signer/brosettlement-mpc-core/internal/shares"
)

func TestFileStoreSavesAndLoadsEncryptedShare(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "share-b.enc")
	store := NewStore(Config{
		Path:   path,
		Cipher: fakeCipher{},
	})

	err := store.SaveShare(context.Background(), shares.ShareToSave{
		Ref:       shares.KeyRef{KeyID: "key_1", OrgID: "org_1"},
		Plaintext: []byte("secret"),
	})
	if err != nil {
		t.Fatalf("save share: %v", err)
	}

	out, err := store.LoadShare(context.Background(), shares.KeyRef{KeyID: "key_1", OrgID: "org_1"})
	if err != nil {
		t.Fatalf("load share: %v", err)
	}
	if string(out.Plaintext) != "secret" {
		t.Fatalf("plaintext mismatch: got=%q", string(out.Plaintext))
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(onDisk) == "secret" {
		t.Fatalf("plaintext leaked to disk")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("invalid file mode: got=%#o", info.Mode().Perm())
	}
}

type fakeCipher struct{}

func (fakeCipher) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	for i := range plaintext {
		out[i] = plaintext[i] ^ 0xAA
	}
	return out, nil
}

func (fakeCipher) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	out := make([]byte, len(ciphertext))
	for i := range ciphertext {
		out[i] = ciphertext[i] ^ 0xAA
	}
	return out, nil
}
