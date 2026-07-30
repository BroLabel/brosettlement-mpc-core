package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/BroLabel/brosettlement-mpc-core/internal/shares"
)

func TestFileStoreSavesAndLoadsEncryptedShare(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "share-b.enc")
	store := NewStore(Config{
		Path:   path,
		Cipher: fakeCipher{},
	})

	err := store.SaveShare(context.Background(), shares.SaveShareInput{
		SessionID:                   "session_1",
		KeyID:                       "key_1",
		LocalPartyID:                "party_b",
		OpaqueDescriptorFingerprint: []byte("opaque-fingerprint"),
		CodecBlob:                   []byte("codec-blob"),
	})
	if err != nil {
		t.Fatalf("save share: %v", err)
	}

	out, err := store.LoadShare(context.Background(), "key_1")
	if err != nil {
		t.Fatalf("load share: %v", err)
	}
	if string(out.Blob) != "codec-blob" {
		t.Fatalf("codec blob mismatch: got=%q", string(out.Blob))
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(onDisk) == "codec-blob" {
		t.Fatalf("codec blob leaked to disk")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("invalid file mode: got=%#o", info.Mode().Perm())
	}
}

func TestFileStoreDoesNotRewritePublishedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "share-b.enc")
	store := NewStore(Config{
		Path:   path,
		Cipher: fakeCipher{},
	})
	ctx := context.Background()
	first := shares.SaveShareInput{
		SessionID:    "session_1",
		KeyID:        "key_1",
		LocalPartyID: "party_b",
		CodecBlob:    []byte("first-publication"),
	}
	if err := store.SaveShare(ctx, first); err != nil {
		t.Fatalf("save first publication: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read first publication: %v", err)
	}

	if err := store.SaveShare(ctx, shares.SaveShareInput{
		SessionID:    first.SessionID,
		KeyID:        first.KeyID,
		LocalPartyID: first.LocalPartyID,
		CodecBlob:    []byte("replacement-publication"),
	}); err == nil {
		t.Fatal("expected second publication to be rejected")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read retained publication: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("published bytes were rewritten")
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
