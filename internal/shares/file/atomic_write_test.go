package file

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWriteTreatsPostPublicationTempCleanupFailureAsSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "share.enc")
	data := []byte("published-bytes")

	err := atomicWriteWithOperations(path, data, fileMode, atomicFileOperations{
		createTemp: os.CreateTemp,
		link:       os.Link,
		remove: func(string) error {
			return errors.New("simulated temp cleanup failure")
		},
	})
	if err != nil {
		t.Fatalf("atomicWriteWithOperations returned error after publication: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read published file: %v", err)
	}
	if string(got) != string(data) {
		t.Fatal("published bytes changed")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read publication directory: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected final file and one unrecognized temp, got %d entries", len(entries))
	}
	for _, entry := range entries {
		if entry.Name() == "share.enc" {
			continue
		}
		if !strings.HasPrefix(entry.Name(), ".share.enc.tmp-") {
			t.Fatalf("unexpected directory entry %q", entry.Name())
		}
	}
}

func TestAtomicWriteCleansTempAndFailsBeforePublication(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "share.enc")
	errLink := errors.New("simulated publication failure")

	err := atomicWriteWithOperations(path, []byte("published-bytes"), fileMode, atomicFileOperations{
		createTemp: os.CreateTemp,
		link: func(string, string) error {
			return errLink
		},
		remove: os.Remove,
	})
	if !errors.Is(err, errLink) {
		t.Fatalf("atomicWriteWithOperations error = %v, want %v", err, errLink)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read publication directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected failed publication cleanup, got %d entries", len(entries))
	}
}
