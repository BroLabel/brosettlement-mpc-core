package shares

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestCodecV2GoldenBytes(t *testing.T) {
	got, err := MarshalKeyMaterial(codecV2GoldenMaterial())
	if err != nil {
		t.Fatalf("MarshalKeyMaterial() error = %v", err)
	}
	want, err := readGoldenHex(codecCorpusFilePath("empty-share.hex"))
	if err != nil {
		t.Fatalf("read local codec-v2 golden vector: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("MarshalKeyMaterial() changed the codec-v2 golden bytes")
	}
}

func TestCodecV2GoldenRoundTrip(t *testing.T) {
	blob, err := readGoldenHex(codecCorpusFilePath("empty-share.hex"))
	if err != nil {
		t.Fatalf("read local codec-v2 golden vector: %v", err)
	}
	got, err := UnmarshalKeyMaterial(blob)
	if err != nil {
		t.Fatalf("UnmarshalKeyMaterial() error = %v", err)
	}
	if !reflect.DeepEqual(got, codecV2GoldenMaterial()) {
		t.Fatal("UnmarshalKeyMaterial() changed the codec-v2 golden material")
	}
}

func codecCorpusFilePath(name string) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate codec corpus test")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "mpc-2of3", "v1", "share-codec-v2", name)
}

func readGoldenHex(path string) ([]byte, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(encoded)))
}
