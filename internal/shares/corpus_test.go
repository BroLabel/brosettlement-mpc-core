package shares

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type codecCorpusManifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	Corpus        string            `json:"corpus"`
	Files         []codecCorpusFile `json:"files"`
}

type codecCorpusFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

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

func TestCodecV2CorpusManifest(t *testing.T) {
	if err := validateCodecCorpus(codecCorpusRoot()); err != nil {
		t.Fatalf("local codec-v2 corpus validation failed: %v", err)
	}
}

func TestCodecCorpusValidationRejectsMissingUnexpectedAndDivergentFiles(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, root string)
	}{
		{
			name: "missing expected file",
			setup: func(t *testing.T, root string) {
				writeCorpusManifest(t, root, codecCorpusFile{Path: "share-codec-v2/vector.hex", Size: 1, SHA256: hashHex([]byte{1})})
			},
		},
		{
			name: "unexpected file",
			setup: func(t *testing.T, root string) {
				writeCorpusFile(t, root, "share-codec-v2/vector.hex", []byte{1})
				writeCorpusFile(t, root, "share-codec-v2/unexpected.hex", []byte{2})
				writeCorpusManifest(t, root, codecCorpusFile{Path: "share-codec-v2/vector.hex", Size: 1, SHA256: hashHex([]byte{1})})
			},
		},
		{
			name: "manifest divergence",
			setup: func(t *testing.T, root string) {
				writeCorpusFile(t, root, "share-codec-v2/vector.hex", []byte{1})
				writeCorpusManifest(t, root, codecCorpusFile{Path: "share-codec-v2/vector.hex", Size: 2, SHA256: hashHex([]byte{2})})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			tt.setup(t, root)
			if err := validateCodecCorpus(root); err == nil {
				t.Fatal("validateCodecCorpus() error = nil, want validation failure")
			}
		})
	}
}

func TestCodecCorpusValidationRejectsUnknownDuplicateAndNonCanonicalManifest(t *testing.T) {
	validFile := codecCorpusFile{Path: "share-codec-v2/vector.hex", Size: 1, SHA256: hashHex([]byte{1})}
	validManifest := `{"schemaVersion":1,"corpus":"mpc-core/share-codec-v2","files":[{"path":"share-codec-v2/vector.hex","size":1,"sha256":"` + validFile.SHA256 + `"}]}`
	tests := []struct {
		name     string
		manifest string
	}{
		{
			name:     "unknown field",
			manifest: validManifest[:len(validManifest)-1] + `,"unexpected":true}`,
		},
		{
			name:     "duplicate field",
			manifest: `{"schemaVersion":1,"schemaVersion":1,"corpus":"mpc-core/share-codec-v2","files":[{"path":"share-codec-v2/vector.hex","size":1,"sha256":"` + validFile.SHA256 + `"}]}`,
		},
		{
			name:     "non-canonical bytes",
			manifest: validManifest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeCorpusFile(t, root, validFile.Path, []byte{1})
			if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(tt.manifest), 0o600); err != nil {
				t.Fatalf("write manifest: %v", err)
			}
			if err := validateCodecCorpus(root); err == nil {
				t.Fatal("validateCodecCorpus() error = nil, want strict manifest validation failure")
			}
		})
	}
}

func codecCorpusRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate codec corpus test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "mpc-2of3", "v1"))
}

func codecCorpusFilePath(name string) string {
	return filepath.Join(codecCorpusRoot(), "share-codec-v2", name)
}

func readGoldenHex(path string) ([]byte, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(encoded)))
}

func validateCodecCorpus(root string) error {
	manifestBlob, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := decodeCodecCorpusManifest(manifestBlob)
	if err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	if manifest.SchemaVersion != 1 || manifest.Corpus != "mpc-core/share-codec-v2" {
		return errors.New("unexpected local corpus identity")
	}

	expected := make(map[string]codecCorpusFile, len(manifest.Files))
	for _, file := range manifest.Files {
		if !filepath.IsLocal(file.Path) || filepath.Ext(file.Path) != ".hex" {
			return fmt.Errorf("invalid corpus path %q", file.Path)
		}
		if _, exists := expected[file.Path]; exists {
			return fmt.Errorf("duplicate manifest file %q", file.Path)
		}
		expected[file.Path] = file
	}
	if len(expected) == 0 {
		return errors.New("empty corpus manifest")
	}

	actual := make(map[string]struct{})
	if err := filepath.WalkDir(filepath.Join(root, "share-codec-v2"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		actual[filepath.ToSlash(relative)] = struct{}{}
		return nil
	}); err != nil {
		return fmt.Errorf("walk local corpus: %w", err)
	}

	for path, expectedFile := range expected {
		if _, exists := actual[path]; !exists {
			return fmt.Errorf("missing corpus file %q", path)
		}
		blob, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			return fmt.Errorf("read corpus file %q: %w", path, err)
		}
		if int64(len(blob)) != expectedFile.Size {
			return fmt.Errorf("corpus file %q size mismatch", path)
		}
		if hashHex(blob) != expectedFile.SHA256 {
			return fmt.Errorf("corpus file %q digest mismatch", path)
		}
	}
	for path := range actual {
		if _, exists := expected[path]; !exists {
			return fmt.Errorf("unexpected corpus file %q", path)
		}
	}
	return nil
}

func writeCorpusManifest(t *testing.T, root string, files ...codecCorpusFile) {
	t.Helper()
	manifest := codecCorpusManifest{SchemaVersion: 1, Corpus: "mpc-core/share-codec-v2", Files: files}
	blob, err := canonicalCodecCorpusManifest(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), blob, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func writeCorpusFile(t *testing.T, root, relative string, blob []byte) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create corpus directory: %v", err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write corpus file: %v", err)
	}
}

func hashHex(blob []byte) string {
	digest := sha256.Sum256(blob)
	return hex.EncodeToString(digest[:])
}

func decodeCodecCorpusManifest(blob []byte) (codecCorpusManifest, error) {
	if err := validateCodecCorpusManifestJSON(blob); err != nil {
		return codecCorpusManifest{}, err
	}

	decoder := json.NewDecoder(bytes.NewReader(blob))
	decoder.DisallowUnknownFields()
	var manifest codecCorpusManifest
	if err := decoder.Decode(&manifest); err != nil {
		return codecCorpusManifest{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return codecCorpusManifest{}, err
	}
	canonical, err := canonicalCodecCorpusManifest(manifest)
	if err != nil {
		return codecCorpusManifest{}, err
	}
	if !bytes.Equal(blob, canonical) {
		return codecCorpusManifest{}, errors.New("manifest is not canonical")
	}
	return manifest, nil
}

func canonicalCodecCorpusManifest(manifest codecCorpusManifest) ([]byte, error) {
	blob, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(blob, '\n'), nil
}

func validateCodecCorpusManifestJSON(blob []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(blob))
	if err := validateCodecCorpusManifestObject(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func validateCodecCorpusManifestObject(decoder *json.Decoder) error {
	if err := requireJSONDelimiter(decoder, '{'); err != nil {
		return err
	}
	seen := map[string]bool{}
	for decoder.More() {
		name, err := requireJSONStringToken(decoder)
		if err != nil {
			return err
		}
		if seen[name] {
			return fmt.Errorf("duplicate manifest field %q", name)
		}
		seen[name] = true
		switch name {
		case "schemaVersion", "corpus":
			if err := discardJSONValue(decoder); err != nil {
				return err
			}
		case "files":
			if err := validateCodecCorpusFiles(decoder); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown manifest field %q", name)
		}
	}
	return requireJSONDelimiter(decoder, '}')
}

func validateCodecCorpusFiles(decoder *json.Decoder) error {
	if err := requireJSONDelimiter(decoder, '['); err != nil {
		return err
	}
	for decoder.More() {
		if err := validateCodecCorpusFile(decoder); err != nil {
			return err
		}
	}
	return requireJSONDelimiter(decoder, ']')
}

func validateCodecCorpusFile(decoder *json.Decoder) error {
	if err := requireJSONDelimiter(decoder, '{'); err != nil {
		return err
	}
	seen := map[string]bool{}
	for decoder.More() {
		name, err := requireJSONStringToken(decoder)
		if err != nil {
			return err
		}
		if seen[name] {
			return fmt.Errorf("duplicate manifest file field %q", name)
		}
		seen[name] = true
		switch name {
		case "path", "size", "sha256":
			if err := discardJSONValue(decoder); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown manifest file field %q", name)
		}
	}
	return requireJSONDelimiter(decoder, '}')
}

func requireJSONStringToken(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	value, ok := token.(string)
	if !ok {
		return "", errors.New("manifest object key is not a string")
	}
	return value, nil
}

func requireJSONDelimiter(decoder *json.Decoder, want rune) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || rune(delimiter) != want {
		return fmt.Errorf("expected JSON delimiter %q", want)
	}
	return nil
}

func discardJSONValue(decoder *json.Decoder) error {
	var value json.RawMessage
	return decoder.Decode(&value)
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("unexpected JSON value after manifest")
		}
		return err
	}
	return nil
}

func TestCodecCorpusManifestFileListIsStable(t *testing.T) {
	manifestBlob, err := os.ReadFile(filepath.Join(codecCorpusRoot(), "manifest.json"))
	if err != nil {
		t.Fatalf("read local manifest: %v", err)
	}
	manifest, err := decodeCodecCorpusManifest(manifestBlob)
	if err != nil {
		t.Fatalf("decode local manifest: %v", err)
	}
	paths := make([]string, 0, len(manifest.Files))
	for _, file := range manifest.Files {
		paths = append(paths, file.Path)
	}
	if !sort.StringsAreSorted(paths) {
		t.Fatal("local corpus manifest files are not sorted")
	}
}
