package preparams

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	kg "github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
)

func TestLegacyCacheOwnershipAndCleanup(t *testing.T) {
	// TEST ONLY — NEVER FUND. The Gob was emitted by the isolated old v1.5
	// executable, not serialized by the candidate library during this test.
	blob, err := os.ReadFile(filepath.Join("..", "..", "testdata", "legacy-preparams", "public-test-only-v1.gob"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	if hex.EncodeToString(sum[:]) != "5b539d6a5d10ec727a4943e2484ebdd0e9718208f8752201e06a6c109f16b987" {
		t.Fatal("legacy cache fixture changed")
	}
	source, err := os.ReadFile(filepath.Join("..", "..", "tools", "legacy-fixture", "preparams", "public-test-only-0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected kg.LocalPreParams
	if err = json.Unmarshal(source, &expected); err != nil {
		t.Fatal(err)
	}
	for _, terminal := range []string{"consume", "discard"} {
		t.Run(terminal, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			valid := filepath.Join(dir, "01-valid.gob")
			corrupt := filepath.Join(dir, "00-corrupt.gob")
			ignored := filepath.Join(dir, "keep.txt")
			for path, data := range map[string][]byte{valid: blob, corrupt: []byte("not a Gob"), ignored: []byte("keep")} {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := DefaultConfig()
			cfg.FileCacheEnabled = true
			cfg.FileCacheDir = dir
			cfg.TargetSize = 1
			cfg.MaxConcurrency = 1
			cfg.AutoRefillOnAcquire = false
			cfg.SyncFallbackOnEmpty = false
			newCachedPool := func() *Pool {
				// Preserve the real cache decoder/validator; suppress only expensive refill.
				p := newPoolForTest(testLogger(), cfg, func(ctx context.Context) (*kg.LocalPreParams, error) { <-ctx.Done(); return nil, ctx.Err() }, nil)
				if err := p.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				return p
			}
			p := newCachedPool()
			if p.Size() != 1 {
				t.Fatal("old cache was not loaded")
			}
			if _, err := os.Stat(corrupt); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("corrupt cache was not removed: %v", err)
			}
			if data, err := os.ReadFile(valid); err != nil || string(data) != string(blob) {
				t.Fatal("valid cache changed while loading")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := p.TryAcquire(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled acquire = %v", err)
			}
			if p.Size() != 1 {
				t.Fatal("canceled acquire consumed cached params")
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			// A canceled acquire/closed pool must leave the unconsumed file restartable.
			p = newCachedPool()
			defer func() { _ = p.Close() }()
			var wg sync.WaitGroup
			results := make(chan *kg.LocalPreParams, 16)
			errs := make(chan error, 16)
			for range 16 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					v, err := p.TryAcquire(context.Background())
					if err == nil {
						results <- v
					} else {
						errs <- err
					}
				}()
			}
			wg.Wait()
			close(results)
			close(errs)
			if len(results) != 1 || len(errs) != 15 {
				t.Fatalf("cache ownership winners=%d losers=%d", len(results), len(errs))
			}
			for err := range errs {
				if !errors.Is(err, ErrPoolEmpty) {
					t.Fatalf("losing acquire = %v", err)
				}
			}
			got := <-results
			if !reflect.DeepEqual(got, &expected) {
				t.Fatal("old Gob fields changed (including PaillierSK.P/Q and proof inputs)")
			}
			if _, err := os.Stat(valid); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("acquired cache file remains reusable: %v", err)
			}
			binding := NewServiceBinding()
			handle := NewHandle(binding, got)
			if terminal == "discard" {
				if err := handle.Discard(); err != nil {
					t.Fatal(err)
				}
				if _, err := Consume(binding, handle); !errors.Is(err, ErrPreParamsDiscarded) {
					t.Fatalf("discarded cache reused: %v", err)
				}
			} else {
				value, err := Consume(binding, handle)
				if err != nil || value != got {
					t.Fatalf("consume lost ownership: %v", err)
				}
				if _, err := Consume(binding, handle); !errors.Is(err, ErrPreParamsConsumed) {
					t.Fatalf("consumed cache reused: %v", err)
				}
			}
			if _, err := os.Stat(ignored); err != nil {
				t.Fatal("unrelated file was removed")
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			// No resurrection of consumed/discarded params at restart.
			p = newCachedPool()
			if p.Size() != 0 {
				t.Fatal("terminal cache params returned after restart")
			}
		})
	}
}
