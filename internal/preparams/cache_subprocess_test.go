package preparams

import (
	"context"
	"encoding/gob"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

const (
	cacheCrashHelperEnv = "PREPARAMS_CACHE_CRASH_HELPER"
	cacheCrashDirEnv    = "PREPARAMS_CACHE_CRASH_DIR"
	cacheCrashPointEnv  = "PREPARAMS_CACHE_CRASH_POINT"
	cacheCrashEntryName = "fake-crash-entry.gob"
)

func TestCacheCrashBoundariesControlRestartReuse(t *testing.T) {
	tests := []struct {
		name           string
		crashPoint     string
		wantReloadSize int
	}{
		{name: "before unlink", crashPoint: "before-unlink", wantReloadSize: 1},
		{name: "after unlink before directory sync", crashPoint: "after-unlink", wantReloadSize: 0},
		{name: "after directory sync before return", crashPoint: "after-sync", wantReloadSize: 0},
		{name: "after handle return", crashPoint: "after-return", wantReloadSize: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := filepath.Join(t.TempDir(), "private-cache")
			if err := os.Mkdir(cacheDir, 0o700); err != nil {
				t.Fatalf("mkdir cache dir: %v", err)
			}
			writeFakeCrashCacheEntry(t, filepath.Join(cacheDir, cacheCrashEntryName))

			readyRead, readyWrite, err := os.Pipe()
			if err != nil {
				t.Fatalf("create ready pipe: %v", err)
			}
			defer func() { _ = readyRead.Close() }()
			releaseRead, releaseWrite, err := os.Pipe()
			if err != nil {
				t.Fatalf("create release pipe: %v", err)
			}
			defer func() { _ = releaseWrite.Close() }()

			cmd := exec.Command(os.Args[0], "-test.run=^TestCacheCrashHelperProcess$")
			cmd.Env = append(os.Environ(),
				cacheCrashHelperEnv+"=1",
				cacheCrashDirEnv+"="+cacheDir,
				cacheCrashPointEnv+"="+tt.crashPoint,
			)
			cmd.ExtraFiles = []*os.File{readyWrite, releaseRead}
			if err := cmd.Start(); err != nil {
				t.Fatalf("start crash helper: %v", err)
			}
			_ = readyWrite.Close()
			_ = releaseRead.Close()

			readyResult := make(chan error, 1)
			go func() {
				var signal [1]byte
				_, err := io.ReadFull(readyRead, signal[:])
				readyResult <- err
			}()
			select {
			case err := <-readyResult:
				if err != nil {
					killAndWaitHelper(t, cmd)
					t.Fatalf("wait for crash barrier: %v", err)
				}
			case <-time.After(3 * time.Second):
				killAndWaitHelper(t, cmd)
				t.Fatal("timed out waiting for helper crash barrier")
			}

			killAndWaitHelper(t, cmd)
			assertCrashRestartSize(t, cacheDir, tt.wantReloadSize)
		})
	}
}

func TestCacheCrashHelperProcess(t *testing.T) {
	if os.Getenv(cacheCrashHelperEnv) != "1" {
		t.Skip("helper process only")
	}
	cacheDir := os.Getenv(cacheCrashDirEnv)
	crashPoint := os.Getenv(cacheCrashPointEnv)
	targetPath := filepath.Join(cacheDir, cacheCrashEntryName)
	ready := os.NewFile(3, "cache-crash-ready")
	release := os.NewFile(4, "cache-crash-release")
	if ready == nil || release == nil {
		t.Fatal("helper barrier pipes are unavailable")
	}
	defer func() { _ = ready.Close() }()
	defer func() { _ = release.Close() }()

	barrier := func() {
		if _, err := ready.Write([]byte{1}); err != nil {
			t.Fatalf("signal crash barrier: %v", err)
		}
		var signal [1]byte
		if _, err := io.ReadFull(release, signal[:]); err != nil {
			t.Fatalf("wait at crash barrier: %v", err)
		}
	}

	fs := &crashBarrierCacheFS{
		cacheFS:    newOSCacheFS(),
		targetPath: targetPath,
		crashPoint: crashPoint,
		barrier:    barrier,
	}
	pool := newPoolForTest(testLogger(), acquireTestConfig(cacheDir),
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)
	pool.fs = fs
	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	got, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if got == nil {
		t.Fatal("Acquire() returned nil")
	}
	if crashPoint == "after-return" {
		barrier()
	}
	t.Fatalf("helper passed crash barrier %q without termination", crashPoint)
}

type crashBarrierCacheFS struct {
	cacheFS
	targetPath string
	crashPoint string
	barrier    func()
	removed    atomic.Bool
}

func (f *crashBarrierCacheFS) Remove(path string) error {
	if path != f.targetPath {
		return f.cacheFS.Remove(path)
	}
	if f.crashPoint == "before-unlink" {
		f.barrier()
	}
	if err := f.cacheFS.Remove(path); err != nil {
		return err
	}
	f.removed.Store(true)
	if f.crashPoint == "after-unlink" {
		f.barrier()
	}
	return nil
}

func (f *crashBarrierCacheFS) SyncDir(path string) error {
	if err := f.cacheFS.SyncDir(path); err != nil {
		return err
	}
	if f.removed.Load() && f.crashPoint == "after-sync" {
		f.barrier()
	}
	return nil
}

func writeFakeCrashCacheEntry(t *testing.T, path string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create fake cache entry: %v", err)
	}
	if err := gob.NewEncoder(file).Encode(&ecdsakeygen.LocalPreParams{}); err != nil {
		_ = file.Close()
		t.Fatalf("encode fake cache entry: %v", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatalf("sync fake cache entry: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close fake cache entry: %v", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		t.Fatalf("open fake cache directory: %v", err)
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		t.Fatalf("sync fake cache directory: %v", err)
	}
	if err := dir.Close(); err != nil {
		t.Fatalf("close fake cache directory: %v", err)
	}
}

func killAndWaitHelper(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Fatalf("kill crash helper: %v", err)
		}
	}
	waitResult := make(chan error, 1)
	go func() {
		waitResult <- cmd.Wait()
	}()
	select {
	case <-waitResult:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for crash helper termination")
	}
}

func assertCrashRestartSize(t *testing.T, cacheDir string, want int) {
	t.Helper()
	pool := newPoolForTest(testLogger(), acquireTestConfig(cacheDir),
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)
	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("restart Start() error = %v", err)
	}
	if got := pool.Size(); got != want {
		_ = pool.Close()
		t.Fatalf("restart pool size = %d, want %d", got, want)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("restart Close() error = %v", err)
	}
}
