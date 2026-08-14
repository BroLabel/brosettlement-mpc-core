package preparams

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type recordingCacheFS struct {
	cacheFS
	onCreateTemp func(string)
	onSyncFile   func(string)
	onLink       func(string, string)
	onRemove     func(string)
	onSyncDir    func(string)
	removeErr    error
	linkErr      error
	syncFileErr  error
	syncDirErr   func(string) error
}

func (f *recordingCacheFS) CreateTemp(dir, pattern string) (cacheFile, error) {
	file, err := f.cacheFS.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	if f.onCreateTemp != nil {
		f.onCreateTemp(file.Name())
	}
	return &recordingCacheFile{
		cacheFile: file,
		onSync: func() {
			if f.onSyncFile != nil {
				f.onSyncFile(file.Name())
			}
		},
		syncErr: f.syncFileErr,
	}, nil
}

func (f *recordingCacheFS) Link(oldPath, newPath string) error {
	if f.onLink != nil {
		f.onLink(oldPath, newPath)
	}
	if f.linkErr != nil {
		return f.linkErr
	}
	return f.cacheFS.Link(oldPath, newPath)
}

func (f *recordingCacheFS) Remove(path string) error {
	if f.onRemove != nil {
		f.onRemove(path)
	}
	if f.removeErr != nil {
		return f.removeErr
	}
	return f.cacheFS.Remove(path)
}

func (f *recordingCacheFS) SyncDir(path string) error {
	if f.onSyncDir != nil {
		f.onSyncDir(path)
	}
	if f.syncDirErr != nil {
		if err := f.syncDirErr(path); err != nil {
			return err
		}
	}
	return f.cacheFS.SyncDir(path)
}

type recordingCacheFile struct {
	cacheFile
	onSync  func()
	syncErr error
}

func (f *recordingCacheFile) Sync() error {
	if f.onSync != nil {
		f.onSync()
	}
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.cacheFile.Sync()
}

func TestDurableCachePublicationUsesCreateOnlyAndSyncOrdering(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "private-cache")
	if err := os.Mkdir(cacheDir, 0o700); err != nil {
		t.Fatalf("mkdir cache dir: %v", err)
	}
	var events []string
	fs := &recordingCacheFS{
		cacheFS: newOSCacheFS(),
		onCreateTemp: func(string) {
			events = append(events, "create-temp")
		},
		onSyncFile: func(string) {
			events = append(events, "file-sync")
		},
		onLink: func(string, string) {
			events = append(events, "publish-no-replace")
		},
		onRemove: func(path string) {
			if filepath.Ext(path) == ".tmp" {
				events = append(events, "remove-temp")
				return
			}
			events = append(events, "unexpected-remove")
		},
		onSyncDir: func(path string) {
			if path == cacheDir {
				events = append(events, "directory-sync")
			}
		},
	}
	pool := newPoolForTest(testLogger(), acquireTestConfig(cacheDir), nil,
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)
	pool.fs = fs

	path, err := pool.saveToCache(&ecdsakeygen.LocalPreParams{})
	if err != nil {
		t.Fatalf("saveToCache() error = %v", err)
	}
	if path == "" {
		t.Fatal("saveToCache() returned an empty path")
	}
	want := []string{"create-temp", "file-sync", "publish-no-replace", "remove-temp", "directory-sync"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestDurableCacheStartRejectsWeakDirectoryPermissions(t *testing.T) {
	cacheDir := t.TempDir()
	if err := os.Chmod(cacheDir, 0o750); err != nil {
		t.Fatalf("chmod cache dir: %v", err)
	}
	pool := newPoolForTest(testLogger(), acquireTestConfig(cacheDir),
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)

	err := pool.Start(context.Background())
	if !errors.Is(err, ErrCachePermissions) {
		t.Fatalf("Start() error = %v, want ErrCachePermissions", err)
	}
	if err := pool.Start(context.Background()); !errors.Is(err, ErrCachePermissions) {
		t.Fatalf("repeated Start() error = %v, want sticky ErrCachePermissions", err)
	}
	if pool.runCtx != nil {
		t.Fatal("disk-cache lifecycle remained started after capability failure")
	}
}

func TestDurableCacheStartRejectsCapabilityFailures(t *testing.T) {
	linkErr := errors.New("create-only publication unsupported")
	fileSyncErr := errors.New("file sync unsupported")
	dirSyncErr := errors.New("directory sync unsupported")

	tests := []struct {
		name string
		fs   func(cacheFS) cacheFS
		want error
	}{
		{
			name: "create-only publication",
			fs: func(base cacheFS) cacheFS {
				return &recordingCacheFS{cacheFS: base, linkErr: linkErr}
			},
			want: linkErr,
		},
		{
			name: "file sync",
			fs: func(base cacheFS) cacheFS {
				return &recordingCacheFS{cacheFS: base, syncFileErr: fileSyncErr}
			},
			want: fileSyncErr,
		},
		{
			name: "directory sync",
			fs: func(base cacheFS) cacheFS {
				return &recordingCacheFS{
					cacheFS: base,
					syncDirErr: func(string) error {
						return dirSyncErr
					},
				}
			},
			want: dirSyncErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := filepath.Join(t.TempDir(), "private-cache")
			pool := newPoolForTest(testLogger(), acquireTestConfig(cacheDir), nil,
				func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
			)
			pool.fs = tt.fs(newOSCacheFS())

			err := pool.Start(context.Background())
			if !errors.Is(err, tt.want) {
				t.Fatalf("Start() error = %v, want %v", err, tt.want)
			}
			if pool.runCtx != nil {
				t.Fatal("disk-cache lifecycle remained started after capability failure")
			}
		})
	}
}

func TestDurableCachePublicationFailureHasNoSilentMemoryFallback(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "private-cache")
	publicationReached := make(chan struct{})
	linkErr := errors.New("publication failed")
	pool := newPoolForTest(testLogger(), acquireTestConfig(cacheDir),
		func(context.Context) (*ecdsakeygen.LocalPreParams, error) {
			return &ecdsakeygen.LocalPreParams{}, nil
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)
	pool.fs = &failSecondLinkCacheFS{
		cacheFS: newOSCacheFS(),
		onSecond: func() {
			close(publicationReached)
		},
		err: linkErr,
	}
	defer func() { _ = pool.Close() }()

	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	select {
	case <-publicationReached:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for generated material publication")
	}
	if pool.Size() != 0 {
		t.Fatalf("pool size = %d, want no in-memory fallback after publication failure", pool.Size())
	}
	if snapshot := pool.Snapshot(); snapshot.GenerationsSuccess != 0 {
		t.Fatalf("GenerationsSuccess = %d, want 0", snapshot.GenerationsSuccess)
	}
}

type failSecondLinkCacheFS struct {
	cacheFS
	calls    atomic.Int32
	onSecond func()
	err      error
}

func (f *failSecondLinkCacheFS) Link(oldPath, newPath string) error {
	if f.calls.Add(1) == 2 {
		f.onSecond()
		return f.err
	}
	return f.cacheFS.Link(oldPath, newPath)
}

func TestDurableCacheLoadingRemovesMalformedEntriesAndIgnoresTemporaryFiles(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "private-cache")
	if err := os.Mkdir(cacheDir, 0o700); err != nil {
		t.Fatalf("mkdir cache dir: %v", err)
	}
	malformedPath := filepath.Join(cacheDir, "malformed.gob")
	temporaryPath := filepath.Join(cacheDir, ".preparams-stale.tmp")
	if err := os.WriteFile(malformedPath, []byte("not-a-gob"), 0o600); err != nil {
		t.Fatalf("write malformed entry: %v", err)
	}
	if err := os.WriteFile(temporaryPath, []byte("temporary"), 0o600); err != nil {
		t.Fatalf("write temporary entry: %v", err)
	}
	generatorStarted := make(chan struct{})
	pool := newPoolForTest(testLogger(), acquireTestConfig(cacheDir),
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			close(generatorStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)
	defer func() { _ = pool.Close() }()

	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := os.Stat(malformedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("malformed entry was not removed: %v", err)
	}
	if _, err := os.Stat(temporaryPath); err != nil {
		t.Fatalf("temporary entry should be ignored, stat error: %v", err)
	}
	if pool.Size() != 0 {
		t.Fatalf("pool size = %d, want malformed and temporary entries excluded", pool.Size())
	}
	select {
	case <-generatorStarted:
	case <-time.After(time.Second):
		t.Fatal("generation worker did not start")
	}
}
