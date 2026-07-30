package preparams

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

var (
	ErrCachePermissions       = errors.New("preparams cache directory is not private")
	ErrCachePathRequired      = errors.New("file-backed preparams item has no cache path")
	ErrInvalidCachedPreParams = errors.New("cached preparams failed validation")
)

type cacheFile interface {
	io.Reader
	io.Writer
	Name() string
	Sync() error
	Close() error
}

type cacheFS interface {
	MkdirAll(path string, perm os.FileMode) error
	Stat(path string) (os.FileInfo, error)
	ReadDir(path string) ([]os.DirEntry, error)
	Open(path string) (cacheFile, error)
	CreateTemp(dir, pattern string) (cacheFile, error)
	Link(oldPath, newPath string) error
	Remove(path string) error
	SyncDir(path string) error
}

type osCacheFS struct{}

func newOSCacheFS() cacheFS {
	return osCacheFS{}
}

func (osCacheFS) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (osCacheFS) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func (osCacheFS) ReadDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}

func (osCacheFS) Open(path string) (cacheFile, error) {
	// #nosec G304 -- callers constrain cache paths beneath the configured directory.
	return os.Open(path)
}

func (osCacheFS) CreateTemp(dir, pattern string) (cacheFile, error) {
	return os.CreateTemp(dir, pattern)
}

func (osCacheFS) Link(oldPath, newPath string) error {
	return os.Link(oldPath, newPath)
}

func (osCacheFS) Remove(path string) error {
	return os.Remove(path)
}

func (osCacheFS) SyncDir(path string) error {
	// #nosec G304 -- path is the configured cache directory.
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func ensurePrivateCacheDir(fs cacheFS, dir string) error {
	if err := fs.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create preparams cache directory: %w", err)
	}
	info, err := fs.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat preparams cache directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: mode=%#o", ErrCachePermissions, info.Mode().Perm())
	}
	return nil
}

func validateCacheCapabilities(fs cacheFS, dir string) error {
	probePath := filepath.Join(dir, ".capability-"+uuid.NewString())
	if err := publishCacheFile(fs, dir, probePath, func(writer io.Writer) error {
		_, err := io.WriteString(writer, "preparams-cache-capability-v1")
		return err
	}); err != nil {
		return fmt.Errorf("validate preparams cache publication: %w", err)
	}
	if err := fs.Remove(probePath); err != nil {
		return fmt.Errorf("validate preparams cache unlink: %w", err)
	}
	if err := fs.SyncDir(dir); err != nil {
		return fmt.Errorf("validate preparams cache unlink durability: %w", err)
	}
	return nil
}

func publishCacheFile(fs cacheFS, dir, finalPath string, write func(io.Writer) error) (err error) {
	temp, err := fs.CreateTemp(dir, ".preparams-*.tmp")
	if err != nil {
		return fmt.Errorf("create preparams cache temporary file: %w", err)
	}
	tempPath := temp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temp.Close()
		}
		if tempPath != "" {
			_ = fs.Remove(tempPath)
		}
	}()

	if err := write(temp); err != nil {
		return fmt.Errorf("write preparams cache temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync preparams cache temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close preparams cache temporary file: %w", err)
	}
	closed = true
	if err := fs.Link(tempPath, finalPath); err != nil {
		return fmt.Errorf("publish preparams cache file without replacement: %w", err)
	}
	if err := fs.Remove(tempPath); err != nil {
		return fmt.Errorf("remove preparams cache temporary file: %w", err)
	}
	tempPath = ""
	if err := fs.SyncDir(dir); err != nil {
		return fmt.Errorf("sync preparams cache directory after publication: %w", err)
	}
	return nil
}

func durablyRemoveCacheFile(fs cacheFS, dir, path string) error {
	if err := fs.Remove(path); err != nil {
		return fmt.Errorf("unlink preparams cache file: %w", err)
	}
	if err := fs.SyncDir(dir); err != nil {
		return fmt.Errorf("sync preparams cache directory after unlink: %w", err)
	}
	return nil
}
