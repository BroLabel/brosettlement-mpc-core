package file

import (
	"fmt"
	"os"
	"path/filepath"
)

type atomicFileOperations struct {
	createTemp func(dir, pattern string) (*os.File, error)
	link       func(oldname, newname string) error
	remove     func(name string) error
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	return atomicWriteWithOperations(path, data, perm, atomicFileOperations{
		createTemp: os.CreateTemp,
		link:       os.Link,
		remove:     os.Remove,
	})
}

func atomicWriteWithOperations(path string, data []byte, perm os.FileMode, ops atomicFileOperations) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}

	tmp, err := ops.createTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	cleanup := func() {
		_ = ops.remove(tmpPath)
	}

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("set temp file mode: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := ops.link(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("publish share: %w", err)
	}
	_ = ops.remove(tmpPath)

	return nil
}
