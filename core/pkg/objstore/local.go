package objstore

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// localStorage implements Store for the local filesystem.
// Used for development, testing, and local validation.
type localStorage struct {
	rootDir string
}

// newlocalStorage creates a filesystem-backed Store rooted at the given directory.
func newlocalStorage(rootDir string) *localStorage {
	return &localStorage{rootDir: rootDir}
}

// Bucket returns the root directory path.
func (s *localStorage) Bucket() string {
	return s.rootDir
}

// Put writes data to a file at rootDir/key.
func (s *localStorage) Put(_ context.Context, key string, body io.Reader, _ string) error {
	fullPath := filepath.Join(s.rootDir, key)

	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("local: creating directory %s: %w", dir, err)
	}

	data, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("local: reading body: %w", err)
	}

	if err := os.WriteFile(fullPath, data, 0600); err != nil {
		return fmt.Errorf("local: writing file %s: %w", fullPath, err)
	}

	return nil
}

// Get opens the file at rootDir/key for reading.
func (s *localStorage) Get(_ context.Context, key string) (io.ReadCloser, error) {
	baseClean := filepath.Clean(s.rootDir)
	targetClean := filepath.Clean(filepath.Join(baseClean, key))
	rel, err := filepath.Rel(baseClean, targetClean)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("invalid file path")
	}
	f, err := os.Open(targetClean)
	if err != nil {
		return nil, fmt.Errorf("local: opening file %s: %w", targetClean, err)
	}
	return f, nil
}

// List returns all files under rootDir matching the given prefix.
func (s *localStorage) List(_ context.Context, prefix string) ([]Object, error) {
	var objects []Object
	searchDir := s.rootDir

	err := filepath.Walk(searchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Get relative path from root directory.
		rel, err := filepath.Rel(s.rootDir, path)
		if err != nil {
			return err
		}
		// Normalize to forward slashes for consistency with cloud providers.
		rel = filepath.ToSlash(rel)

		if strings.HasPrefix(rel, prefix) {
			objects = append(objects, Object{
				Key:  rel,
				Size: info.Size(),
			})
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("local: listing directory: %w", err)
	}

	return objects, nil
}
