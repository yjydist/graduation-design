package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/renameio/v2"
	"github.com/jszwec/csvutil"
)

// WriteAtomic writes data to path atomically via renameio, creating parent
// directories as needed.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	if path == "" {
		return errors.New("harness: empty output path")
	}
	if perm == 0 {
		perm = 0o644
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("harness: create parent dir for %s: %w", path, err)
	}
	if err := renameio.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("harness: atomic write %s: %w", path, err)
	}
	return nil
}

// WriteJSON marshals v as indented JSON with a trailing newline and writes it
// atomically to path.
func WriteJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("harness: marshal json for %s: %w", path, err)
	}
	raw = append(raw, '\n')
	return WriteAtomic(path, raw, 0o644)
}

// ReadJSON reads path and unmarshals its JSON contents into dst.
func ReadJSON(path string, dst any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("harness: read json %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("harness: unmarshal json %s: %w", path, err)
	}
	return nil
}

// MergeJSON atomically updates a JSON object file by merging top-level keys
// from patch into the existing object (or creating a new object if the file
// does not exist).
func MergeJSON(path string, patch map[string]any) error {
	var current map[string]any
	if err := ReadJSON(path, &current); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		current = map[string]any{}
	}
	if current == nil {
		current = map[string]any{}
	}
	for k, v := range patch {
		current[k] = v
	}
	return WriteJSON(path, current)
}

// WriteCSV encodes rows as RFC 4180 CSV with a header row using csvutil and
// writes the result atomically to path.
func WriteCSV[T any](path string, rows []T) error {
	raw, err := csvutil.Marshal(rows)
	if err != nil {
		return fmt.Errorf("harness: marshal csv for %s: %w", path, err)
	}
	return WriteAtomic(path, raw, 0o644)
}

// ReadCSV reads path and decodes its CSV records into a typed slice using
// csvutil.
func ReadCSV[T any](path string) ([]T, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("harness: read csv %s: %w", path, err)
	}
	var rows []T
	if err := csvutil.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("harness: unmarshal csv %s: %w", path, err)
	}
	if rows == nil {
		rows = []T{}
	}
	return rows, nil
}

// SHA256File computes the lowercase hexadecimal SHA-256 digest of the file at
// path.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("harness: open %s for sha256: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("harness: hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256Bytes computes the lowercase hexadecimal SHA-256 digest of data.
func SHA256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
