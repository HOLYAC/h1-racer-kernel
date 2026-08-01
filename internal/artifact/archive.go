package artifact

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var fixedArchiveTime = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

type archiveEntry struct {
	absolute string
	relative string
	mode     os.FileMode
}

// WriteDeterministicZip archives regular files under source in lexical order.
// Entries are stored without compression, with fixed timestamps and permissions,
// so identical trees produce byte-identical archives across supported platforms.
func WriteDeterministicZip(source, output, prefix string) error {
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("stat archive source: %w", err)
	}
	if !sourceInfo.IsDir() {
		return errors.New("archive source must be a directory")
	}
	prefix = normalizePrefix(prefix)
	entries, err := collectEntries(source, output, prefix)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("archive source contains no regular files")
	}
	if err = os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return fmt.Errorf("create archive parent: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(output), ".h1-racer-archive-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary archive: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()

	writer := zip.NewWriter(temporary)
	for _, entry := range entries {
		if err = addEntry(writer, entry); err != nil {
			_ = writer.Close()
			return err
		}
	}
	if err = writer.Close(); err != nil {
		return fmt.Errorf("finalize archive: %w", err)
	}
	if err = temporary.Sync(); err != nil {
		return fmt.Errorf("sync archive: %w", err)
	}
	if err = temporary.Close(); err != nil {
		return fmt.Errorf("close archive: %w", err)
	}
	if err = replaceFile(temporaryPath, output); err != nil {
		return err
	}
	committed = true
	return nil
}

func collectEntries(source, output, prefix string) ([]archiveEntry, error) {
	source, err := filepath.Abs(source)
	if err != nil {
		return nil, fmt.Errorf("resolve archive source: %w", err)
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return nil, fmt.Errorf("resolve archive output: %w", err)
	}
	if relative, relativeErr := filepath.Rel(source, output); relativeErr == nil &&
		relative != "." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && relative != ".." {
		return nil, errors.New("archive output cannot be inside the source tree")
	}
	var entries []archiveEntry
	err = filepath.WalkDir(source, func(path string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == source {
			return nil
		}
		if samePath(path, output) {
			return errors.New("archive output cannot be inside the source tree")
		}
		info, infoErr := item.Info()
		if infoErr != nil {
			return infoErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("archive source contains symlink: %s", path)
		}
		if item.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("archive source contains non-regular file: %s", path)
		}
		relative, relativeErr := filepath.Rel(source, path)
		if relativeErr != nil {
			return relativeErr
		}
		relative = filepath.ToSlash(relative)
		if relative == "." || strings.HasPrefix(relative, "../") || strings.Contains(relative, "/../") {
			return fmt.Errorf("unsafe archive path: %s", relative)
		}
		if prefix != "" {
			relative = prefix + "/" + relative
		}
		mode := os.FileMode(0o644)
		if info.Mode()&0o111 != 0 {
			mode = 0o755
		}
		entries = append(entries, archiveEntry{absolute: path, relative: relative, mode: mode})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk archive source: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].relative < entries[j].relative
	})
	return entries, nil
}

func addEntry(writer *zip.Writer, entry archiveEntry) error {
	header := &zip.FileHeader{
		Name:   entry.relative,
		Method: zip.Store,
	}
	header.SetModTime(fixedArchiveTime)
	header.SetMode(entry.mode)
	header.NonUTF8 = false
	destination, err := writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create archive entry %s: %w", entry.relative, err)
	}
	source, err := os.Open(entry.absolute)
	if err != nil {
		return fmt.Errorf("open archive entry %s: %w", entry.relative, err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := source.Close()
	if copyErr != nil {
		return fmt.Errorf("copy archive entry %s: %w", entry.relative, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close archive entry %s: %w", entry.relative, closeErr)
	}
	return nil
}

func normalizePrefix(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	value = strings.Trim(value, "/")
	return value
}

func samePath(left, right string) bool {
	if strings.EqualFold(filepath.Clean(left), filepath.Clean(right)) {
		return true
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func replaceFile(temporary, destination string) error {
	if err := os.Rename(temporary, destination); err == nil {
		return nil
	}
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove existing archive: %w", err)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return fmt.Errorf("commit archive: %w", err)
	}
	return nil
}
