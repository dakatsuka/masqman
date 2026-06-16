package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileLoggerFlushAndCloseSyncFile(t *testing.T) {
	t.Parallel()

	file := &countingAuditFile{}
	logger := &FileLogger{file: file}

	if err := logger.Flush(); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}
	if file.syncs != 1 {
		t.Fatalf("Flush syncs = %d, want 1", file.syncs)
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if file.syncs != 2 {
		t.Fatalf("Close syncs = %d, want 2", file.syncs)
	}
	if file.closes != 1 {
		t.Fatalf("Close closes = %d, want 1", file.closes)
	}
}

func TestFileLoggerRotationSyncsOldFileBeforeClose(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	oldFile := &countingAuditFile{size: 1}
	newFile := &countingAuditFile{}
	logger := &FileLogger{
		path:   path,
		config: FileConfig{Path: path, MaxBytes: 1},
		file:   oldFile,
		openFile: func(string) (auditFile, error) {
			return newFile, nil
		},
	}

	if err := logger.Log(context.Background(), Event{
		Time:   time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC),
		Kind:   EventAuth,
		UserID: "alice",
	}); err != nil {
		t.Fatalf("Log returned error: %v", err)
	}
	if oldFile.syncs != 1 {
		t.Fatalf("rotation old file syncs = %d, want 1", oldFile.syncs)
	}
	if oldFile.closes != 1 {
		t.Fatalf("rotation old file closes = %d, want 1", oldFile.closes)
	}
	if newFile.syncs != 0 {
		t.Fatalf("Log syncs new file = %d, want 0", newFile.syncs)
	}
	if newFile.writes != 1 {
		t.Fatalf("Log writes new file = %d, want 1", newFile.writes)
	}
}

type countingAuditFile struct {
	writes int
	syncs  int
	closes int
	size   int64
}

func (f *countingAuditFile) Write(bytes []byte) (int, error) {
	f.writes++
	f.size += int64(len(bytes))

	return len(bytes), nil
}

func (f *countingAuditFile) Stat() (os.FileInfo, error) {
	return fileInfo{size: f.size}, nil
}

func (f *countingAuditFile) Sync() error {
	if f.closes > 0 {
		return errors.New("sync after close")
	}
	f.syncs++

	return nil
}

func (f *countingAuditFile) Close() error {
	f.closes++

	return nil
}

func (f *countingAuditFile) Chmod(os.FileMode) error {
	return nil
}

type fileInfo struct {
	size int64
}

func (i fileInfo) Name() string {
	return "audit.jsonl"
}

func (i fileInfo) Size() int64 {
	return i.size
}

func (i fileInfo) Mode() os.FileMode {
	return 0o600
}

func (i fileInfo) ModTime() time.Time {
	return time.Time{}
}

func (i fileInfo) IsDir() bool {
	return false
}

func (i fileInfo) Sys() any {
	return nil
}
