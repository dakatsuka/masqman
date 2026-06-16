// Package audit writes structured, normalized Masqman audit events.
package audit

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// EventKind identifies the audit event category.
type EventKind string

const (
	// EventAuth records a browser or MySQL authentication event.
	EventAuth EventKind = "auth"
	// EventQuery records a query decision.
	EventQuery EventKind = "query"
)

// Event is the JSON-serializable audit record shape used by M1.
type Event struct {
	Time                time.Time `json:"time"`
	Kind                EventKind `json:"kind"`
	UserID              string    `json:"user_id,omitempty"`
	SourceAddr          string    `json:"source_addr,omitempty"`
	NormalizedStatement string    `json:"normalized_statement,omitempty"`
	Decision            string    `json:"decision,omitempty"`
	MaskedFields        int       `json:"masked_fields,omitempty"`
	ErrorClass          string    `json:"error_class,omitempty"`
}

// Logger writes audit events. Callers fail closed when Log returns an error for
// accepted authentication or query work.
type Logger interface {
	Log(ctx context.Context, event Event) error
}

// FileLogger writes newline-delimited JSON audit events to one owner-only file.
type FileLogger struct {
	mu       sync.Mutex
	path     string
	config   FileConfig
	file     auditFile
	openFile func(string) (auditFile, error)
}

// FileConfig controls file audit output and size-based rotation.
type FileConfig struct {
	Path       string
	MaxBytes   int64
	MaxBackups int
}

// NewFileLogger opens or creates a file audit sink with owner-only permissions.
func NewFileLogger(path string) (*FileLogger, error) {
	return NewFileLoggerWithConfig(FileConfig{Path: path})
}

// NewFileLoggerWithConfig opens or creates a file audit sink with optional
// size-based rotation.
func NewFileLoggerWithConfig(config FileConfig) (*FileLogger, error) {
	file, err := openAuditFile(config.Path)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}

	return &FileLogger{
		path:     config.Path,
		config:   config,
		file:     file,
		openFile: openAuditFile,
	}, nil
}

// Log writes one JSON line to the audit file.
func (l *FileLogger) Log(_ context.Context, event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := l.rotateIfNeededLocked(int64(len(encoded))); err != nil {
		return err
	}
	_, err = l.file.Write(encoded)

	return err
}

// Flush forces buffered audit file state to stable storage.
func (l *FileLogger) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.flushLocked()
}

// Close flushes and closes the audit file.
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.flushLocked(); err != nil {
		_ = l.file.Close()
		return err
	}

	return l.file.Close()
}

func (l *FileLogger) rotateIfNeededLocked(nextWriteBytes int64) error {
	if l.config.MaxBytes <= 0 {
		return nil
	}

	info, err := l.file.Stat()
	if err != nil {
		return err
	}
	if info.Size()+nextWriteBytes <= l.config.MaxBytes {
		return nil
	}
	if err := l.flushLocked(); err != nil {
		return err
	}
	if err := l.file.Close(); err != nil {
		return err
	}
	if err := l.rotateBackupsLocked(); err != nil {
		return err
	}

	file, err := l.openFile(l.path)
	if err != nil {
		return err
	}
	l.file = file

	return l.file.Chmod(0o600)
}

func (l *FileLogger) flushLocked() error {
	return l.file.Sync()
}

type auditFile interface {
	Write([]byte) (int, error)
	Stat() (os.FileInfo, error)
	Sync() error
	Close() error
	Chmod(os.FileMode) error
}

func openAuditFile(path string) (auditFile, error) {
	// #nosec G304 -- the audit sink path is operator configuration, not user input.
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}

func (l *FileLogger) rotateBackupsLocked() error {
	if l.config.MaxBackups <= 0 {
		return os.Remove(l.path)
	}

	oldest := l.path + "." + strconv.Itoa(l.config.MaxBackups)
	if err := removeIfExists(oldest); err != nil {
		return err
	}
	for index := l.config.MaxBackups - 1; index >= 1; index-- {
		from := l.path + "." + strconv.Itoa(index)
		to := l.path + "." + strconv.Itoa(index+1)
		if err := renameIfExists(from, to); err != nil {
			return err
		}
	}

	return renameIfExists(l.path, l.path+".1")
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

func renameIfExists(from string, to string) error {
	if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// NormalizeStatement removes comments and replaces string and numeric literals
// with placeholders before a statement is written to audit logs.
func NormalizeStatement(statement string) string {
	var out strings.Builder
	lastWasSpace := false
	lastWasPlaceholder := false

	for i := 0; i < len(statement); {
		r := rune(statement[i])
		if isDashDashComment(statement, i) || statement[i] == '#' {
			i++
			for i < len(statement) && statement[i] != '\n' {
				i++
			}
			lastWasSpace = out.Len() > 0
			continue
		}
		if statement[i] == '/' && i+1 < len(statement) && statement[i+1] == '*' {
			i += 2
			for i+1 < len(statement) && !isBlockCommentEnd(statement, i) {
				i++
			}
			if i+1 < len(statement) {
				i += 2
			}
			lastWasSpace = out.Len() > 0
			continue
		}

		if statement[i] == '\'' || statement[i] == '"' {
			quote := statement[i]
			writeToken(&out, &lastWasSpace, &lastWasPlaceholder, "?")
			i++
			for i < len(statement) {
				if statement[i] == '\\' && i+1 < len(statement) {
					i += 2
					continue
				}
				if statement[i] == quote {
					i++
					break
				}
				i++
			}
			continue
		}

		if unicode.IsDigit(r) {
			writeToken(&out, &lastWasSpace, &lastWasPlaceholder, "?")
			for i < len(statement) && isNumericLiteralByte(statement[i]) {
				i++
			}
			continue
		}

		if unicode.IsSpace(r) {
			if out.Len() > 0 {
				lastWasSpace = true
			}
			i++
			continue
		}

		if lastWasSpace && out.Len() > 0 {
			out.WriteByte(' ')
			lastWasSpace = false
		}
		out.WriteRune(r)
		lastWasPlaceholder = r == '?'
		i++
	}

	return strings.TrimSpace(out.String())
}

func writeToken(out *strings.Builder, lastWasSpace *bool, lastWasPlaceholder *bool, token string) {
	if *lastWasSpace && out.Len() > 0 {
		out.WriteByte(' ')
		*lastWasPlaceholder = false
	}
	if *lastWasPlaceholder {
		*lastWasSpace = false
		return
	}
	out.WriteString(token)
	*lastWasSpace = false
	*lastWasPlaceholder = token == "?"
}

func isNumericLiteralByte(value byte) bool {
	return (value >= '0' && value <= '9') ||
		(value >= 'a' && value <= 'z') ||
		(value >= 'A' && value <= 'Z') ||
		value == '.' ||
		value == '_'
}

func isBlockCommentEnd(statement string, index int) bool {
	return statement[index] == '*' && statement[index+1] == '/'
}

func isDashDashComment(statement string, index int) bool {
	if statement[index] != '-' || index+1 >= len(statement) || statement[index+1] != '-' {
		return false
	}
	if index+2 >= len(statement) {
		return false
	}

	next := statement[index+2]

	return next == ' ' || next == '\t' || next == '\n' || next == '\r' || next == '\f'
}
