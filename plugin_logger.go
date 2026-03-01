package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"
)

const (
	defaultPluginLogPath   = "/run/swarm-external-secrets/plugin.log"
	defaultPluginLogSizeMB = 10
)

// rotatingFileWriter writes logs to a file and keeps a single rotated backup.
type rotatingFileWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
}

func newRotatingFileWriter(path string, maxSizeMB int) (*rotatingFileWriter, error) {
	if path == "" {
		return nil, fmt.Errorf("log path is empty")
	}

	if maxSizeMB <= 0 {
		maxSizeMB = defaultPluginLogSizeMB
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat log file: %w", err)
	}

	return &rotatingFileWriter{
		path:     path,
		maxBytes: int64(maxSizeMB) * 1024 * 1024,
		file:     f,
		size:     stat.Size(),
	}, nil
}

func (w *rotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return 0, fmt.Errorf("log file writer is closed")
	}

	if w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotateLocked(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}

	err := w.file.Close()
	w.file = nil
	return err
}

func (w *rotatingFileWriter) rotateLocked() error {
	if w.file == nil {
		return fmt.Errorf("log file writer is closed")
	}

	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close current log file: %w", err)
	}

	backupPath := w.path + ".1"
	_ = os.Remove(backupPath)
	if err := os.Rename(w.path, backupPath); err != nil {
		return fmt.Errorf("rotate log file: %w", err)
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create new log file: %w", err)
	}

	w.file = f
	w.size = 0
	return nil
}

func parsePositiveIntOrDefault(value string, fallback int) int {
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}

	return parsed
}

func setupPluginFileLogging() io.Closer {
	logPath := getEnvOrDefault("PLUGIN_LOG_PATH", defaultPluginLogPath)
	maxSizeMB := parsePositiveIntOrDefault(os.Getenv("PLUGIN_LOG_MAX_SIZE_MB"), defaultPluginLogSizeMB)

	writer, err := newRotatingFileWriter(logPath, maxSizeMB)
	if err != nil {
		log.WithError(err).Warn("plugin file logging disabled; continuing with daemon logs only")
		return nil
	}

	log.SetOutput(io.MultiWriter(os.Stderr, writer))
	log.WithFields(log.Fields{
		"log_path":    logPath,
		"log_size_mb": maxSizeMB,
	}).Info("plugin file logging enabled")

	return writer
}
