package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

const (
	defaultPluginLogPath = "/run/swarm-external-secrets/plugin.log"
	defaultMaxLogSize    = int64(10 * 1024 * 1024) // 10MB
)

// cappedFileWriter appends to a log file and rotates it when max size is exceeded.
type cappedFileWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
}

func newCappedFileWriter(path string, maxBytes int64) (*cappedFileWriter, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxLogSize
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	return &cappedFileWriter{path: path, maxBytes: maxBytes, file: f}, nil
}

func (w *cappedFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.rotateIfNeeded(int64(len(p))); err != nil {
		return 0, err
	}

	return w.file.Write(p)
}

func (w *cappedFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	return w.file.Close()
}

func (w *cappedFileWriter) rotateIfNeeded(incoming int64) error {
	info, err := w.file.Stat()
	if err != nil {
		return fmt.Errorf("stat log file: %w", err)
	}

	if info.Size()+incoming <= w.maxBytes {
		return nil
	}

	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close log file for rotation: %w", err)
	}

	rotatedPath := w.path + ".1"
	if err := os.Remove(rotatedPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove previous rotated log: %w", err)
	}

	if err := os.Rename(w.path, rotatedPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rotate log file: %w", err)
	}

	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("reopen log file after rotation: %w", err)
	}

	w.file = f
	return nil
}

func configureLogger(debugFlag bool) io.Closer {
	level := parseLogLevel(getEnvOrDefault("PLUGIN_LOG_LEVEL", "info"), debugFlag)
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	logPath := getEnvOrDefault("PLUGIN_LOG_PATH", defaultPluginLogPath)
	writer, err := newCappedFileWriter(logPath, defaultMaxLogSize)
	if err != nil {
		log.SetOutput(os.Stderr)
		log.Warnf("failed to initialize file logging at %s: %v", logPath, err)
		return nil
	}

	log.SetOutput(io.MultiWriter(os.Stderr, writer))
	log.Infof("plugin logging configured with path=%s level=%s max_size_mb=%d", logPath, level.String(), defaultMaxLogSize/(1024*1024))
	return writer
}

func parseLogLevel(raw string, debugFlag bool) log.Level {
	if debugFlag {
		return log.DebugLevel
	}

	parsed, err := log.ParseLevel(strings.ToLower(strings.TrimSpace(raw)))
	if err != nil {
		return log.InfoLevel
	}
	return parsed
}
