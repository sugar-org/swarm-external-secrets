// Command mock-doppler-server is a minimal Doppler API stub for smoke tests.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultAddr   = "127.0.0.1:18080"
	downloadPath  = "/v3/configs/config/secrets/download"
	setSecretPath = "/mock/set-secret"
)

// defaultSmokeTestToken is a fake token used only by this local test server.
const defaultSmokeTestToken = "dp.st.smoke-test" // #nosec G101

type server struct {
	token   string
	mu      sync.RWMutex
	secrets map[string]string
}

func main() {
	addr := flag.String("addr", defaultAddr, "listen address")
	token := flag.String("token", defaultSmokeTestToken, "expected bearer token")
	flag.Parse()

	srv := &server{
		token: *token,
		secrets: map[string]string{
			"SMOKE_TEST_PASSWORD": "doppler-smoke-pass-v1",
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(downloadPath, srv.handleDownload)
	mux.HandleFunc(setSecretPath, srv.handleSetSecret)

	log.Printf("Doppler mock listening on http://%s", *addr)

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("mock server failed: %v", err)
	}
}

func (s *server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.URL.Query().Get("format") != "json" {
		http.Error(w, "unsupported format", http.StatusBadRequest)
		return
	}

	payload, err := json.Marshal(s.filtered(r))
	if err != nil {
		http.Error(w, "failed to encode secrets", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload) // #nosec G705 -- local mock returns JSON, not HTML
}

func (s *server) handleSetSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var req struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Name == "" {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.secrets[req.Name] = req.Value
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (s *server) authorize(r *http.Request) bool {
	return r.Header.Get("Authorization") == fmt.Sprintf("Bearer %s", s.token)
}

func (s *server) filtered(r *http.Request) map[string]string {
	all := s.snapshot()
	raw := strings.TrimSpace(r.URL.Query().Get("secrets"))
	if raw == "" {
		return all
	}

	filtered := make(map[string]string)
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if value, ok := all[name]; ok {
			filtered[name] = value
		}
	}
	return filtered
}

func (s *server) snapshot() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	copy := make(map[string]string, len(s.secrets))
	for key, value := range s.secrets {
		copy[key] = value
	}
	return copy
}
