package providers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// ReconcileFunc is the callback signature that the driver exposes so that both
// the existing ticker and the new webhook path can share the same
// fetch-and-update logic.
// The function receives the Docker secret name that needs to be reconciled.
type ReconcileFunc func(secretName string) error

// HCP Vault Secrets webhook payload types -----

// WebhookPayload represents the top-level structure of an HCP Vault Secrets
// webhook event.  Only the fields the plugin cares about are kept; unknown
// fields are silently ignored by encoding/json.
type WebhookPayload struct {
	EventID          string              `json:"event_id"`
	EventAction      string              `json:"event_action"`
	EventDescription string              `json:"event_description"`
	EventSource      string              `json:"event_source"`
	EventVersion     string              `json:"event_version"`
	ResourceID       string              `json:"resource_id"`
	ResourceName     string              `json:"resource_name"`
	EventPayload     WebhookEventPayload `json:"event_payload"`
}

// WebhookEventPayload holds the inner payload shipped inside every HCP webhook
// event.  The "name" field carries the human-readable secret name.
type WebhookEventPayload struct {
	AppName        string `json:"app_name"`
	Name           string `json:"name"`
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	PrincipalID    string `json:"principal_id"`
	Provider       string `json:"provider"`
	Timestamp      string `json:"timestamp"`
	Type           string `json:"type"`
	Version        int    `json:"version"`
}

// WebhookConfig holds the user-supplied configuration for the webhook listener.
type WebhookConfig struct {
	// Port on which the HTTP listener binds (default 9095).
	Port int
	// Secret is the HMAC token shared with HCP.  When non-empty every
	// incoming request MUST carry a valid X-HCP-Webhook-Signature header.
	Secret string
}

// WebhookServer is an HTTP server that receives push events from HCP Vault
// Secrets and triggers secret reconciliation through the shared ReconcileFunc.
type WebhookServer struct {
	config    *WebhookConfig
	reconcile ReconcileFunc
	server    *http.Server
}

// actionable is the set of HCP event actions that should trigger a
// reconciliation.  "test" is the HCP verification ping — we accept it but
// do not reconcile.
var actionable = map[string]bool{
	"create": true,
	"update": true,
	"rotate": true,
}

// NewWebhookServer creates a ready-to-start webhook server.
func NewWebhookServer(cfg *WebhookConfig, reconcile ReconcileFunc) *WebhookServer {
	mux := http.NewServeMux()

	ws := &WebhookServer{
		config:    cfg,
		reconcile: reconcile,
		server: &http.Server{
			Addr:              fmt.Sprintf(":%d", cfg.Port),
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
		},
	}

	mux.HandleFunc("/webhook", ws.handleWebhook)
	mux.HandleFunc("/webhook/health", ws.handleHealth)

	return ws
}

// Start begins listening.  This method blocks; call it in a goroutine.
func (ws *WebhookServer) Start() error {
	log.Printf("Webhook server listening on %s", ws.server.Addr)
	if err := ws.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Errorf("Webhook server error: %v", err)
		return err
	}
	return nil
}

// Stop gracefully shuts the server down.
func (ws *WebhookServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ws.server.Shutdown(ctx)
}

// HTTP handlers

func (ws *WebhookServer) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the raw body (needed for HMAC validation before unmarshalling).
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("webhook: failed to read request body: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// HMAC validation
	if ws.config.Secret != "" {
		sig := r.Header.Get("X-HCP-Webhook-Signature")
		if sig == "" {
			log.Warn("webhook: missing X-HCP-Webhook-Signature header")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !ws.verifyHMAC(body, sig) {
			log.Warn("webhook: HMAC signature mismatch")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Parse payload
	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Errorf("webhook: failed to parse payload: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	log.Printf("webhook: received event_action=%s event_source=%s secret=%s",
		payload.EventAction, payload.EventSource, payload.EventPayload.Name)

	// HCP verification ping
	if strings.EqualFold(payload.EventAction, "test") {
		log.Info("webhook: responding to HCP verification ping")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Filter to actionable secret events
	if !isSecretEvent(payload.EventSource) {
		log.Printf("webhook: ignoring non-secret event source: %s", payload.EventSource)
		w.WriteHeader(http.StatusOK)
		return
	}

	if !actionable[strings.ToLower(payload.EventAction)] {
		log.Printf("webhook: ignoring event_action=%s", payload.EventAction)
		w.WriteHeader(http.StatusOK)
		return
	}

	secretName := payload.EventPayload.Name
	if secretName == "" {
		log.Warn("webhook: event has no secret name in payload, skipping")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Trigger reconciliation asynchronously
	go func() {
		log.Printf("webhook: reconciling secret %q (action=%s)", secretName, payload.EventAction)
		if err := ws.reconcile(secretName); err != nil {
			log.Errorf("webhook: reconciliation failed for %q: %v", secretName, err)
		} else {
			log.Printf("webhook: successfully reconciled secret %q", secretName)
		}
	}()

	// Return 200 immediately so HCP does not retry.
	w.WriteHeader(http.StatusOK)
}

func (ws *WebhookServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok","webhook_enabled":true}`)
}

// Helpers

// verifyHMAC checks the X-HCP-Webhook-Signature header against the raw body.
// HCP uses HMAC-SHA256 with the shared token to compute the hex-encoded
// signature.
func (ws *WebhookServer) verifyHMAC(body []byte, signature string) bool {
	mac := hmac.New(sha256.New, []byte(ws.config.Secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison to prevent timing attacks.
	return hmac.Equal([]byte(expected), []byte(signature))
}

// isSecretEvent returns true when the event_source indicates a secret
// lifecycle event as opposed to app or integration events.
//
// HCP Vault Secrets uses these event_source values:
//   - "hashicorp.secrets.secret"      → secret lifecycle (we care about this)
//   - "hashicorp.secrets.app"         → application lifecycle (ignore)
//   - "hashicorp.secrets.integration" → integration lifecycle (ignore)
func isSecretEvent(source string) bool {
	return strings.EqualFold(source, "hashicorp.secrets.secret")
}
