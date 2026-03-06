package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"
)

// VaultWebhookPayload represents the HCP Vault Secrets webhook structure
type VaultWebhookPayload struct {
	ResourceID       string                 `json:"resource_id"`
	ResourceName     string                 `json:"resource_name"`
	EventID          string                 `json:"event_id"`
	EventAction      string                 `json:"event_action"`
	EventDescription string                 `json:"event_description"`
	EventSource      string                 `json:"event_source"`
	EventVersion     string                 `json:"event_version"`
	EventPayload     map[string]interface{} `json:"event_payload"`
}

// WebhookConfig holds webhook server configuration
type WebhookConfig struct {
	Port          string
	Secret        string
	ReconcileFunc func(secretName string) error
}

// WebhookServer handles incoming webhook requests from Vault
type WebhookServer struct {
	config   *WebhookConfig
	server   *http.Server
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewWebhookServer creates a new webhook server instance
func NewWebhookServer(config *WebhookConfig) *WebhookServer {
	return &WebhookServer{
		config:   config,
		stopChan: make(chan struct{}),
	}
}

// Start begins listening for webhook events
func (ws *WebhookServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", ws.handleWebhook)
	mux.HandleFunc("/health", ws.handleHealth)

	ws.server = &http.Server{
		Addr:    ":" + ws.config.Port,
		Handler: mux,
	}

	ws.wg.Add(1)
	go func() {
		defer ws.wg.Done()
		log.Infof("Webhook server starting on port %s", ws.config.Port)
		log.Infof("Webhook endpoint: http://0.0.0.0:%s/webhook", ws.config.Port)

		if ws.config.Secret != "" {
			log.Info("Webhook signature validation: ENABLED")
		} else {
			log.Warn("Webhook signature validation: DISABLED (no WEBHOOK_SECRET set)")
		}

		if err := ws.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Webhook server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the webhook server
func (ws *WebhookServer) Stop() error {
	close(ws.stopChan)

	if ws.server != nil {
		if err := ws.server.Close(); err != nil {
			return fmt.Errorf("failed to stop webhook server: %v", err)
		}
	}

	ws.wg.Wait()
	log.Info("Webhook server stopped")
	return nil
}

// validateSignature validates the webhook signature using HMAC-SHA256
func (ws *WebhookServer) validateSignature(payload []byte, signature string) bool {
	if ws.config.Secret == "" {
		return true // No secret configured, skip validation
	}

	mac := hmac.New(sha256.New, []byte(ws.config.Secret))
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

// writeJSON is a helper to write a JSON error/response body
func writeJSON(w http.ResponseWriter, status int, body map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// handleWebhook processes incoming webhook events from HCP Vault Secrets
func (ws *WebhookServer) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{
			"error": "method not allowed",
		})
		return
	}

	// Read the raw body for signature validation
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Failed to read webhook body: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "failed to read request body",
		})
		return
	}
	defer r.Body.Close()

	// Validate HMAC-SHA256 signature if secret is configured
	if ws.config.Secret != "" {
		signature := r.Header.Get("X-HCP-Webhook-Signature")
		if signature == "" {
			log.Warn("Rejected webhook: missing X-HCP-Webhook-Signature header")
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"error": "missing X-HCP-Webhook-Signature header",
			})
			return
		}

		if !ws.validateSignature(bodyBytes, signature) {
			log.Warn("Rejected webhook: invalid HMAC-SHA256 signature")
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"error": "invalid webhook signature",
			})
			return
		}
		log.Debug("Webhook HMAC-SHA256 signature validated successfully")
	}

	// Parse the webhook payload
	var payload VaultWebhookPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		log.Errorf("Failed to parse webhook payload: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": fmt.Sprintf("invalid JSON payload: %v", err),
		})
		return
	}

	log.WithFields(log.Fields{
		"event_id":     payload.EventID,
		"event_action": payload.EventAction,
		"event_source": payload.EventSource,
		"resource":     payload.ResourceName,
	}).Info("Received webhook event")

	// Extract the vault secret name from event_payload.name
	secretName, ok := payload.EventPayload["name"].(string)
	if !ok || secretName == "" {
		log.Warn("Webhook payload missing or empty 'name' field in event_payload")
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "event_payload.name is required and must be a non-empty string",
		})
		return
	}

	appName, _ := payload.EventPayload["app_name"].(string)

	log.WithFields(log.Fields{
		"app_name":     appName,
		"secret_name":  secretName,
		"event_action": payload.EventAction,
	}).Info("Processing webhook event for secret")

	// Trigger reconciliation — ReconcileSecret resolves vault name → docker secret name
	if ws.config.ReconcileFunc == nil {
		log.Error("ReconcileFunc is not set on WebhookServer — cannot process event")
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "webhook handler not properly initialised (missing reconcile function)",
		})
		return
	}

	if err := ws.config.ReconcileFunc(secretName); err != nil {
		log.Errorf("Reconciliation failed for secret '%s': %v", secretName, err)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":       "reconciliation failed",
			"secret_name": secretName,
			"detail":      err.Error(),
		})
		return
	}

	log.Infof("✅ Webhook processed successfully for secret '%s' (event: %s)", secretName, payload.EventID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "received",
		"event_id":    payload.EventID,
		"secret_name": secretName,
	})
}

// handleHealth returns health status of the webhook server
func (ws *WebhookServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "healthy",
	})
}
