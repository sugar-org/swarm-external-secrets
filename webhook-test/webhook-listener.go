package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
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

// WebhookServer handles incoming webhook requests
type WebhookServer struct {
	port          string
	webhookSecret string
}

func NewWebhookServer(port, secret string) *WebhookServer {
	return &WebhookServer{
		port:          port,
		webhookSecret: secret,
	}
}

func (ws *WebhookServer) validateSignature(payload []byte, signature string) bool {
	if ws.webhookSecret == "" {
		log.Println("No webhook secret configured - skipping validation")
		return true
	}

	mac := hmac.New(sha256.New, []byte(ws.webhookSecret))
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

func (ws *WebhookServer) handleWebhook(c *gin.Context) {
	// Read the raw body for signature validation
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Get signature from header (HCP Vault sends this as X-HCP-Webhook-Signature)
	signature := c.GetHeader("X-HCP-Webhook-Signature")

	// Validate signature if secret is configured
	if ws.webhookSecret != "" {
		if signature == "" {
			log.Println("Missing X-HCP-Webhook-Signature header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing signature"})
			return
		}

		if !ws.validateSignature(bodyBytes, signature) {
			log.Println("Invalid webhook signature")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
			return
		}
		log.Println("Webhook signature validated")
	}

	// Parse the webhook payload
	var payload VaultWebhookPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		log.Printf("Failed to parse webhook payload: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}

	// Log the received event
	separator := strings.Repeat("=", 80)
	log.Println("\n" + separator)
	log.Printf("Received Webhook Event")
	log.Println(separator)
	log.Printf("Event ID:          %s\n", payload.EventID)
	log.Printf("Event Action:      %s\n", payload.EventAction)
	log.Printf("Event Source:      %s\n", payload.EventSource)
	log.Printf("Event Description: %s\n", payload.EventDescription)
	log.Printf("Resource ID:       %s\n", payload.ResourceID)
	log.Printf("Resource Name:     %s\n", payload.ResourceName)

	// Extract relevant info from event payload
	if appName, ok := payload.EventPayload["app_name"].(string); ok {
		log.Printf("App Name:          %s\n", appName)
	}
	if secretName, ok := payload.EventPayload["name"].(string); ok {
		log.Printf("Secret Name:       %s\n", secretName)
	}
	if secretType, ok := payload.EventPayload["type"].(string); ok {
		log.Printf("Secret Type:       %s\n", secretType)
	}
	if version, ok := payload.EventPayload["version"].(float64); ok {
		log.Printf("Version:           %.0f\n", version)
	}

	log.Println(separator)

	// Pretty print full payload
	prettyJSON, _ := json.MarshalIndent(payload, "", "  ")
	log.Printf("\nFull Payload:\n%s\n", string(prettyJSON))

	// Respond with success
	c.JSON(http.StatusOK, gin.H{
		"status":   "received",
		"event_id": payload.EventID,
	})
}

func (ws *WebhookServer) Start() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	router.POST("/webhook", ws.handleWebhook)

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	log.Printf("Starting webhook server on port %s\n", ws.port)
	log.Printf("Webhook endpoint: http://localhost:%s/webhook\n", ws.port)
	log.Printf("Health check: http://localhost:%s/health\n", ws.port)

	if ws.webhookSecret != "" {
		log.Println("Webhook signature validation: ENABLED")
	} else {
		log.Println("Webhook signature validation: DISABLED")
	}

	log.Println("\nWaiting for webhook events...")

	if err := router.Run(":" + ws.port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func main() {
	port := os.Getenv("WEBHOOK_PORT")
	if port == "" {
		port = "9095"
	}

	secret := os.Getenv("WEBHOOK_SECRET")

	server := NewWebhookServer(port, secret)
	server.Start()
}
