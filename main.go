package main

import (
	"flag"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.Print("Starting Vault Secrets Provider...")
	var (
		flVersion = flag.Bool("version", false, "Print version")
		flDebug   = flag.Bool("debug", false, "Enable debug logging")
	)
	flag.Parse()

	if *flVersion {
		log.Println("Vault Secrets Provider v1.0.0")
		return
	}

	// Default to InfoLevel; allow override via LOG_LEVEL (0-7) or --debug.
	log.SetLevel(log.InfoLevel)
	if lvlStr, ok := os.LookupEnv("LOG_LEVEL"); ok {
		lvlStr = strings.TrimSpace(lvlStr)
		if lvlStr != "" {
			n, err := strconv.Atoi(lvlStr)
			if err != nil || n < 0 || n > 7 {
				log.Warnf("Invalid LOG_LEVEL=%q; expected integer 0-7. Using default level %s.", lvlStr, log.GetLevel())
			} else {
				// logrus supports 0-6 (panic..trace); accept 7 as trace for compatibility.
				if n == 7 {
					n = int(log.TraceLevel)
				}
				log.SetLevel(log.Level(n))
				log.Debugf("Log level set from LOG_LEVEL=%s (%s)", lvlStr, log.GetLevel())
			}
		}
	} else if *flDebug {
		log.SetLevel(log.DebugLevel)
	}

	// Initialize the Vault driver
	driver, err := NewDriver()
	if err != nil {
		log.Fatalf("Failed to initialize vault driver: %v", err)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start cleanup goroutine
	go func() {
		<-sigChan
		log.Println("Received shutdown signal, cleaning up...")
		if err := driver.Stop(); err != nil {
			log.Errorf("Error during cleanup: %v", err)
		}
		os.Exit(0)
	}()

	// Create the plugin handler
	handler := secrets.NewHandler(driver)

	// Serve the plugin - must match config.json socket name
	log.Println("Starting Vault secrets provider plugin...")
	if err := handler.ServeUnix("plugin", 0); err != nil {
		log.Fatalf("Failed to serve plugin: %v", err)
	}
}
