package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
)

func main() {
	fmt.Print("Starting Vault Secrets Provider...")
	var (
		flVersion = flag.Bool("version", false, "Print version")
		flDebug   = flag.Bool("debug", false, "Enable debug logging")
	)
	flag.Parse()

	if *flVersion {
		fmt.Println("Vault Secrets Provider v1.0.0")
		return
	}
	if *flDebug {
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
