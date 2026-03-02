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
	configureLogging()
	fmt.Println("Starting Vault Secrets Provider...")

	var (
		fVersion = flag.Bool("version", false, "Print version")
		fDebug   = flag.Bool("debug", false, "Enable debug logging")
	)

	flag.Parse()

	if *fVersion {
		fmt.Println("Vault Secrets Provider v1.0.0")
		return
	}

	// Enable debug level if flag is set
	if *fDebug {
		log.SetLevel(log.DebugLevel)
	}

	// Initialize the Vault driver
	driver, err := NewDriver()
	if err != nil {
		log.Errorf("Failed to initialize vault driver: %v", err)
		os.Exit(1)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

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

	log.Println("Starting Vault secrets provider plugin...")

	// Serve the plugin (must match config.json socket name)
	if err := handler.ServeUnix("plugin", 0); err != nil {
		log.Errorf("Failed to serve plugin: %v", err)
		os.Exit(1)
	}
}
