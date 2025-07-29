package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// WebInterface provides a simple web interface for monitoring
type WebInterface struct {
	monitor *Monitor
	server  *http.Server
}

// NewWebInterface creates a new web monitoring interface
func NewWebInterface(monitor *Monitor, port int) *WebInterface {
	mux := http.NewServeMux()

	wi := &WebInterface{
		monitor: monitor,
		server: &http.Server{
			Addr:              fmt.Sprintf(":%d", port),
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}

	// Register routes
	mux.HandleFunc("/", wi.handleDashboard)
	mux.HandleFunc("/metrics", wi.handleMetrics)
	mux.HandleFunc("/health", wi.handleHealth)
	mux.HandleFunc("/api/metrics", wi.handleAPIMetrics)

	return wi
}

// Start starts the web interface server
func (wi *WebInterface) Start() error {
	go func() {
		if err := wi.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Web interface server error: %v", err)
		}
	}()

	log.Printf("Started web monitoring interface on %s", wi.server.Addr)
	return nil
}

// Stop stops the web interface server
func (wi *WebInterface) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return wi.server.Shutdown(ctx)
}

// handleDashboard serves the main dashboard page
func (wi *WebInterface) handleDashboard(w http.ResponseWriter, r *http.Request) {
	metrics := wi.monitor.GetMetrics()
	health := wi.monitor.GetHealthStatus()

	tmpl := template.Must(template.New("dashboard").Parse(dashboardTemplate))

	data := struct {
		Metrics *Metrics
		Health  map[string]interface{}
	}{
		Metrics: metrics,
		Health:  health,
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleMetrics serves detailed metrics in JSON format
func (wi *WebInterface) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := wi.monitor.GetMetrics()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleHealth serves health status
func (wi *WebInterface) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := wi.monitor.GetHealthStatus()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleAPIMetrics serves metrics in Prometheus format
func (wi *WebInterface) handleAPIMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := wi.monitor.GetMetrics()

	w.Header().Set("Content-Type", "text/plain")

	// Basic Prometheus-style metrics
	_, _ = fmt.Fprintf(w, "# HELP vault_swarm_plugin_goroutines Current number of goroutines\n")
	_, _ = fmt.Fprintf(w, "# TYPE vault_swarm_plugin_goroutines gauge\n")
	_, _ = fmt.Fprintf(w, "vault_swarm_plugin_goroutines %d\n", metrics.NumGoroutines)

	_, _ = fmt.Fprintf(w, "# HELP vault_swarm_plugin_memory_bytes Memory usage in bytes\n")
	_, _ = fmt.Fprintf(w, "# TYPE vault_swarm_plugin_memory_bytes gauge\n")
	_, _ = fmt.Fprintf(w, "vault_swarm_plugin_memory_bytes{type=\"alloc\"} %d\n", metrics.MemAllocBytes)
	_, _ = fmt.Fprintf(w, "vault_swarm_plugin_memory_bytes{type=\"sys\"} %d\n", metrics.MemSysBytes)
	_, _ = fmt.Fprintf(w, "vault_swarm_plugin_memory_bytes{type=\"heap\"} %d\n", metrics.MemHeapBytes)

	_, _ = fmt.Fprintf(w, "# HELP vault_swarm_plugin_secret_rotations_total Total number of secret rotations\n")
	_, _ = fmt.Fprintf(w, "# TYPE vault_swarm_plugin_secret_rotations_total counter\n")
	_, _ = fmt.Fprintf(w, "vault_swarm_plugin_secret_rotations_total %d\n", metrics.SecretRotations)

	_, _ = fmt.Fprintf(w, "# HELP vault_swarm_plugin_rotation_errors_total Total number of rotation errors\n")
	_, _ = fmt.Fprintf(w, "# TYPE vault_swarm_plugin_rotation_errors_total counter\n")
	_, _ = fmt.Fprintf(w, "vault_swarm_plugin_rotation_errors_total %d\n", metrics.SecretRotationErrors)

	_, _ = fmt.Fprintf(w, "# HELP vault_swarm_plugin_gc_total Total number of garbage collections\n")
	_, _ = fmt.Fprintf(w, "# TYPE vault_swarm_plugin_gc_total counter\n")
	_, _ = fmt.Fprintf(w, "vault_swarm_plugin_gc_total %d\n", metrics.NumGC)
}

const dashboardTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Vault Swarm Plugin Monitor</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            color: #333;
            border-bottom: 2px solid #007acc;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .status {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
        }
        .healthy { background-color: #28a745; }
        .unhealthy { background-color: #dc3545; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .card {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #007acc;
        }
        .card h3 {
            margin-top: 0;
            color: #333;
        }
        .metric {
            display: flex;
            justify-content: space-between;
            margin: 10px 0;
            padding: 5px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        .metric:last-child {
            border-bottom: none;
        }
        .metric-label {
            font-weight: bold;
            color: #555;
        }
        .metric-value {
            color: #007acc;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Vault Swarm Plugin Monitor</h1>
            <p>Real-time monitoring of secret provider plugin</p>
            <span class="status {{if .Health.healthy}}healthy{{else}}unhealthy{{end}}">
                {{if .Health.healthy}}HEALTHY{{else}}UNHEALTHY{{end}}
            </span>
        </div>

        <div class="grid">
            <div class="card">
                <h3>📊 System Metrics</h3>
                <div class="metric">
                    <span class="metric-label">Goroutines:</span>
                    <span class="metric-value">{{.Metrics.NumGoroutines}}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Memory Allocated:</span>
                    <span class="metric-value">{{printf "%.2f" (div .Metrics.MemAllocBytes 1048576.0)}} MB</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Memory System:</span>
                    <span class="metric-value">{{printf "%.2f" (div .Metrics.MemSysBytes 1048576.0)}} MB</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Memory Heap:</span>
                    <span class="metric-value">{{printf "%.2f" (div .Metrics.MemHeapBytes 1048576.0)}} MB</span>
                </div>
                <div class="metric">
                    <span class="metric-label">GC Cycles:</span>
                    <span class="metric-value">{{.Metrics.NumGC}}</span>
                </div>
            </div>

            <div class="card">
                <h3>🔄 Secret Rotation</h3>
                <div class="metric">
                    <span class="metric-label">Total Rotations:</span>
                    <span class="metric-value">{{.Metrics.SecretRotations}}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Rotation Errors:</span>
                    <span class="metric-value">{{.Metrics.SecretRotationErrors}}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Error Rate:</span>
                    <span class="metric-value">{{printf "%.2f" .Health.error_rate}}%</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Rotation Interval:</span>
                    <span class="metric-value">{{.Metrics.RotationInterval}}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Last Ticker Beat:</span>
                    <span class="metric-value">{{if .Metrics.TickerHeartbeat.IsZero}}Never{{else}}{{.Metrics.TickerHeartbeat.Format "15:04:05"}}{{end}}</span>
                </div>
            </div>

            <div class="card">
                <h3>⏱️ Uptime & Status</h3>
                <div class="metric">
                    <span class="metric-label">Uptime:</span>
                    <span class="metric-value">{{printf "%.2f" .Health.uptime_seconds}} seconds</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Started At:</span>
                    <span class="metric-value">{{.Metrics.MonitoringStartTime.Format "2006-01-02 15:04:05"}}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Ticker Health:</span>
                    <span class="metric-value">{{if .Health.ticker_healthy}}✅ Healthy{{else}}❌ Unhealthy{{end}}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Last GC:</span>
                    <span class="metric-value">{{if .Metrics.LastGCTime.IsZero}}Never{{else}}{{.Metrics.LastGCTime.Format "15:04:05"}}{{end}}</span>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>Page auto-refreshes every 30 seconds | 
               <a href="/metrics">JSON Metrics</a> | 
               <a href="/health">Health Check</a> | 
               <a href="/api/metrics">Prometheus Metrics</a>
            </p>
        </div>
    </div>
</body>
</html>
`
