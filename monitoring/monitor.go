package monitoring

import (
	"context"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Metrics holds various monitoring metrics
type Metrics struct {
	mu                   sync.RWMutex
	NumGoroutines        int           `json:"num_goroutines"`
	MemAllocBytes        uint64        `json:"mem_alloc_bytes"`
	MemSysBytes          uint64        `json:"mem_sys_bytes"`
	MemHeapBytes         uint64        `json:"mem_heap_bytes"`
	NumGC                uint32        `json:"num_gc"`
	GCPauseTotal         time.Duration `json:"gc_pause_total"`
	LastGCTime           time.Time     `json:"last_gc_time"`
	SecretRotations      int64         `json:"secret_rotations"`
	SecretRotationErrors int64         `json:"secret_rotation_errors"`
	TickerHeartbeat      time.Time     `json:"ticker_heartbeat"`
	MonitoringStartTime  time.Time     `json:"monitoring_start_time"`
	RotationInterval     time.Duration `json:"rotation_interval"`
}

// Monitor handles system monitoring and metrics collection
type Monitor struct {
	metrics     *Metrics
	ctx         context.Context
	cancel      context.CancelFunc
	interval    time.Duration
	listeners   []chan *Metrics
	listenersMu sync.RWMutex
	lastLogTime time.Time
}

// NewMonitor creates a new monitoring instance
func NewMonitor(interval time.Duration) *Monitor {
	ctx, cancel := context.WithCancel(context.Background())

	return &Monitor{
		metrics: &Metrics{
			MonitoringStartTime: time.Now(),
		},
		ctx:         ctx,
		cancel:      cancel,
		interval:    interval,
		lastLogTime: time.Now(),
	}
}

// Start begins the monitoring process
func (m *Monitor) Start() {
	go m.monitorLoop()
	log.Printf("Started system monitoring with interval: %v", m.interval)
}

// Stop stops the monitoring process
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}

	// Close all listener channels
	m.listenersMu.Lock()
	for _, listener := range m.listeners {
		close(listener)
	}
	m.listeners = nil
	m.listenersMu.Unlock()

	log.Printf("Stopped system monitoring")
}

// GetMetrics returns a copy of current metrics
func (m *Monitor) GetMetrics() *Metrics {
	m.metrics.mu.RLock()
	defer m.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions
	return &Metrics{
		NumGoroutines:        m.metrics.NumGoroutines,
		MemAllocBytes:        m.metrics.MemAllocBytes,
		MemSysBytes:          m.metrics.MemSysBytes,
		MemHeapBytes:         m.metrics.MemHeapBytes,
		NumGC:                m.metrics.NumGC,
		GCPauseTotal:         m.metrics.GCPauseTotal,
		LastGCTime:           m.metrics.LastGCTime,
		SecretRotations:      m.metrics.SecretRotations,
		SecretRotationErrors: m.metrics.SecretRotationErrors,
		TickerHeartbeat:      m.metrics.TickerHeartbeat,
		MonitoringStartTime:  m.metrics.MonitoringStartTime,
		RotationInterval:     m.metrics.RotationInterval,
	}
}

// IncrementSecretRotations increments the secret rotation counter
func (m *Monitor) IncrementSecretRotations() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	m.metrics.SecretRotations++
}

// IncrementRotationErrors increments the rotation error counter
func (m *Monitor) IncrementRotationErrors() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	m.metrics.SecretRotationErrors++
}

// UpdateTickerHeartbeat updates the ticker heartbeat timestamp
func (m *Monitor) UpdateTickerHeartbeat() {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	m.metrics.TickerHeartbeat = time.Now()
}

// SetRotationInterval sets the rotation interval for tracking
func (m *Monitor) SetRotationInterval(interval time.Duration) {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	m.metrics.RotationInterval = interval
}

// AddListener adds a metrics listener channel
func (m *Monitor) AddListener() <-chan *Metrics {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()

	ch := make(chan *Metrics, 10) // Buffered to prevent blocking
	m.listeners = append(m.listeners, ch)
	return ch
}

// RemoveListener removes a metrics listener channel
func (m *Monitor) RemoveListener(ch <-chan *Metrics) {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()

	for i, listener := range m.listeners {
		if listener == ch {
			close(listener)
			m.listeners = append(m.listeners[:i], m.listeners[i+1:]...)
			break
		}
	}
}

// monitorLoop runs the main monitoring loop
func (m *Monitor) monitorLoop() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return

		case <-ticker.C:
			m.collectMetrics()
			m.notifyListeners()
		}
	}
}

// collectMetrics gathers current system metrics
func (m *Monitor) collectMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()

	m.metrics.NumGoroutines = runtime.NumGoroutine()
	m.metrics.MemAllocBytes = memStats.Alloc
	m.metrics.MemSysBytes = memStats.Sys
	m.metrics.MemHeapBytes = memStats.HeapAlloc
	m.metrics.NumGC = memStats.NumGC

	m.metrics.GCPauseTotal = time.Duration(uint64ToInt64(memStats.PauseTotalNs))

	if memStats.NumGC > 0 {
		// LastGC is nanoseconds since 1970, convert to time.Time
		m.metrics.LastGCTime = time.Unix(0, uint64ToInt64(memStats.LastGC))
	}

	// Log metrics every 5 minutes
	if time.Since(m.lastLogTime) >= 5*time.Minute {
		m.logMetrics()
		m.lastLogTime = time.Now()
	}
}

// notifyListeners sends metrics to all registered listeners
func (m *Monitor) notifyListeners() {
	if len(m.listeners) == 0 {
		return
	}

	metrics := m.GetMetrics()

	m.listenersMu.RLock()
	defer m.listenersMu.RUnlock()

	for _, listener := range m.listeners {
		select {
		case listener <- metrics:
		default:
			// Channel is full, skip this update
		}
	}
}

// logMetrics logs current metrics at info level
func (m *Monitor) logMetrics() {
	log.WithFields(log.Fields{
		"goroutines":       m.metrics.NumGoroutines,
		"memory_alloc_mb":  m.metrics.MemAllocBytes / 1024 / 1024,
		"memory_sys_mb":    m.metrics.MemSysBytes / 1024 / 1024,
		"memory_heap_mb":   m.metrics.MemHeapBytes / 1024 / 1024,
		"num_gc":           m.metrics.NumGC,
		"secret_rotations": m.metrics.SecretRotations,
		"rotation_errors":  m.metrics.SecretRotationErrors,
		"uptime_minutes":   time.Since(m.metrics.MonitoringStartTime).Minutes(),
	}).Info("System metrics snapshot")
}

// CheckTickerHealth checks if the ticker is working properly
func (m *Monitor) CheckTickerHealth() bool {
	m.metrics.mu.RLock()
	defer m.metrics.mu.RUnlock()

	if m.metrics.TickerHeartbeat.IsZero() {
		return true // No heartbeat yet, assume healthy
	}

	// Consider ticker unhealthy if no heartbeat for 3x the rotation interval
	maxAge := m.metrics.RotationInterval * 3
	if maxAge == 0 {
		maxAge = 5 * time.Minute // Default to 5 minutes
	}

	return time.Since(m.metrics.TickerHeartbeat) < maxAge
}

// GetHealthStatus returns overall health status
func (m *Monitor) GetHealthStatus() map[string]interface{} {
	metrics := m.GetMetrics()

	return map[string]interface{}{
		"healthy":          m.CheckTickerHealth(),
		"uptime_seconds":   time.Since(metrics.MonitoringStartTime).Seconds(),
		"goroutines":       metrics.NumGoroutines,
		"memory_usage_mb":  metrics.MemAllocBytes / 1024 / 1024,
		"total_rotations":  metrics.SecretRotations,
		"rotation_errors":  metrics.SecretRotationErrors,
		"error_rate":       m.calculateErrorRate(),
		"ticker_last_beat": metrics.TickerHeartbeat,
		"ticker_healthy":   m.CheckTickerHealth(),
	}
}

// calculateErrorRate calculates the error rate for secret rotations
func (m *Monitor) calculateErrorRate() float64 {
	m.metrics.mu.RLock()
	defer m.metrics.mu.RUnlock()

	total := m.metrics.SecretRotations + m.metrics.SecretRotationErrors
	if total == 0 {
		return 0.0
	}

	return float64(m.metrics.SecretRotationErrors) / float64(total) * 100.0
}
