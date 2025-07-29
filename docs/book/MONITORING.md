---
name: Monitoring and Performance Guide 
---

# Monitoring and Performance Guide

The Vault Swarm Plugin includes comprehensive monitoring capabilities to track system performance, secret rotation activity, and overall health.

## Overview

The monitoring system tracks:
- System resources (memory, goroutines)
- Secret rotation metrics
- Provider health status
- Ticker behavior and timing
- Error rates and performance

## Web Interface

Access the monitoring dashboard at the configured port (default: 8080):

```
http://localhost:8080
```

### Dashboard Features

- **Real-time Metrics**: Auto-refreshes every 30 seconds
- **Health Status**: Overall system health indicator
- **Memory Usage**: Allocation, system, and heap memory
- **Goroutine Count**: Track concurrent operations
- **Secret Rotation**: Success/failure counts and rates
- **Uptime Tracking**: Monitor system availability

### API Endpoints

#### `/metrics` - JSON Metrics
Returns detailed metrics in JSON format:
```json
{
  "num_goroutines": 5,
  "mem_alloc_bytes": 2048576,
  "mem_sys_bytes": 8388608,
  "secret_rotations": 42,
  "rotation_errors": 2,
  "ticker_heartbeat": "2023-12-01T10:30:00Z",
  "monitoring_start_time": "2023-12-01T10:00:00Z"
}
```

#### `/health` - Health Check
Returns health status for load balancers:
```json
{
  "healthy": true,
  "uptime_seconds": 1800,
  "goroutines": 5,
  "memory_usage_mb": 2,
  "total_rotations": 42,
  "rotation_errors": 2,
  "error_rate": 4.76,
  "ticker_healthy": true
}
```

#### `/api/metrics` - Prometheus Format
Returns metrics in Prometheus exposition format:
```
# HELP vault_swarm_plugin_goroutines Current number of goroutines
# TYPE vault_swarm_plugin_goroutines gauge
vault_swarm_plugin_goroutines 5

# HELP vault_swarm_plugin_memory_bytes Memory usage in bytes
# TYPE vault_swarm_plugin_memory_bytes gauge
vault_swarm_plugin_memory_bytes{type="alloc"} 2048576
vault_swarm_plugin_memory_bytes{type="sys"} 8388608
```

## Performance Monitoring

### Memory Usage

The system tracks three key memory metrics:

- **Allocated Memory**: Currently allocated and in-use memory
- **System Memory**: Total memory obtained from OS
- **Heap Memory**: Memory allocated on the heap

### Goroutine Monitoring

Tracks the number of active goroutines to detect:
- Memory leaks from goroutine accumulation
- Proper cleanup of monitoring routines
- Concurrent operation efficiency

### Garbage Collection

Monitors GC activity:
- Number of GC cycles
- Total pause time
- Last GC timestamp

## Secret Rotation Monitoring

### Metrics Tracked

- **Total Rotations**: Successful secret rotations
- **Rotation Errors**: Failed rotation attempts
- **Error Rate**: Percentage of failed rotations
- **Ticker Health**: Rotation scheduling status

### Ticker Health Check

The system monitors the rotation ticker to ensure:
- Regular heartbeat updates
- Proper scheduling intervals
- Detection of stuck or failed timers

Health is considered poor if no heartbeat for 3x rotation interval.

## Configuration

### Environment Variables

```bash
# Enable monitoring (default: true)
ENABLE_MONITORING=true

# Web interface port (default: 8080)
MONITORING_PORT=8080

# Rotation monitoring interval (default: 10s)
VAULT_ROTATION_INTERVAL=30s
```

### Docker Plugin Configuration

```bash
docker plugin set vault-secrets-plugin:latest \
    ENABLE_MONITORING=true \
    MONITORING_PORT=9090 \
    VAULT_ROTATION_INTERVAL=1m
```

## Integration Examples

### Prometheus Scraping

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'vault-swarm-plugin'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/api/metrics'
    scrape_interval: 30s
```

### Health Check (Docker Swarm)

```yaml
version: '3.8'
services:
  health-checker:
    image: curlimages/curl
    command: |
      sh -c 'while true; do
        curl -f http://plugin-host:8080/health || exit 1
        sleep 30
      done'
```

### Grafana Dashboard

Example queries for Grafana:

```promql
# Memory usage
vault_swarm_plugin_memory_bytes{type="alloc"}

# Goroutine count
vault_swarm_plugin_goroutines

# Rotation rate
rate(vault_swarm_plugin_secret_rotations_total[5m])

# Error rate
rate(vault_swarm_plugin_rotation_errors_total[5m]) / 
rate(vault_swarm_plugin_secret_rotations_total[5m])
```

## Troubleshooting

### High Memory Usage

1. Check goroutine count for leaks
2. Monitor GC frequency and pause times
3. Review secret tracking overhead

### Rotation Failures

1. Check error rate metrics
2. Verify provider connectivity
3. Review ticker health status

### Performance Issues

1. Monitor response times via `/health`
2. Check memory allocation patterns
3. Verify goroutine efficiency

### Common Issues

**Ticker Unhealthy**
- Check rotation interval configuration
- Verify no blocking operations in rotation
- Monitor for deadlocks or long operations

**High Error Rate**
- Review provider authentication
- Check network connectivity
- Validate secret paths and permissions

**Memory Growth**
- Check for goroutine leaks
- Monitor secret tracker growth
- Review cleanup operations

## Best Practices

### Production Monitoring

1. **Set up health checks** for container orchestration
2. **Monitor error rates** and set alerts
3. **Track memory trends** for capacity planning
4. **Use Prometheus integration** for historical data

### Performance Optimization

1. **Tune rotation intervals** based on requirements
2. **Monitor goroutine counts** for efficiency
3. **Set memory limits** for containers
4. **Use health endpoints** in load balancers

### Security Considerations

1. **Restrict monitoring port** access
2. **Use HTTPS** for production monitoring
3. **Avoid exposing metrics** externally without authentication
4. **Monitor for credential rotation** success