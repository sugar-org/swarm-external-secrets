package monitoring

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleDashboardRendersHTML(t *testing.T) {
	monitor := NewMonitor(time.Second)
	monitor.SetRotationInterval(10 * time.Second)

	web := NewWebInterface(monitor, 8080)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	web.handleDashboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if got := rec.Header().Get(contentTypeHeader); got != "text/html" {
		t.Fatalf("expected content type %q, got %q", "text/html", got)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Vault Swarm Plugin Monitor") {
		t.Fatalf("expected dashboard HTML in response body, got %q", body)
	}
}
