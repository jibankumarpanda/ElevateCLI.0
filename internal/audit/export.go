// Package audit ships saved scan reports to optional centralized audit
// endpoints. Export is best-effort and never blocks local analysis: a failed
// ship is surfaced as a warning by the caller, and the local record is already
// durable.
package audit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Exporter POSTs report payloads to a centralized audit endpoint.
type Exporter struct {
	// Endpoint is the absolute URL that receives report payloads.
	Endpoint string
	// Token, when non-empty, is sent as a bearer credential.
	Token string
	// Client is the HTTP client used for requests. A sane default is used when
	// nil.
	Client *http.Client
}

// New returns an Exporter for endpoint, authenticating with token.
func New(endpoint, token string) *Exporter {
	return &Exporter{
		Endpoint: endpoint,
		Token:    token,
		Client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Export sends payload as application/json. It returns an error when the
// endpoint rejects the payload or is unreachable.
func (e *Exporter) Export(ctx context.Context, payload []byte) error {
	if e.Endpoint == "" {
		return fmt.Errorf("audit export: no endpoint configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("audit export: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.Token != "" {
		req.Header.Set("Authorization", "Bearer "+e.Token)
	}
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("audit export: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("audit export: endpoint returned %s: %s", resp.Status, string(bytes.TrimSpace(body)))
	}
	return nil
}
