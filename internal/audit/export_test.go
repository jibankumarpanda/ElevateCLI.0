package audit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExportPostsJSONWithBearer(t *testing.T) {
	var gotAuth, gotCT string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	ex := New(srv.URL, "s3cr3t")
	if err := ex.Export(context.Background(), []byte(`{"id":"scan-1"}`)); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if gotAuth != "Bearer s3cr3t" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if string(body) != `{"id":"scan-1"}` {
		t.Errorf("body = %q", body)
	}
}

func TestExportErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()

	if err := New(srv.URL, "").Export(context.Background(), []byte("{}")); err == nil {
		t.Fatal("expected error for non-2xx response")
	}
}

func TestExportNoEndpoint(t *testing.T) {
	if err := New("", "").Export(context.Background(), []byte("{}")); err == nil {
		t.Fatal("expected error when no endpoint configured")
	}
}

func TestExportUnreachable(t *testing.T) {
	if err := New("http://127.0.0.1:0", "").Export(context.Background(), []byte("{}")); err == nil {
		t.Fatal("expected error for unreachable endpoint")
	}
}
