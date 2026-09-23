package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/fireline-security/fireline-core/internal/api"
	"github.com/fireline-security/fireline-core/internal/domain"
	"github.com/fireline-security/fireline-core/internal/policy"
	"github.com/fireline-security/fireline-core/internal/storage"
	"github.com/fireline-security/fireline-core/internal/storage/memory"
)

// failingRepo is a storage.ObservationRepository whose List/Get can be
// configured to fail. memory.Repository never returns an error from
// either (beyond ErrNotFound), so this is the only way to exercise the
// handlers' 500 "internal error" branches without a real, breakable
// database.
type failingRepo struct {
	listErr error
	getErr  error
}

func (f *failingRepo) Insert(context.Context, domain.Observation) error { return nil }

func (f *failingRepo) Get(context.Context, uuid.UUID) (domain.Observation, error) {
	if f.getErr != nil {
		return domain.Observation{}, f.getErr
	}
	return domain.Observation{}, storage.ErrNotFound
}

func (f *failingRepo) ListByFingerprint(context.Context, domain.Fingerprint) ([]domain.Observation, error) {
	return nil, nil
}

func (f *failingRepo) List(context.Context, int) ([]domain.Observation, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return nil, nil
}

func mustObservation(t *testing.T) domain.Observation {
	t.Helper()
	obs, err := domain.NewObservation(
		domain.SourceRef{Tool: "trivy", RuleID: "CVE-2024-1"},
		domain.IdentityComponents{"package": "openssl"},
		"HIGH",
		json.RawMessage(`{"id":"CVE-2024-1"}`),
		nil,
	)
	if err != nil {
		t.Fatalf("NewObservation: %v", err)
	}
	return obs
}

// mustEngine builds a minimal, always-compiling *policy.Engine: one rule
// matching mustObservation's "HIGH" severity, with zero tolerance so any
// freshly-inserted Observation crosses immediately (same pattern
// internal/policy/engine_test.go uses for immediate-match tests).
func mustEngine(t *testing.T) *policy.Engine {
	t.Helper()
	engine, err := policy.NewEngine(domain.Fireline{
		Name:    "test",
		Version: "1",
		Rules: []domain.Rule{
			{ID: "high-severity", When: `severity_raw == "HIGH"`, Tolerance: "0s"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestListObservations(t *testing.T) {
	repo := memory.New()
	ctx := context.Background()

	obs := mustObservation(t)
	if err := repo.Insert(ctx, obs); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/observations")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var got []domain.Observation
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].ID != obs.ID {
		t.Fatalf("got %+v, want one observation with ID %s", got, obs.ID)
	}
}

func TestListObservations_ValidCustomLimit(t *testing.T) {
	repo := memory.New()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := repo.Insert(ctx, mustObservation(t)); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}

	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/observations?limit=2")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var got []domain.Observation
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d observations, want 2 (limit=2 of 3 inserted)", len(got))
	}
}

func TestListObservations_EmptyIsJSONArrayNotNull(t *testing.T) {
	repo := memory.New()
	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/observations")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got := strings.TrimSpace(string(body)); got != "[]" {
		t.Errorf("body = %q, want %q", got, "[]")
	}
}

func TestListObservations_InvalidLimit(t *testing.T) {
	repo := memory.New()
	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	for _, limit := range []string{"abc", "0", "-5"} {
		resp, err := http.Get(srv.URL + "/api/v1/observations?limit=" + limit)
		if err != nil {
			t.Fatalf("GET ?limit=%s: %v", limit, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("?limit=%s: status = %d, want %d", limit, resp.StatusCode, http.StatusBadRequest)
		}
	}
}

func TestGetObservation(t *testing.T) {
	repo := memory.New()
	ctx := context.Background()

	obs := mustObservation(t)
	if err := repo.Insert(ctx, obs); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/observations/" + obs.ID.String())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var got domain.Observation
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != obs.ID {
		t.Errorf("ID = %s, want %s", got.ID, obs.ID)
	}
}

func TestGetObservation_NotFound(t *testing.T) {
	repo := memory.New()
	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/observations/" + uuid.New().String())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestGetObservation_InvalidID(t *testing.T) {
	repo := memory.New()
	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/observations/not-a-uuid")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestListCrossings(t *testing.T) {
	repo := memory.New()
	ctx := context.Background()

	obs := mustObservation(t)
	if err := repo.Insert(ctx, obs); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/crossings")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var got []domain.Crossing
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].ObservationID != obs.ID || got[0].RuleID != "high-severity" {
		t.Fatalf("got %+v, want one crossing for observation %s", got, obs.ID)
	}
}

func TestListCrossings_EmptyIsJSONArrayNotNull(t *testing.T) {
	repo := memory.New()
	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/crossings")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got := strings.TrimSpace(string(body)); got != "[]" {
		t.Errorf("body = %q, want %q", got, "[]")
	}
}

func TestListCrossings_InvalidLimit(t *testing.T) {
	repo := memory.New()
	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/crossings?limit=abc")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestListObservations_RepoError(t *testing.T) {
	repo := &failingRepo{listErr: errors.New("boom")}
	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/observations")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

func TestListCrossings_RepoError(t *testing.T) {
	repo := &failingRepo{listErr: errors.New("boom")}
	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/crossings")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

func TestGetObservation_RepoError(t *testing.T) {
	repo := &failingRepo{getErr: errors.New("boom")}
	srv := httptest.NewServer(api.NewHandler(repo, mustEngine(t)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/observations/" + uuid.New().String())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}
