// Package api serves fireline-core's HTTP read API for Observations and
// Crossings. See docs/api.md for what it doesn't do yet.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/fireline-security/fireline-core/internal/domain"
	"github.com/fireline-security/fireline-core/internal/policy"
	"github.com/fireline-security/fireline-core/internal/storage"
)

const defaultListLimit = 100

// NewHandler builds an http.Handler serving the read API against repo,
// evaluating Crossings against the pre-compiled engine. It depends only on
// the storage.ObservationRepository interface, so it can be (and is, in
// api_test.go) exercised against the in-memory fake without a real
// database.
func NewHandler(repo storage.ObservationRepository, engine *policy.Engine) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/observations", listObservations(repo))
	mux.HandleFunc("GET /api/v1/observations/{id}", getObservation(repo))
	mux.HandleFunc("GET /api/v1/crossings", listCrossings(repo, engine))
	return mux
}

// parseLimit reads the optional ?limit= query param, defaulting to
// defaultListLimit. ok is false when the caller has already written a 400
// response and the handler should return immediately.
func parseLimit(w http.ResponseWriter, r *http.Request) (limit int, ok bool) {
	limit = defaultListLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return 0, false
		}
		limit = n
	}
	return limit, true
}

func listObservations(repo storage.ObservationRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, ok := parseLimit(w, r)
		if !ok {
			return
		}

		observations, err := repo.List(r.Context(), limit)
		if err != nil {
			slog.Error("list observations", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if observations == nil {
			observations = []domain.Observation{} // never serialize a bare list as JSON null
		}
		writeJSON(w, http.StatusOK, observations)
	}
}

// listCrossings evaluates engine against the Observations repo currently
// holds, live, per request, with asOf = time.Now().UTC(). There is no
// --as-of/--against equivalent over HTTP; historical and diff evaluation
// stay CLI-only (see docs/policy-engine/evaluation.md).
func listCrossings(repo storage.ObservationRepository, engine *policy.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, ok := parseLimit(w, r)
		if !ok {
			return
		}

		observations, err := repo.List(r.Context(), limit)
		if err != nil {
			slog.Error("list observations for crossings", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		crossings, err := engine.Evaluate(observations, time.Now().UTC())
		if err != nil {
			slog.Error("evaluate crossings", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if crossings == nil {
			crossings = []domain.Crossing{} // never serialize a bare list as JSON null
		}
		writeJSON(w, http.StatusOK, crossings)
	}
}

func getObservation(repo storage.ObservationRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "id must be a UUID")
			return
		}

		obs, err := repo.Get(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeError(w, http.StatusNotFound, "observation not found")
				return
			}
			slog.Error("get observation", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, obs)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encode response", "error", err)
	}
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}
