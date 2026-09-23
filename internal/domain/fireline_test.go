package domain

import (
	"errors"
	"testing"
	"time"
)

func validFireline() Fireline {
	return Fireline{
		Name:    "baseline",
		Version: "1",
		Rules: []Rule{
			{ID: "high-severity", When: `severity_raw == "HIGH"`, Tolerance: "24h"},
		},
	}
}

func TestFireline_Validate(t *testing.T) {
	if err := validFireline().Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFireline_Validate_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(Fireline) Fireline
		wantErr error
	}{
		{
			name:    "empty name",
			mutate:  func(f Fireline) Fireline { f.Name = ""; return f },
			wantErr: ErrFirelineNoName,
		},
		{
			name:    "empty version",
			mutate:  func(f Fireline) Fireline { f.Version = ""; return f },
			wantErr: ErrFirelineNoVersion,
		},
		{
			name:    "no rules",
			mutate:  func(f Fireline) Fireline { f.Rules = nil; return f },
			wantErr: ErrFirelineNoRules,
		},
		{
			name: "empty rule id",
			mutate: func(f Fireline) Fireline {
				f.Rules = []Rule{{ID: "", When: "true"}}
				return f
			},
			wantErr: ErrRuleNoID,
		},
		{
			name: "duplicate rule ids",
			mutate: func(f Fireline) Fireline {
				f.Rules = []Rule{
					{ID: "dup", When: "true"},
					{ID: "dup", When: "false"},
				}
				return f
			},
			wantErr: ErrRuleDuplicateID,
		},
		{
			name: "empty when",
			mutate: func(f Fireline) Fireline {
				f.Rules = []Rule{{ID: "r1", When: ""}}
				return f
			},
			wantErr: ErrRuleNoWhen,
		},
		{
			name: "unparsable tolerance",
			mutate: func(f Fireline) Fireline {
				f.Rules = []Rule{{ID: "r1", When: "true", Tolerance: "not-a-duration"}}
				return f
			},
			wantErr: ErrRuleBadTolerance,
		},
		{
			name: "negative tolerance",
			mutate: func(f Fireline) Fireline {
				f.Rules = []Rule{{ID: "r1", When: "true", Tolerance: "-1h"}}
				return f
			},
			wantErr: ErrRuleBadTolerance,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.mutate(validFireline())
			if err := f.Validate(); !errors.Is(err, tt.wantErr) {
				t.Errorf("got error %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestRule_ToleranceDuration(t *testing.T) {
	tests := []struct {
		name      string
		tolerance string
		want      time.Duration
		wantErr   error
	}{
		{"empty defaults to zero", "", 0, nil},
		{"valid duration", "168h", 168 * time.Hour, nil},
		{"zero duration", "0s", 0, nil},
		{"unparsable", "not-a-duration", 0, ErrRuleBadTolerance},
		{"negative", "-1h", 0, ErrRuleBadTolerance},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Rule{ID: "r1", When: "true", Tolerance: tt.tolerance}
			got, err := r.ToleranceDuration()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got error %v, want %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("got duration %v, want %v", got, tt.want)
			}
		})
	}
}
