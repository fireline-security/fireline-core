package policy

import (
	"testing"

	"github.com/google/uuid"

	"github.com/fireline-security/fireline-core/internal/domain"
)

func crossingFor(obsID uuid.UUID) domain.Crossing {
	return domain.Crossing{RuleID: "high-severity", ObservationID: obsID}
}

func TestDiffNewlyCaught_OnlyNewCrossingsReported(t *testing.T) {
	shared := uuid.New()
	newOnly := uuid.New()

	baseline := []domain.Crossing{crossingFor(shared)}
	current := []domain.Crossing{
		crossingFor(shared),
		crossingFor(newOnly),
	}

	got := DiffNewlyCaught(current, baseline)
	if len(got) != 1 || got[0].ObservationID != newOnly {
		t.Fatalf("got %+v, want exactly the newOnly crossing", got)
	}
}

func TestDiffNewlyCaught_EmptyBaseline_ReturnsAllCurrent(t *testing.T) {
	current := []domain.Crossing{
		crossingFor(uuid.New()),
		crossingFor(uuid.New()),
	}

	got := DiffNewlyCaught(current, nil)
	if len(got) != len(current) {
		t.Fatalf("got %d crossings, want %d", len(got), len(current))
	}
}

func TestDiffNewlyCaught_NoNewCrossings_ReturnsEmpty(t *testing.T) {
	id := uuid.New()
	baseline := []domain.Crossing{crossingFor(id)}
	current := []domain.Crossing{crossingFor(id)}

	got := DiffNewlyCaught(current, baseline)
	if len(got) != 0 {
		t.Fatalf("got %d crossings, want 0: %+v", len(got), got)
	}
}
