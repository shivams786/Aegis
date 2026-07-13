package risk

import (
	"testing"

	"github.com/aegis/aegis/internal/authn"
	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/tools"
)

func TestCalculateHighValueRefundIsHighRisk(t *testing.T) {
	def := tools.DemoDefinitions()[0]
	req := invocation.Request{
		Agent: authn.Agent{ID: "agent_low_trust", TrustLevel: 1},
		Arguments: map[string]any{
			"amount_minor": int64(5_000_000),
		},
	}

	result := Calculate(req, def, Context{})
	if result.Score < 65 {
		t.Fatalf("expected high score, got %#v", result)
	}
	if result.EngineVersion != EngineVersion {
		t.Fatalf("unexpected engine version: %s", result.EngineVersion)
	}
}
