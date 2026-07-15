package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/risk"
	"github.com/aegis/aegis/internal/tools"
)

type OPAEvaluator struct {
	BaseURL      string
	DecisionPath string
	PolicyHash   string
	PolicyVersion string
	Client       *http.Client
	Timeout      time.Duration
}

func (e OPAEvaluator) Evaluate(req invocation.Request, tool tools.Definition, riskResult risk.Result) (Decision, error) {
	if e.BaseURL == "" || e.DecisionPath == "" {
		return Decision{}, errors.New("opa evaluator is not configured")
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	client := e.Client
	if client == nil {
		client = http.DefaultClient
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	input := map[string]any{
		"input": map[string]any{
			"delegation": map[string]any{
				"id":    req.DelegationID,
				"valid": true,
			},
			"invocation": req,
			"tool": map[string]any{
				"id": req.Tool.ID,
				"active": tool.Active,
				"risk": tool.Risk,
				"side_effect": tool.SideEffect,
				"data_sensitivity": tool.DataSensitivity,
				"schema_hash": tool.SchemaHash,
			},
			"arguments": req.Arguments,
			"risk": riskResult,
		},
	}
	body, err := json.Marshal(input)
	if err != nil {
		return Decision{}, fmt.Errorf("marshal opa input: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.BaseURL+"/v1/data/"+e.DecisionPath, bytes.NewReader(body))
	if err != nil {
		return Decision{}, fmt.Errorf("create opa request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		return Decision{}, fmt.Errorf("evaluate opa policy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Decision{}, fmt.Errorf("opa returned status %d", resp.StatusCode)
	}
	var payload opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return Decision{}, fmt.Errorf("decode opa response: %w", err)
	}
	decision := payload.Result
	if decision.PolicyHash == "" {
		decision.PolicyHash = e.PolicyHash
	}
	if decision.PolicyVer == "" {
		decision.PolicyVer = e.PolicyVersion
	}
	if decision.EvaluatedAt.IsZero() {
		decision.EvaluatedAt = time.Now().UTC()
	}
	if decision.Decision == "" {
		decision.Decision = invocation.DecisionDeny
		decision.Allow = false
		decision.ReasonCodes = []string{"OPA_EMPTY_DECISION"}
	}
	return withID(decision), nil
}

type opaResponse struct {
	Result Decision `json:"result"`
}
