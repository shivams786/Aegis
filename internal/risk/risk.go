package risk

import (
	"time"

	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/tools"
)

const EngineVersion = "risk-v1"

type Result struct {
	Score         int      `json:"score"`
	Level         string   `json:"level"`
	Reasons       []Reason `json:"reasons"`
	EngineVersion string   `json:"engine_version"`
}

type Reason struct {
	Code   string `json:"code"`
	Weight int    `json:"weight"`
}

type Context struct {
	RecentDeniedRequests int
	RecentFailedAuth     int
	AgentRegisteredAt    time.Time
	HourUTC              int
	CrossRegion          bool
	NewResource          bool
}

func Calculate(req invocation.Request, tool tools.Definition, ctx Context) Result {
	score := 0
	reasons := make([]Reason, 0)
	add := func(code string, weight int) {
		score += weight
		reasons = append(reasons, Reason{Code: code, Weight: weight})
	}

	switch tool.Risk {
	case tools.RiskCritical:
		add("TOOL_CRITICAL_RISK", 40)
	case tools.RiskHigh:
		add("TOOL_HIGH_RISK", 25)
	case tools.RiskMedium:
		add("TOOL_MEDIUM_RISK", 12)
	}
	switch tool.SideEffect {
	case tools.SideEffectFinancial:
		add("FINANCIAL_SIDE_EFFECT", 20)
	case tools.SideEffectIrreversibleWrite:
		add("IRREVERSIBLE_WRITE", 20)
	case tools.SideEffectReversibleWrite:
		add("WRITE_SIDE_EFFECT", 8)
	}
	switch tool.DataSensitivity {
	case tools.DataRestricted:
		add("RESTRICTED_DATA", 20)
	case tools.DataConfidential:
		add("CONFIDENTIAL_DATA", 10)
	}
	amount := req.AmountMinor()
	if amount >= 5_000_000 {
		add("LARGE_FINANCIAL_AMOUNT", 30)
	} else if amount >= 1_000_000 {
		add("ELEVATED_FINANCIAL_AMOUNT", 15)
	}
	if req.Agent.TrustLevel <= 1 {
		add("LOW_AGENT_TRUST", 20)
	} else if req.Agent.TrustLevel <= 3 {
		add("MEDIUM_AGENT_TRUST", 8)
	}
	if !ctx.AgentRegisteredAt.IsZero() && time.Since(ctx.AgentRegisteredAt) < 7*24*time.Hour {
		add("NEW_AGENT", 10)
	}
	if ctx.RecentDeniedRequests > 0 {
		add("RECENT_DENIED_REQUESTS", min(15, ctx.RecentDeniedRequests*5))
	}
	if ctx.RecentFailedAuth > 0 {
		add("RECENT_FAILED_AUTHENTICATION", min(15, ctx.RecentFailedAuth*5))
	}
	if ctx.CrossRegion {
		add("CROSS_REGION_REQUEST", 8)
	}
	if ctx.NewResource {
		add("NEW_RESOURCE", 6)
	}
	if ctx.HourUTC >= 0 && (ctx.HourUTC < 6 || ctx.HourUTC > 22) {
		add("UNUSUAL_TIME_OF_DAY", 5)
	}

	if score > 100 {
		score = 100
	}
	return Result{
		Score:         score,
		Level:         level(score),
		Reasons:       reasons,
		EngineVersion: EngineVersion,
	}
}

func level(score int) string {
	switch {
	case score >= 85:
		return "CRITICAL"
	case score >= 65:
		return "HIGH"
	case score >= 35:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
