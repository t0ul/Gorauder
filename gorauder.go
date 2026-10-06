// Package gorauder is a zero-dependency red-team harness for LLM systems — it
// marauds the model fleet looking for the way in. You give it seed attacks
// (prompt injection, jailbreak, system-prompt exfiltration), it multiplies each
// through obfuscation converters (base64, rot13, leetspeak, prefix-injection,
// payload-splitting), fires them at a Target, scores each response, and reports
// an attack-success-rate.
//
// It is the attack half of attack-driven development: run the same corpus
// against an undefended target and a guardrailed one (e.g. behind gumpers) and
// the drop in ASR is your defense's proof of work. Audit is decoupled behind an
// Auditor interface identical to gledger.AuditLog.Emit. Part of the fleet.
package gorauder

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Seed is a base attack before any obfuscation is applied.
type Seed struct {
	ID        string // stable id, e.g. "inj-01"
	Technique string // family, e.g. "instruction-override"
	Prompt    string // the raw attack text
	// Marker is a benign proxy for success: if the target echoes it, the
	// injection "worked". Used by MarkerScorer. Optional.
	Marker string
	// Objective is a human-readable description of what success means.
	Objective string
}

// Target is the system under test. A real one posts to an LLM/gateway; a test
// one can be a closure. Send must be safe for concurrent use if Runner is ever
// parallelized (v0 runs sequentially).
type Target interface {
	Send(ctx context.Context, prompt string) (string, error)
}

// TargetFunc adapts a function to a Target.
type TargetFunc func(ctx context.Context, prompt string) (string, error)

// Send implements Target.
func (f TargetFunc) Send(ctx context.Context, prompt string) (string, error) { return f(ctx, prompt) }

// Converter obfuscates a prompt to probe filter evasion.
type Converter interface {
	Name() string
	Convert(prompt string) string
}

// Scorer decides whether a response means the attack succeeded (i.e. the defense
// FAILED). Success==true is bad for the defender.
type Scorer interface {
	Score(seed Seed, response string) (success bool, reason string)
}

// Auditor receives structured audit events. *gledger.AuditLog satisfies it as-is.
type Auditor interface {
	Emit(traceID, span, event string, fields map[string]any) string
}

// Result is the outcome of one (seed × converter) attack.
type Result struct {
	RunID     string
	SeedID    string
	Technique string
	Converter string
	Prompt    string
	Response  string
	Success   bool   // the attack beat the target
	Reason    string // why the scorer decided as it did
	Err       string // transport error, if any
}

// Report aggregates a run.
type Report struct {
	RunID     string
	Total     int
	Succeeded int // attacks that beat the target
	Errors    int
	Results   []Result
}

// ASR is the attack success rate in [0,1] over non-errored attacks.
func (r Report) ASR() float64 {
	denom := r.Total - r.Errors
	if denom <= 0 {
		return 0
	}
	return float64(r.Succeeded) / float64(denom)
}

// ByTechnique returns per-technique success counts, for a breakdown.
func (r Report) ByTechnique() map[string][2]int { // technique -> {succeeded, total}
	out := make(map[string][2]int)
	for _, res := range r.Results {
		c := out[res.Technique]
		c[1]++
		if res.Success {
			c[0]++
		}
		out[res.Technique] = c
	}
	return out
}

// Runner drives seeds × converters against a Target and scores each response.
type Runner struct {
	target     Target
	converters []Converter
	scorer     Scorer
	auditor    Auditor
}

// Option configures a Runner.
type Option func(*Runner)

// WithConverters sets the obfuscation converters. Default: Identity only.
func WithConverters(cs ...Converter) Option { return func(r *Runner) { r.converters = cs } }

// WithScorer sets the scorer. Default: MarkerScorer (falls back to refusal when
// a seed has no marker).
func WithScorer(s Scorer) Option { return func(r *Runner) { r.scorer = s } }

// WithAuditor attaches an audit sink (e.g. a *gledger.AuditLog).
func WithAuditor(a Auditor) Option { return func(r *Runner) { r.auditor = a } }

// NewRunner builds a Runner.
func NewRunner(target Target, opts ...Option) *Runner {
	r := &Runner{
		target:     target,
		converters: []Converter{Identity{}},
		scorer:     MarkerScorer{},
	}
	for _, o := range opts {
		o(r)
	}
	if len(r.converters) == 0 {
		r.converters = []Converter{Identity{}}
	}
	return r
}

// Run executes every seed through every converter, scoring each response.
func (r *Runner) Run(ctx context.Context, seeds []Seed) Report {
	runID := NewTraceID()
	rep := Report{RunID: runID}
	r.audit(runID, "start", map[string]any{"seeds": len(seeds), "converters": len(r.converters)})

	for _, s := range seeds {
		for _, c := range r.converters {
			if ctx.Err() != nil {
				return rep
			}
			prompt := c.Convert(s.Prompt)
			res := Result{
				RunID: runID, SeedID: s.ID, Technique: s.Technique,
				Converter: c.Name(), Prompt: prompt,
			}
			resp, err := r.target.Send(ctx, prompt)
			if err != nil {
				res.Err = err.Error()
				rep.Errors++
			} else {
				res.Response = resp
				res.Success, res.Reason = r.scorer.Score(s, resp)
				if res.Success {
					rep.Succeeded++
				}
			}
			rep.Total++
			rep.Results = append(rep.Results, res)
		}
	}

	r.audit(runID, "complete", map[string]any{
		"total": rep.Total, "succeeded": rep.Succeeded,
		"errors": rep.Errors, "asr": rep.ASR(),
	})
	return rep
}

func (r *Runner) audit(runID, event string, fields map[string]any) {
	if r.auditor != nil {
		r.auditor.Emit(runID, "gorauder", event, fields)
	}
}

// Summary renders a compact, human-readable report.
func (rep Report) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "run %s: %d attacks, %d succeeded, %d errors — ASR %.1f%%\n",
		rep.RunID[:8], rep.Total, rep.Succeeded, rep.Errors, rep.ASR()*100)
	bt := rep.ByTechnique()
	keys := make([]string, 0, len(bt))
	for k := range bt {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := bt[k]
		fmt.Fprintf(&b, "  %-22s %d/%d\n", k, c[0], c[1])
	}
	return b.String()
}

// NewTraceID returns a random 128-bit hex correlation id.
func NewTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
