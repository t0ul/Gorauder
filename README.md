# gorauder

A zero-dependency **red-team harness** for LLM systems — it marauds your model
fleet looking for the way in. Pure Go standard library, deterministic, scriptable
in CI.

Part of *the fleet* — build-your-own Go security tools. gorauder is the attack
side (the Go-native answer to a Python red-teaming toolkit); it pairs with
[`gumpers`](https://github.com/t0ul/gumpers) (guardrails),
[`gouncer`](https://github.com/t0ul/gouncer) (gateway),
[`gledger`](https://github.com/t0ul/gledger) (audit), and
[`goflage`](https://github.com/t0ul/goflage) (redaction).

## The ADD loop

gorauder is the *attack* half of attack-driven development. Point the same corpus
at an undefended target and a guardrailed one, and the drop in **attack-success
rate (ASR)** is your defense's proof of work:

```
undefended target   → ASR 100%
behind gumpers rails → ASR   6%   ← the number your module can claim
```

## How it works

- **Seeds** — a benign-by-design corpus (`DefaultSeeds`). Instruction-override
  seeds carry a harmless success marker (`PWNED-01`) as a proxy for "the
  injection worked", so success scores deterministically with no genuinely
  harmful content. Prompt-exfiltration seeds score by canary instead.
- **Converters** — each seed is multiplied through obfuscation strategies that
  probe filter evasion: `identity`, `base64`, `rot13`, `leetspeak`,
  `prefix-injection`, `payload-splitting`.
- **Target** — the system under test, behind a one-method interface. The CLI
  ships an OpenAI-compatible HTTP target; tests use closures.
- **Scorer** — decides whether a response means the attack beat the defense:
  `MarkerScorer`, `RefusalScorer`, `CanaryScorer`, and `BlockAwareScorer`
  (counts a defender's explicit block as a failed attack).
- **Report** — totals, per-technique breakdown, and `ASR()`.

```go
runner := gorauder.NewRunner(target,
    gorauder.WithConverters(gorauder.AllConverters()...),
    gorauder.WithScorer(gorauder.MarkerScorer{}),
    gorauder.WithAuditor(auditLog), // e.g. *gledger.AuditLog
)
rep := runner.Run(ctx, gorauder.DefaultSeeds())
fmt.Print(rep.Summary())
```

## CLI

```sh
go build ./cmd/gorauder
./gorauder -dry                                              # print every generated attack
./gorauder -url http://127.0.0.1:4000/v1/chat/completions -model planner
./gorauder -url ... -model planner -canary ZX9-CANARY-7Q    # also score prompt leaks
```

Exit code is `2` when any attack succeeded (ASR > 0), so it fails CI the moment a
regression reopens a hole.

## Test

```sh
go test ./...
```

## Status

v0. Static seed corpus + deterministic converters and scorers. Not yet:
multi-turn/crescendo attacks, model-graded scoring, or feeding successful attacks
back as new seeds (iterative search).

## Ethics

The built-in corpus is deliberately benign — it tests whether a system can be
*steered off its instructions*, using harmless proxy markers, not how to produce
harmful content. Only run it against systems you own or are authorized to test.
