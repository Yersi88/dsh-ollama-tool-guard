# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-10-29

First public release.

### Added

- **Per-call review through an Ollama decision model.** Six typed questions — `undo`, `kind`, `self`, `credential`, `sensitive`, `exfil` — scored in one non-autoregressive System One pass, so output tokens cost nothing.
- **Three review layers, cheapest first.** Fixed `hardDeny` patterns and deterministic `egress`/`ingress` patterns decide without a model call; only the remainder reaches the model.
- **Settings page** under Settings → Plugins → Tool Guard: layer toggles, threshold sliders, effect-class checkboxes, `scriptRoot`, and the last 40 decisions with their scores. Served by two host routes, so tuning never requires a file-write escalation.
- **Script-body review.** A `bash` command that executes a local script has that script's contents attached to the review request — 0/6 detected on innocuously-named dangerous scripts without it, 6/6 with it. Bounded to `scriptRoot`, so unrelated documents are never read.
- **JSONL audit log** at `~/.dsh/tool-guard-audit.jsonl`. Arguments are hashed, never stored; the log records the decision, the rule, the scores and the latency.
- **Config outside the workspace** at `~/.dsh/tool-guard.json`, so the agent's own file sandbox cannot rewrite it. Seeded on first run.
- **Calibration fixtures** in `eval/` plus the recorded measurements behind every default threshold.
- Unit tests (14) and CI on Node 20/22/24.

### Security

- A model verdict can only turn a pass into a prompt; it never denies. Denials come from deterministic patterns or from the guard being unable to run.
- **Fail-closed**: if the decision model is unreachable, every tool call is denied with a reason naming the config path.
- Pattern layers inspect only calls that execute something, so a file that documents a dangerous command is not itself treated as one.
- The settings write route requires an `x-tool-guard` header, which a cross-origin form post cannot set without a preflight.

### Known limitations

- Stateless per call: an operation split across two calls passes both checks individually.
- Exfiltration by a transport the patterns do not name is judged by the model, not by a rule.
- A fork bomb inside a script was classified `read` by the model; the deterministic pattern covers it instead.
- Resource exhaustion (filling the disk) scores low on every question.
