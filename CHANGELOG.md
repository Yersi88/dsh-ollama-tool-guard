# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 2026-10-29

### Fixed

- **The guard could lock a session completely.** A single 8-second timeout on a shared GPU made every tool call fail closed at once — observed live, including the calls needed to diagnose it. The decision model is now retried: timeouts, network failures, `408`/`425`/`429`/`5xx` and unparseable bodies are attempted again with exponential backoff, while any other `4xx` or a cancelled call stops retrying immediately. Exhausting the retries keeps the documented fail-closed behaviour.
- `timeoutMs` raised from `8000` to `15000` and made per-*attempt*, since the model queues behind the agent's own work.
- **A cancelled call is reported as a cancellation.** Pressing Esc during a review used to surface as a fail-closed denial naming the decision model, so a human's own abort was recorded as an outage. The audit log now records `cancel`.
- **The audit log no longer records argument text.** It stored the first 70 characters of every command, every `file_path` verbatim, the first 90 characters of every URL and the first 90 characters of any other tool's arguments — enough to persist a token or a private path indefinitely. It now stores a hash plus a non-identifying shape (argument count, byte size, line count, file extension).
- **`hardDeny` now matches the bodies of executed scripts.** A root wipe or a fork bomb inside `boom.sh` is denied deterministically instead of depending on the model; before this the patterns only ever saw the command string `bash boom.sh`.

### Added

- **Connection settings.** `endpoint` and `model` are editable in the settings page, with a *Test saved config* button that sends one probe question and reports latency or the failure. The endpoint must be Ollama's System One API (`/v1/systemone`); an OpenAI-compatible URL cannot answer the typed questions, because the decision models are not chat models.
- `sendArguments` (default **on**): send the call's arguments — including whole file bodies for `write`/`edit` — to the model. Off sends only the tool name, working directory and call shape. The settings page has the checkbox next to a warning that turning it off weakens every verdict.
- **The prompt says what the call does and where.** It now leads with the model's classification as a verb (`READING`, `MODIFYING`, `DELETING`, `WRITING`, `SYSTEM CHANGE`) and a deterministic `inside workspace` / `OUTSIDE workspace` label computed from the arguments, followed by a plain-English reason instead of a rule name and a raw score dump.
- Unit tests grew from 14 to 46: retries and backoff, config normalisation, answer validation, `sendArguments`, wrapper-aware root-wipe parsing, symlink containment, concurrent saves and the operation/location labels.
- `retries` (default `2`) and `retryBackoffMs` (default `300`), both configurable and exposed in the settings page alongside `timeoutMs`.

### Changed

- Config loading is one normaliser (`withDefaults`) shared by the file, the settings routes and the seed: a partial nested config keeps every default it does not restate, a wrong-typed field falls back instead of throwing out of the hook, and `rules`/`questions` members are coerced so a hand-edited string cannot silently delete a threshold.
- `isRootWipe()` reads `rm` flags instead of matching their spelling, so `rm -rfv /`, `-r -f`, `--recursive --force`, `--` and `sudo`/`env`/`bash -c` wrappers are denied where the regex missed them. Script bodies are parsed the same way.
- Config saves are serialised through one chain with a unique temp file and `0600`; two open settings tabs could previously corrupt the file into an unparseable state that denied every tool call.
- The failure of a configured `scriptRoot` to resolve is now audited instead of silently disabling script review.

- The npm package now ships `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `test/` and `eval/`; it previously carried only the three runtime files.
- `npm test` runs `node --test` with no path argument, so the quoted glob that older runners may not expand is gone.

### Security

- **The settings routes are now authenticated.** `GET /tool-guard/state` and `POST /tool-guard/config` require the host's browser cookie (`connection.requestRejection`) and answer `401` (or `403` for a foreign Host/Origin) without it. Previously they answered any local request: measured live, the state route returned `200` while the application root returned `401`, which let any local process read the audit tail and rewrite the config — including switching the guard off.
- README and SECURITY state that an `ask` is a **blocking** approval request: with no approval channel in the session it resolves as a cancellation, so a wrong score blocks the call and the refusal is reported as `the user rejected tool "…"`.
- README and SECURITY state the worst-case fail-closed stall (`timeoutMs × (retries + 1)` plus backoff: about 46 s at the defaults, ~15 min at the clamp maxima) instead of leaving it implicit.
- SECURITY states that the default `clef:cloud` model receives every reviewed call's arguments plus any attached script body.

## [0.3.0] — 2026-10-29

First public release.

### Added

- **Per-call review through an Ollama decision model.** Six typed questions — `undo`, `kind`, `self`, `credential`, `sensitive`, `exfil` — scored in one non-autoregressive System One pass, so output tokens cost nothing.
- **Three review layers, cheapest first.** Fixed `hardDeny` patterns and deterministic `egress`/`ingress` patterns decide without a model call; only the remainder reaches the model.
- **Settings page** under Settings → Plugins → Tool Guard: layer toggles, threshold sliders, effect-class checkboxes, `scriptRoot`, and the last 40 decisions with their scores. Served by two host routes, so tuning never requires a file-write escalation.
- **Script-body review.** A `bash` command that executes a local script has that script's contents attached to the review request — 0/6 detected on innocuously-named dangerous scripts without it, 6/6 with it. Bounded to `scriptRoot`, so unrelated documents are never read.
- **JSONL audit log** at `~/.dsh/tool-guard-audit.jsonl`, recording the decision, the rule, the scores and the latency.
- **Config outside the workspace** at `~/.dsh/tool-guard.json`, so the agent's own file sandbox cannot rewrite it. Seeded on first run.
- **Calibration fixtures** in `eval/`, with the measurements behind the `undo` and `sensitive` defaults recorded in the code.
- Unit tests (14, the suite at that tag) and CI on Node 20/22/24.

### Security

- A model verdict can only turn a pass into a prompt; it never denies. Denials come from deterministic patterns or from the guard being unable to run.
- **Fail-closed**: if the decision model is unreachable, every tool call is denied with a reason naming the config path.
- Pattern layers inspect only calls that execute something, so a file that documents a dangerous command is not itself treated as one.
- The settings write route requires an `x-tool-guard` header, which a cross-origin form post cannot set without a preflight.

### Known limitations

- Stateless per call: an operation split across two calls passes both checks individually.
- Exfiltration by a transport the patterns do not name is judged by the model, not by a rule.
- A fork bomb inside a script was classified `read` by the model, and at this release only an inline bomb was covered by pattern (addressed in 0.4.0).
- Resource exhaustion (filling the disk) scores low on every question.
- The settings routes were unauthenticated at this release (addressed in 0.4.0).
