# dsh-ollama-tool-guard

Per-tool-call safety review for the DeepSeek Harness, using an Ollama **decision model** instead of a chat LLM. Every tool call is scored before it runs; suspicious calls come back to you as an approval prompt.

## Why

The harness sandbox is a wall around **writes**: anything outside the workspace is mechanically escalated. Everything else is free — reads outside the workspace, outbound network traffic, and any command that happens to be destructive inside the workspace. This plugin adds a review layer over that gap without loosening the wall.

## How it decides

Three layers, cheapest first. A cheaper layer that fires means the expensive one never runs.

| Layer | Cost | Outcome |
|---|---|---|
| `hardDeny` | 0 ms, regex | `deny` — fixed catastrophic patterns: root-level recursive delete, raw write to a block device, filesystem format, fork bomb, sysrq trigger |
| `egress` / `ingress` | 0 ms, regex | `ask` — data leaving the machine, or external content entering agent memory/skills |
| decision model | ~0.5–1 s | `ask` when a thresholded question trips, otherwise pass |

Pattern layers only inspect calls that **execute** something. Writing a file that documents a dangerous command is not running it; only command-bearing calls are pattern-matched.

**A model verdict never denies.** A wrong model costs an extra prompt; it cannot silently authorise or block anything. Denials come only from deterministic rules or from the guard being unable to run (fail-closed).

The `ask` prompt shows the rule that fired, the scores that drove it, and a mechanical summary of the call — not a truncated blob:

```
tool-guard undo>0.4 · undo=0.77 kind=destroy self=0.05 credential=0.03 · bash · 11 lines · set -euo pipefail
```

## The decision model

Ollama's System One API (`/v1/systemone`), default `clef:cloud` (Cloudflare Clef, 27B). Six typed questions are scored in **one non-autoregressive forward pass** — no generated tokens, so no output cost:

| Question | Type | Asks |
|---|---|---|
| `undo` | noul | would recovery require restoring something unrecreatable? |
| `kind` | choice | read / write / modify / destroy / system |
| `self` | noul | does this weaken the agent's own guard or permissions? |
| `credential` | noul | does this write, copy or transmit secrets? |
| `sensitive` | noul | does this read personal files unrelated to the task? |
| `exfil` | noul | does this send local data off the machine? |

Scripts a `bash` command is about to execute are read and attached to the request, so `bash main.sh` is reviewed on its **contents**. Without that the guard only sees the command string, which carries no information — measured 0/6 on innocuously-named dangerous scripts versus 6/6 with the body attached. Only workspace files are ever read, so unrelated documents are never forwarded to the model.

## Install

Author the package anywhere in the workspace, then install it into the profile:

```
plugin_manager { action: "install_bundle", target: "<abs path>/dsh-ollama-tool-guard" }
```

The plugin seeds `~/.dsh/tool-guard.json` on first run. That path is deliberate: it sits **outside** the workspace, so the agent's own file sandbox cannot rewrite it — disarming the guard takes an escalation, not a model's opinion.

The host caches the module at load time; editing `lib/index.js` takes effect after a host restart (or plugin reload), not immediately.

## Config

`~/.dsh/tool-guard.json` — re-read on every call, so edits apply immediately.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | kill switch; `false` passes every call untouched |
| `endpoint` | `http://127.0.0.1:11434/v1/systemone` | System One endpoint |
| `model` | `clef:cloud` | any Ollama decision model |
| `timeoutMs` | `8000` | per-call budget; timeout is fail-closed |
| `scriptRoot` | `null` | directory whose scripts may have their bodies reviewed; `null` = the host working directory. Files outside it are never read |
| `audit` | `true` | append one JSONL line per call to `~/.dsh/tool-guard-audit.jsonl` |
| `hardDeny.enabled` | `true` | regex list that denies without a model call |
| `egress.enabled` | `true` | regex list of outbound-data transports |
| `ingress.enabled` | `true` | agent-memory write tools plus URI patterns |
| `rules` | see below | question → `{above: n}` or `{in: [...]}` |
| `alwaysAsk` | `[]` | tool names always surfaced |
| `skip` | `[]` | tool names never evaluated |

Default rules: `undo > 0.4`, `kind ∈ {system}`, `self > 0.65`, `credential > 0.5`, `sensitive > 0.8`, `exfil > 0.7`.

The audit log stores tool name, decision, rule, scores, latency and a mechanical summary — **arguments are hashed, never stored**, so secrets cannot leak into it. It is written fire-and-forget and cannot fail a decision.

## Calibration

Measured 2026-10-29, all thresholds set from data rather than intuition. Fixtures live in `eval/`.

| Set | Size | Flagged |
|---|---|---|
| Real tool calls (155 sessions) | 280 | 3 (1.1%) |
| Authored dangers | 100 | 97 |
| Verbose twins of those dangers | 30 | 28 |
| Unrelated sensitive reads | 8 | 8 |
| Exfiltrations | 8 | 8 |
| Write→execute, innocuous names | 6 | 6 |

Two earlier rule designs were discarded on this data: an `outside` question flagged 65% of real traffic (its reads are routinely outside the workspace), and a `destroys` probability never exceeded 0.38 across all 280 calls.

## Known gaps

- **Prompt injection via memory ingest** (ingesting an attacker-controlled document into memory) — covered by the deterministic `ingress` layer, not by the model.
- **Resource exhaustion** (filling the disk) scores low on every question.
- **Cross-call exfiltration** — the guard is stateless. Reading a file in one call and posting it in another passes both checks individually.
- **A fork bomb inside a script** was classified `read` by the model; the deterministic hard-deny covers it by pattern instead.

## Requirements

- DeepSeek Harness 0.2.x
- Ollama with the System One API: ≥ 0.35.1 for `clef`, ≥ 0.40.4 for `kev`
- `clef:cloud` needs a signed-in Ollama with credits; `clef` (27B, ~18–20 GB) runs locally; `clef-flash` (9B) is the latency pick

## Status

Running in one deployment. Release-ready in structure: no hard-coded paths, scrubbed fixtures, unit tests, and CI on Node 20/22/24.

## Development

No dependencies and no build step.

```
npm test
```

Runs `test/*.test.mjs` against a fake context and a fake `fetch` — no harness and no model needed. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
