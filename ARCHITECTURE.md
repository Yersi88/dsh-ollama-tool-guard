# Architecture

How the guard decides, and where its numbers come from. The user-facing view is [README.md](README.md); the security posture is [SECURITY.md](SECURITY.md).

## Three layers, cheapest first

A layer that fires means the more expensive ones never run.

| Layer | Cost | Outcome |
|---|---|---|
| `hardDeny` | 0 ms, regex | **deny** — fixed catastrophic patterns: root-level recursive delete, raw write to a block device, filesystem format, fork bomb, sysrq trigger |
| `egress` / `ingress` | 0 ms, regex | **ask** — data leaving the machine, or fetched content about to run |
| decision model | ~0.5–1 s | **ask** when a thresholded question trips, otherwise pass |

The layers do not see the same thing, and the difference matters. `hardDeny` reads the command string **and** the bodies of the scripts that command executes, so a wipe hidden in `boom.sh` is denied like the inline one. `egress` and `ingress` both read the command string only: `egress` looks for the transport shapes that carry data out, `ingress` for the shapes where bytes fetched from the internet reach an interpreter — `| sh`, `bash <(curl …)`, download→`chmod +x`→run, clone→run, `eval $(curl …)`. Nothing is matched against a file the call merely reads, and a plain download is not ingress.

**A model verdict never denies.** A wrong high score costs a prompt. A wrong low score is a missed catch and the call proceeds — that false-negative rate is the layer's residual risk, not a boundary. Denials come only from the deterministic rules or from the guard being unable to run.

An `ask` **blocks**. When the session cannot show an approval prompt — a delegated or headless run, or prompts disabled — the host resolves it as a cancellation and the call is aborted before dispatch, reporting `the user rejected tool "…"` for a human who was never asked.

## The decision model

Ollama's System One API (`/v1/systemone`). Six typed questions are scored in one non-autoregressive forward pass — no generated tokens, so no output cost:

| Question | Type | Asks |
|---|---|---|
| `undo` | noul | would recovery require restoring something unrecreatable? |
| `kind` | choice | read / write / modify / destroy / system |
| `self` | noul | does this weaken the agent's own guard or permissions? |
| `credential` | noul | does this write, copy or transmit secrets? |
| `sensitive` | noul | does this read personal files unrelated to the task? |
| `exfil` | noul | does this send local data off the machine? |

Scripts a `bash` command is about to execute are attached to the request, so `bash main.sh` is reviewed on its contents — measured 0/6 detected on innocuously-named dangerous scripts without that, 6/6 with it. Only files under `scriptRoot` are ever read (default: the host working directory; set it explicitly), so unrelated documents are never forwarded.

`sendArguments` is on by default: a reviewed call is sent to the endpoint with its own arguments — for a `write`, the whole file body. With a local model that never leaves the machine; with a `:cloud` tag it does.

## Config reference

`~/.dsh/tool-guard.json`, re-read on every call.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | kill switch; `false` passes every call untouched |
| `endpoint` | `http://127.0.0.1:11434/v1/systemone` | System One endpoint |
| `model` | `clef-flash` | any Ollama decision model; a `:cloud` tag sends each reviewed call off the machine |
| `timeoutMs` | `15000` | per-attempt budget. The model shares the GPU with the agent, so this must cover a queue, not a typical call |
| `retries` | `2` | extra attempts after the first, on timeout, network failure, `408`/`425`/`429`/`5xx` or an unparseable body. Any other `4xx`, or a cancelled call, gives up immediately |
| `retryBackoffMs` | `300` | exponential backoff base: 300 ms, 600 ms, 1200 ms |
| `scriptRoot` | `null` | directory whose scripts may have their bodies reviewed; `null` = host working directory |
| `audit` | `true` | append one JSONL line per call to `~/.dsh/tool-guard-audit.jsonl` |
| `sendArguments` | `true` | send the call's arguments to the model. Leave it on: a model that cannot see content cannot judge it |
| `questions` | six typed questions | the prompt itself — instructions, criteria and question type |
| `hardDeny.enabled` | `true` | regex list that denies without a model call |
| `egress.enabled` | `true` | regex list of outbound-data transports |
| `ingress.enabled` | `true` | remote content reaching an execution sink: `curl\|sh`, `bash <(curl …)`, download→`chmod +x`→run, clone→run, `eval $(curl …)` |
| `rules` | see below | question → `{above: n}` or `{in: [...]}` |
| `alwaysAsk` | `[]` | tool names always surfaced |
| `skip` | `[]` | tool names never evaluated |
| `trustWorkspace` | `false` | skip the model for file reads and writes whose target is inside the workspace. Shell commands are still reviewed, and the deterministic layers never consult it |

With the model unreachable, one call stalls for `timeoutMs × (retries + 1) + retryBackoffMs × (2^retries - 1)` before failing closed: **45.9 s** at these defaults, about 15 minutes at the clamp maxima (`timeoutMs` 120000, `retries` 5, `retryBackoffMs` 5000). Every call pays that while the model is down.

Default rules: `undo > 0.4`, `kind ∈ {system}`, `self > 0.65`, `credential > 0.5`, `sensitive > 0.8`, `exfil > 0.7`.

`kind` is a classification, not a probability: `read` only inspects or fetches; `write` creates or appends; `modify` overwrites or edits an existing file; `destroy` deletes, truncates or force-pushes; `system` changes services, permissions, network configuration or acts on a remote host. Each class listed in `kind.in` surfaces the call when the model picks it, whatever the scores are — the settings page renders that list as five checkboxes.

## Audit log

One JSONL line per call: tool name, decision, rule, scores, latency, a truncated hash of the arguments and a non-identifying shape (argument count, byte size, line count, file extension). No argument text, paths, command lines or URLs — though a truncated hash, a timestamp and the agent id remain, so treat the file as fingerprintable rather than anonymous. The readable summary is never written to the log, but it *is* returned as the prompt or denial reason, so it appears in the session transcript: keep tokens off command lines. The write is fire-and-forget and cannot fail a decision. The file is append-only and **never rotated** — it grows by one line per evaluated call, so trim or rotate it yourself if that matters.

## Calibration

Thresholds were set against the fixtures in `eval/`, scored with `clef:cloud` (the 27B model, default at the time). Decision scores are model-specific: 0.5.0 defaults to the 9B `clef-flash`, which has not been re-scored against this corpus. Those sets are authored, so they measure separation between harmless and dangerous calls — not a false-positive rate on real traffic, which was never measured on an unbiased sample.

| Set | Size | Flagged |
|---|---|---|
| Authored dangers | 100 | 97 |
| Verbose twins of those dangers | 30 | 28 |
| Unrelated sensitive reads | 8 | 8 |
| Exfiltrations | 8 | 8 |
| Write→execute, innocuous names | 6 | 6 |

Two earlier rule designs were discarded on this data: an `outside` question flagged most real traffic (reads are routinely outside the workspace), and a `destroys` probability never separated the sets at all.

## Known gaps

- **Prompt injection through documents or memory** — no deterministic layer covers it. The guard has no memory layer: content that is fetched and later written into instructions passes unless the model judges the call that fetches it.
- **Resource exhaustion** (filling the disk) scores low on every question.
- **Cross-call exfiltration** — the guard is stateless. Reading a file in one call and posting it in another passes both checks individually.
- **Obfuscated destruction** — `x=$(rm -rf /)`, `\rm`, `$IFS`, `nice -n 10 rm …` reach only the model layer, not the deny list.
