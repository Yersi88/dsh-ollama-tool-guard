# Security

## What this plugin is

A **review** layer, not a sandbox. It raises the cost of a mistake; it does not establish a boundary.

If the decision model is unavailable the guard fails closed — every tool call is denied until `enabled` is set to `false` in `~/.dsh/tool-guard.json`, the tool is listed in `skip`, or the plugin is removed. That refusal is not instant: with the defaults a call waits `timeoutMs × (retries + 1)` plus backoff — about 46 seconds — before it is denied, and about 15 minutes at the clamp maxima. While the model is down every call pays that, including the calls you would use to diagnose it.

## What it actually guarantees

**Deterministic** (cannot be talked into firing, cannot misfire on judgement):

- `hardDeny` patterns deny outright, without a model call. They are matched against the command string of a command-bearing call **and** against the bodies of the scripts that command runs.
- `egress` patterns raise a prompt on any command-bearing call.
- `ingress` patterns and the agent-memory tool-name list raise a prompt on any call.

**Probabilistic** (a 9B–27B classifier's opinion):

- The six question scores. A wrong score can only turn a pass into a prompt, never a silent allow.

## An `ask` is only a prompt if the session can show one

`ask` is a **blocking** approval request, not a notification. The host resolves it through its approval service, and when the session has no approval channel — a delegated or headless run, or approval prompts disabled — the resolution is a cancellation and the call is aborted before dispatch. The tool result then reads `the user rejected tool "…"`, attributing to the human a decision they were never shown.

In that configuration a wrong score **does** block, silently, which is the opposite of what a review layer should promise. Run unattended sessions with `skip` covering the tools you do not want reviewed, or with `enabled: false`, and keep the guard on sessions you are watching.

## What leaves the machine

With `sendArguments` on — the default — every reviewed call goes to the `endpoint` that judges it, and that payload carries the call's own arguments: for `write`/`edit` the **whole file body**, for `bash` the command text, for any tool its arguments. Scripts under `scriptRoot` referenced by a `bash` call are read and attached as well.

The default endpoint is `clef:cloud`, so by default this content leaves the machine on its way to Cloudflare. That is deliberate: a guard that cannot see what it is judging falls back to scoring shapes, and an agent can then execute a file whose body nobody inspected. If that egress is unacceptable, point `endpoint` at a local model (`clef`, 27B; `clef-flash` or `kev:9b` with less memory) — same verdicts, nothing on the wire. `sendArguments: false` is the fallback when even a local model must not see content, at the cost of much weaker reviews; the deterministic layers keep reading script bodies locally either way.

The audit log does **not** carry it: it records the decision, rule, scores, latency and an argument *shape*, never the argument text.

## Where the guard itself is weak

- **The settings routes answer the host's browser cookie, and nothing else.** `GET /tool-guard/state` and `POST /tool-guard/config` are gated on `connection.requestRejection` — the Host/Origin checks and browser authentication the rest of the host surface uses — and a request without them gets `401`. Before that check existed they answered any local request: measured on a live deployment, the state route returned `200` with no cookie while the application root returned `401`. What remains is that anything able to present that cookie (your browser) can read the audit tail and rewrite the config in two clicks, and the `x-tool-guard` header on the write route only defends against a cross-origin form post. `~/.dsh/tool-guard.json` sits outside the workspace so the agent's file tools cannot write it; the settings page is the sanctioned way in.
- **An agent cannot maintain the guard.** The `self` question's `true` criterion includes "edits ... the tool guard", so a tool call that edits this plugin's own source or config scores high on `self` and is surfaced for approval — or refused outright where approval prompts are unavailable. Expect maintenance of `lib/index.js` to need a human, or to be done with the plugin unloaded.

## What it does not protect against

- **Anything the sandbox permits.** Reads outside the workspace, outbound network traffic and in-workspace destruction are all permitted by default; the guard only asks.
- **Split operations.** The guard is stateless. Reconnaissance in one call and exfiltration in another each look harmless alone.
- **Content it cannot see.** Only files under `scriptRoot` (default: the host working directory) named by a `bash` command have their bodies attached. Everything else is judged on its command string.
- **A compromised config.** `~/.dsh/tool-guard.json` is outside the workspace so the agent's file tools cannot write it, but anything with the agent's own OS user privileges can, and so can a client holding the browser cookie.

## Arguments sent with the request

With the default `model: clef:cloud`, every reviewed call is sent to Cloudflare: the tool name, the full parsed arguments, the working directory, and — for a `bash` command that names one — the body of the script it is about to run. The audit log stays local and holds no argument text, but the model request is not the log. Configure a local decision model (`clef`, `clef-flash`, or any System One model you run yourself) if that is not acceptable.

## Reporting

Open an issue or a private security advisory on the repository. The 0.4.0 tree has had two rounds of independent review (functionality, tests, docs, adversarial fix-verification); the findings and their fixes are in the changelog. Treat it as reviewed-but-young rather than audited.
