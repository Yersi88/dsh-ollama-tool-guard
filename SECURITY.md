# Security

## What this plugin is

A **review** layer, not a sandbox. It raises the cost of a mistake; it does not establish a boundary.

If the decision model is unavailable the guard fails closed — every tool call is denied until `enabled` is set to `false` in `~/.dsh/tool-guard.json` or the plugin is removed.

## What it actually guarantees

**Deterministic** (cannot be talked into firing, cannot misfire on judgement):

- `hardDeny` patterns deny outright, without a model call.
- `egress` and `ingress` patterns always raise a prompt.

**Probabilistic** (a 9B–27B classifier's opinion):

- The six question scores. A wrong score costs at most an extra prompt, never a silent allow or block, because a model verdict can only turn a pass into a prompt.

## What it does not protect against

- **Anything the sandbox permits.** Reads outside the workspace, outbound network traffic and in-workspace destruction are all permitted by default; the guard only asks.
- **Split operations.** The guard is stateless. Reconnaissance in one call and exfiltration in another each look harmless alone.
- **Content it cannot see.** Only scripts inside the workspace referenced by a `bash` command have their bodies attached. Everything else is judged on its command string.
- **A compromised config.** `~/.dsh/tool-guard.json` is outside the workspace so the agent's sandbox cannot write it, but anything with the agent's own OS user privileges can.

## Reporting

This is currently a private, single-machine deployment. Treat the code as unreviewed until it has had an independent audit.
