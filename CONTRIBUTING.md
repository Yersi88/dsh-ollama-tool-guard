# Contributing

## Development

No dependencies and no build step — the host half is plain ESM and the client half is a plain-JS module for the browser's module loader.

```
node --check lib/index.js
node --check client.js
node --test
```

`node --test` discovers every `*.test.mjs` under `test/` with `node:test` and runs it against a fake context and a fake `fetch`, so it needs neither a running harness nor a model. It covers the deterministic layers, fail-closed behaviour, the layer switches, the audit shape and both settings routes.

Run it from the repository root, and do not name the test file on the command line: a command that names a local script has that script's body read by the guard, and `test/guard.test.mjs` contains the dangerous patterns on purpose.

## Layout

| Path | Role |
|---|---|
| `lib/index.js` | Host half: the `tools/pre-execute` listener, the settings routes, config load/save |
| `client.js` | Client half: the Settings → Plugins → Tool Guard page |
| `cordis.patch.yml` | The single loader row |
| `test/` | Unit tests, no network |
| `eval/` | Calibration fixtures: authored dangers, verbose twins, edge cases |

## Changing thresholds

Do not tune a threshold by intuition. Add cases to `eval/`, score them, and check the separation before changing a default. `undo` and `sensitive` carry a comment recording the measurement behind them; the others came from the same corpus but their measurements are not written down, so re-measure rather than guess.

## Testing against a live model

Set overrides so a local run never touches the real config:

```
DSH_TOOL_GUARD_CONFIG=/tmp/tg.json \
DSH_TOOL_GUARD_AUDIT=/tmp/tg-audit.jsonl \
node --test
```

## Code changes need a restart

The host caches the module at boot. Editing `lib/index.js` takes effect after the harness restarts; config edits apply immediately, because the config file is re-read on every call.

## Editing the guard while the guard is running

The `self` question's criteria include "edits ... the tool guard", so a tool call that edits `lib/index.js` or `~/.dsh/tool-guard.json` scores high on `self` and is surfaced for approval — and refused outright in a session where approval prompts are unavailable. Expect to apply host-half changes by hand, or to do them with the plugin unloaded.

## Releasing

The repository publishes from CI: `.github/workflows/publish.yml` runs on a
**published GitHub Release**, tests first, and refuses to publish unless the tag
matches `package.json`.

1. Bump `version` in `package.json` and promote `CHANGELOG.md`'s `Unreleased`
   section to that version. Commit.
2. Tag and push: `git tag -a vX.Y.Z -m "…" && git push origin vX.Y.Z`.
3. Draft a Release on that tag and publish it. The workflow runs.

**The first publish has to happen before trusted publishing exists.** npm
configures a trusted publisher on the *package* page, and the package only
appears after it has been published once. So: publish once with the token
below, then switch.

**Authentication, two ways:**

- **Token (works while the repository is private).** Create an npm *Automation*
  token, add it as the repository secret `NPM_TOKEN`. That is what the workflow
  reads today.
- **Trusted publishing (no secret to rotate).** On npmjs.com, add this
  repository and the workflow filename as a trusted publisher for the package.
  Then delete the `env:` block from the publish step and add `--provenance`.
  **Provenance requires a public repository**, so this route starts the day the
  repository is flipped public.

The workflow can also be started by hand — Actions → **Publish** → *Run
workflow* — which skips the tag/version check and is the way to bootstrap the
first release.

Dry run before the first real publish:

```
npm publish --dry-run --access public
```

It prints the tarball contents — check that `SECURITY.md`, `CHANGELOG.md`,
`CONTRIBUTING.md`, `test/` and `eval/` are in it.
