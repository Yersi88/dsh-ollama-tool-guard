# Contributing

## Development

No dependencies and no build step — the host half is plain ESM and the client half is a plain-JS module for the browser's module loader.

```
node --check lib/index.js
node --check client.js
npm test
```

`npm test` runs `test/*.test.mjs` with `node:test` against a fake context and a fake `fetch`, so it needs neither a running harness nor a model. It covers the deterministic layers, fail-closed behaviour, the layer switches and both settings routes.

## Layout

| Path | Role |
|---|---|
| `lib/index.js` | Host half: the `tools/pre-execute` listener, the settings routes, config load/save |
| `client.js` | Client half: the Settings → Plugins → Tool Guard page |
| `cordis.patch.yml` | The single loader row |
| `test/` | Unit tests, no network |
| `eval/` | Calibration fixtures: authored dangers, verbose twins, edge cases |

## Changing thresholds

Do not tune a threshold by intuition. Add cases to `eval/`, score them, and check the separation before changing a default — the defaults in `lib/index.js` carry a comment recording the measurement behind them.

## Testing against a live model

Set overrides so a local run never touches the real config:

```
DSH_TOOL_GUARD_CONFIG=/tmp/tg.json \
DSH_TOOL_GUARD_AUDIT=/tmp/tg-audit.jsonl \
node --test "test/*.test.mjs"
```

## Code changes need a restart

The host caches the module at boot. Editing `lib/index.js` takes effect after the harness restarts; config edits apply immediately, because the config file is re-read on every call.
