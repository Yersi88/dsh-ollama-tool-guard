window.__ModuleLoader__.load({
  id: 'dsh-ollama-tool-guard',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useCallback, useEffect, useState } = React

    const FLAGS = [
      ['enabled', 'Guard enabled'],
      ['audit', 'Write audit log'],
      ['hardDeny.enabled', 'Hard-deny patterns'],
      ['egress.enabled', 'Egress patterns'],
      ['ingress.enabled', 'Ingress patterns'],
    ]
    const THRESHOLDS = ['undo', 'self', 'credential', 'sensitive', 'exfil']
    const KINDS = [
      ['read', 'only inspects, searches or fetches'],
      ['write', 'creates a file or appends output'],
      ['modify', 'overwrites or edits an existing file'],
      ['destroy', 'deletes, truncates or force-pushes'],
      ['system', 'services, permissions, network, remote hosts'],
    ]

    const read = (target, path) =>
      path.split('.').reduce((value, key) => (value === null || value === undefined ? undefined : value[key]), target)

    const write = (target, path, next) => {
      const [head, ...rest] = path.split('.')
      if (rest.length === 0) return { ...target, [head]: next }
      return { ...target, [head]: write(target?.[head] ?? {}, rest.join('.'), next) }
    }

    const card = {
      border: '1px solid color-mix(in srgb, currentColor 18%, transparent)',
      borderRadius: 10,
      padding: '12px 14px',
      marginBottom: 12,
    }
    const label = { display: 'flex', alignItems: 'center', gap: 8, padding: '3px 0', cursor: 'pointer' }
    const rowStyle = { display: 'flex', alignItems: 'center', gap: 10, padding: '3px 0' }
    const nameStyle = { minWidth: 90, opacity: 0.75, fontSize: 13 }
    const button = {
      font: 'inherit', padding: '6px 14px', borderRadius: 7, cursor: 'pointer',
      border: '1px solid color-mix(in srgb, currentColor 25%, transparent)',
      background: 'transparent', color: 'inherit',
    }
    const mono = { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 12 }
    const numberInput = {
      ...mono, width: 110, padding: '4px 6px', borderRadius: 6,
      border: '1px solid color-mix(in srgb, currentColor 25%, transparent)',
      background: 'transparent', color: 'inherit',
    }
    const hint = { fontSize: 12, opacity: 0.6 }

    function Panel() {
      const [config, setConfig] = useState(null)
      const [audit, setAudit] = useState([])
      const [meta, setMeta] = useState({})
      const [status, setStatus] = useState('loading…')
      const [dirty, setDirty] = useState(false)
      const [probe, setProbe] = useState(null)

      const load = useCallback(async () => {
        setStatus('loading…')
        try {
          const response = await fetch('/tool-guard/state', { headers: { accept: 'application/json' } })
          if (!response.ok) throw new Error(`HTTP ${response.status}`)
          const data = await response.json()
          setConfig(data.config)
          setAudit(data.audit ?? [])
          setMeta({ path: data.path, auditPath: data.auditPath })
          setDirty(false)
          setStatus('')
        } catch (error) {
          setStatus(`cannot reach the guard: ${error.message}`)
        }
      }, [])

      useEffect(() => { load() }, [load])

      const save = useCallback(async () => {
        setStatus('saving…')
        try {
          const response = await fetch('/tool-guard/config', {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'x-tool-guard': '1' },
            body: JSON.stringify(config),
          })
          const body = await response.json()
          if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`)
          setConfig(body.config)
          setDirty(false)
          setStatus('saved — applies to the next tool call')
        } catch (error) {
          setStatus(`save failed: ${error.message}`)
        }
      }, [config])

      const change = (path, value) => {
        setConfig((current) => write(current, path, value))
        setDirty(true)
      }

      if (config === null) {
        return h('div', { style: { padding: 16, opacity: 0.8 } }, status)
      }

      const kindRule = config.rules?.kind?.in ?? []

      return h('div', { style: { padding: '4px 2px', maxWidth: 720 } },
        h('p', { style: { margin: '0 0 12px', fontSize: 13, opacity: 0.75 } },
          'Every tool call is scored before it runs. Changes take effect on the next call — no restart.'),

        h('section', { style: card },
          h('strong', { style: { display: 'block', marginBottom: 6 } }, 'Layers'),
          ...FLAGS.map(([path, text]) =>
            h('label', { key: path, style: label },
              h('input', {
                type: 'checkbox',
                checked: read(config, path) === true,
                onChange: (event) => change(path, event.target.checked),
              }),
              h('span', { style: { fontSize: 13 } }, text)))),

        h('section', { style: card },
          h('strong', { style: { display: 'block', marginBottom: 6 } }, 'Thresholds'),
          h('p', { style: { margin: '0 0 8px', fontSize: 12, opacity: 0.65 } },
            'A call is surfaced when any score passes its threshold. Lower means more prompts.'),
          ...THRESHOLDS.map((key) => {
            const value = config.rules?.[key]?.above ?? 0
            return h('div', { key, style: rowStyle },
              h('span', { style: nameStyle }, key),
              h('input', {
                type: 'range', min: 0, max: 1, step: 0.05, value,
                style: { flex: 1 },
                onChange: (event) => change(`rules.${key}.above`, Number(event.target.value)),
              }),
              h('span', { style: { ...mono, minWidth: 34, textAlign: 'right' } }, value.toFixed(2)))
          })),

        h('section', { style: card },
          h('strong', { style: { display: 'block', marginBottom: 4 } }, 'Connection'),
          h('p', { style: { margin: '0 0 8px', fontSize: 12, opacity: 0.65 } },
            'Must be a System One endpoint — Ollama serves it at /v1/systemone and it is what answers the typed questions. An OpenAI-compatible /v1/chat/completions URL cannot: the decision models (clef, clef-flash, kev) are not chat models. Any Ollama decision model works here: clef-flash is the default (small, fast, local), clef is the more careful local option, and a model with a :cloud suffix is routed through Ollama to the provider and sends each reviewed call off the machine.'),
          h('div', { style: rowStyle },
            h('span', { style: nameStyle }, 'endpoint'),
            h('input', {
              type: 'text',
              value: config.endpoint ?? '',
              placeholder: 'http://127.0.0.1:11434/v1/systemone',
              onChange: (event) => change('endpoint', event.target.value.trim()),
              style: { ...mono, flex: 1, padding: '4px 6px', borderRadius: 6, border: '1px solid color-mix(in srgb, currentColor 25%, transparent)', background: 'transparent', color: 'inherit' },
            })),
          h('div', { style: rowStyle },
            h('span', { style: nameStyle }, 'model'),
            h('input', {
              type: 'text',
              value: config.model ?? '',
              placeholder: 'clef-flash',
              onChange: (event) => change('model', event.target.value.trim()),
              style: { ...mono, width: 220, padding: '4px 6px', borderRadius: 6, border: '1px solid color-mix(in srgb, currentColor 25%, transparent)', background: 'transparent', color: 'inherit' },
            }),
            h('button', {
              style: button,
              onClick: async () => {
                setProbe({ text: 'testing the saved config…' })
                try {
                  const response = await fetch('/tool-guard/test', { method: 'POST', headers: { 'x-tool-guard': '1' } })
                  const body = await response.json()
                  setProbe({ text: body.ok
                    ? `ok — ${body.model} answered in ${body.ms} ms (${(body.answers ?? []).join(', ')})`
                    : `failed — ${body.error ?? body.detail ?? ('HTTP ' + body.status)}` })
                } catch (error) {
                  setProbe({ text: `failed — ${error.message}` })
                }
              },
            }, 'Test saved config')),
          probe === null ? null : h('p', { style: { ...mono, margin: '6px 0 0', opacity: 0.8 } }, probe.text)),

        h('section', { style: card },
          h('strong', { style: { display: 'block', marginBottom: 6 } }, 'Model call'),
          h('p', { style: { margin: '0 0 8px', fontSize: 12, opacity: 0.65 } },
            'The decision model shares the GPU with the agent, so a request can queue behind your own work. Retries and a longer timeout cover that; exhausting them still fails closed.'),
          h('label', { style: label },
            h('input', {
              type: 'checkbox',
              checked: config.sendArguments !== false,
              onChange: (event) => change('sendArguments', event.target.checked),
            }),
            h('span', { style: { fontSize: 13 } }, 'Send call arguments to the model')),
          h('p', { style: { margin: '0 0 10px', fontSize: 12, opacity: 0.65 } },
            'On by default, and it should stay on: the model cannot judge content it has not seen, and an agent can otherwise execute a file whose body nobody inspected. Off scores only the call\'s shape — weaker verdicts — while the deterministic layers still read script bodies locally.'),
          h('div', { style: rowStyle },
            h('span', { style: nameStyle }, 'timeout'),
            h('input', {
              type: 'number', min: 1000, max: 120000, step: 1000,
              value: config.timeoutMs ?? 15000,
              onChange: (event) => change('timeoutMs', Number(event.target.value)),
              style: numberInput,
            }),
            h('span', { style: hint }, 'ms per attempt')),
          h('div', { style: rowStyle },
            h('span', { style: nameStyle }, 'retries'),
            h('input', {
              type: 'number', min: 0, max: 5, step: 1,
              value: config.retries ?? 2,
              onChange: (event) => change('retries', Number(event.target.value)),
              style: numberInput,
            }),
            h('span', { style: hint }, 'extra attempts after the first')),
          h('div', { style: rowStyle },
            h('span', { style: nameStyle }, 'backoff'),
            h('input', {
              type: 'number', min: 0, max: 5000, step: 50,
              value: config.retryBackoffMs ?? 300,
              onChange: (event) => change('retryBackoffMs', Number(event.target.value)),
              style: numberInput,
            }),
            h('span', { style: hint }, 'ms, doubling each retry'))),

        h('section', { style: card },
          h('strong', { style: { display: 'block', marginBottom: 6 } }, 'Script review root'),
          h('p', { style: { margin: '0 0 8px', fontSize: 12, opacity: 0.65 } },
            'Scripts a bash command runs from under this directory have their contents reviewed before dispatch. Anything outside it is never read. Empty uses the host working directory.'),
          h('input', {
            type: 'text',
            value: config.scriptRoot ?? '',
            placeholder: '(host working directory)',
            onChange: (event) => change('scriptRoot', event.target.value.trim() === '' ? null : event.target.value.trim()),
            style: {
              ...mono, width: '100%', boxSizing: 'border-box', padding: '6px 8px', borderRadius: 6,
              border: '1px solid color-mix(in srgb, currentColor 25%, transparent)',
              background: 'transparent', color: 'inherit',
            },
          })),

        h('section', { style: card },
          h('strong', { style: { display: 'block', marginBottom: 4 } }, 'Surface when the model classifies the call as'),
          h('p', { style: { margin: '0 0 8px', fontSize: 12, opacity: 0.65 } },
            "Each ticked class makes the model's own classification enough to raise a prompt, whatever the scores are. Untick everything and this rule never fires."),
          h('div', { style: { display: 'grid', gap: 4 } },
            ...KINDS.map(([kind, hintText]) =>
              h('label', { key: kind, style: { ...label, padding: 0 } },
                h('input', {
                  type: 'checkbox',
                  checked: kindRule.includes(kind),
                  onChange: (event) => {
                    const next = event.target.checked
                      ? [...kindRule, kind]
                      : kindRule.filter((existing) => existing !== kind)
                    change('rules.kind.in', next)
                  },
                }),
                h('span', { style: { fontSize: 13 } }, `${kind} — ${hintText}`))))),

        h('div', { style: { display: 'flex', gap: 10, alignItems: 'center', marginBottom: 12 } },
          h('button', { style: { ...button, opacity: dirty ? 1 : 0.5 }, disabled: !dirty, onClick: save },
            dirty ? 'Save changes' : 'Saved'),
          h('button', { style: button, onClick: load }, 'Reload'),
          h('span', { style: { fontSize: 12, opacity: 0.7 } }, status)),

        h('section', { style: card },
          h('strong', { style: { display: 'block', marginBottom: 8 } }, `Recent decisions (${audit.length})`),
          audit.length === 0
            ? h('span', { style: { fontSize: 12, opacity: 0.7 } }, 'No calls recorded yet.')
            : h('div', { style: { maxHeight: 260, overflowY: 'auto' } },
                ...audit.slice(0, 40).map((entry, index) =>
                  h('div', {
                    key: `${entry.ts}-${index}`,
                    style: {
                      ...mono, display: 'grid',
                      gridTemplateColumns: '58px 82px 1fr',
                      gap: 8, padding: '3px 0',
                      borderTop: index === 0 ? 'none' : '1px solid color-mix(in srgb, currentColor 10%, transparent)',
                      opacity: entry.decision === 'pass' ? 0.6 : 1,
                    },
                  },
                    h('span', {}, new Date(entry.ts).toLocaleTimeString([], { hour12: false })),
                    h('span', {}, entry.decision === 'pass' ? '· pass' : entry.decision),
                    h('span', { style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } },
                      `${entry.tool} — ${entry.rule ?? 'no rule'} ${entry.scores ? `(${entry.scores})` : ''}`))))),

        h('p', { style: { ...mono, opacity: 0.5, margin: 0 } }, `${meta.path ?? ''}`))
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('settings.plugins.tab', () => ctx.slots.register({
          name: 'settings.plugins.tab',
          id: 'tool-guard',
          order: 40,
          label: 'Tool Guard',
        }, Panel))
      },
    }
  },
})
