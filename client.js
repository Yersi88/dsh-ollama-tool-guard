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
    const KINDS = ['read', 'write', 'modify', 'destroy', 'system']

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

    function Panel() {
      const [config, setConfig] = useState(null)
      const [audit, setAudit] = useState([])
      const [meta, setMeta] = useState({})
      const [status, setStatus] = useState('loading…')
      const [dirty, setDirty] = useState(false)

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
          h('strong', { style: { display: 'block', marginBottom: 6 } }, 'Surfaced effect classes'),
          h('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 14 } },
            ...KINDS.map((kind) =>
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
                h('span', { style: { fontSize: 13 } }, kind))))),

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
                    h('span', {}, new Date(entry.ts).toLocaleTimeString()),
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
