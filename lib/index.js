/**
 * Decision-model tool-call guard.
 *
 * Every tool call is scored by an Ollama System One (decision) model before it
 * is dispatched, and the outcome is one of:
 *
 *   - `ask`    surfaced to the human with the verdict; the human decides.
 *   - `next()` proceeds untouched.
 *   - `deny`   only from the fixed catastrophic-pattern list, or when the guard
 *              itself cannot run (model unreachable, config unreadable).
 *
 * A model verdict never denies: a wrong model costs an extra prompt. Denials
 * come only from deterministic rules, so they cannot be talked into firing.
 *
 * Layering, cheapest first: hard-deny patterns → deterministic egress/ingress
 * patterns → the decision model. Nothing model-based runs when a deterministic
 * rule has already decided.
 *
 * The guard does not touch permission presets, so the deterministic sandbox
 * wall (workspace-write + ask) stays exactly as it is.
 *
 * @module dsh-ollama-tool-guard
 */
import { appendFile, readFile, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { homedir } from 'node:os'
import { extname, join, resolve } from 'node:path'

export const name = 'ollama-tool-guard'
export const inject = ['tools']

const HOME = homedir()
/** Outside the workspace on purpose: the agent's file sandbox cannot write here,
 * so disarming the guard needs a real escalation, not a model's opinion. */
const CONFIG_PATH = process.env.DSH_TOOL_GUARD_CONFIG ?? join(HOME, '.dsh', 'tool-guard.json')
const AUDIT_PATH = process.env.DSH_TOOL_GUARD_AUDIT ?? join(HOME, '.dsh', 'tool-guard-audit.jsonl')

/** Only scripts inside the configured root are attached, so the guard never ships unrelated files to the cloud model. */
const SCRIPT_MAX_BYTES = 65536
const SCRIPT_EXTENSIONS = new Set(['.sh', '.bash', '.zsh', '.py', '.js', '.mjs', '.cjs', '.ts'])
const SCRIPT_REFERENCE =
  /(?:^|[\s;&|()'"=])((?:~|\.{1,2})?\/?[A-Za-z0-9_./-]*\.(?:sh|bash|zsh|py|js|mjs|cjs|ts))(?=$|[\s;&|()'"])/g

const DEFAULTS = {
  enabled: true,
  endpoint: 'http://127.0.0.1:11434/v1/systemone',
  model: 'clef:cloud',
  timeoutMs: 8000,
  /** Append one JSONL line per evaluated call. Argument text is never logged. */
  audit: true,

  /**
   * Root under which `bash`-referenced scripts are read so their bodies can be
   * reviewed. `null` means the process working directory. Anything outside this
   * root is ignored, so no call can make the guard upload an unrelated document.
   */
  scriptRoot: null,

  /**
   * Fixed patterns that deny outright and never reach the model. These have no
   * legitimate use inside an agent session, so asking would be theatre.
   */
  hardDeny: {
    enabled: true,
    patterns: [
      '\\brm\\s+-[rRfF]{1,3}\\s+(?:--no-preserve-root\\s+)?/(?=[\\s*;|&]|$)',
      '\\bdd\\b[^\\n]*\\bof=/dev/(?:sd|nvme|hd|vd|mmcblk)',
      '\\bmkfs(?:\\.\\w+)?\\b',
      ':\\(\\)\\s*\\{\\s*:\\s*\\|\\s*:\\s*&\\s*\\}\\s*;\\s*:',
      '/proc/sysrq-trigger',
      '\\bchmod\\s+-R\\s+0{3}\\s+/(?=[\\s*;|&]|$)',
      '>\\s*/dev/(?:sd|nvme|hd)\\w*',
    ],
  },

  /**
   * Deterministic egress: the transport shapes that move local data out. Asking
   * on the pattern rather than trusting a probability for the worst outcome.
   */
  egress: {
    enabled: true,
    patterns: [
      '\\bcurl\\b[^\\n|;]*\\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)\\b',
      '\\|\\s*(?:nc|ncat|netcat)\\b',
      '\\bscp\\b[^\\n]*\\s[\\w.-]+@[\\w.-]+:',
      '\\brsync\\b[^\\n]*\\s[\\w.-]+@[\\w.-]+:',
      '\\bwget\\b[^\\n]*--post-(?:data|file)',
    ],
  },

  /**
   * Deterministic ingress: content entering the agent's own instructions or
   * memory. Measured zero detection through the model, so it is patternised.
   */
  ingress: {
    enabled: true,
    tools: [
      'mcp__openviking__add_resource',
      'mcp__openviking__add_skill',
      'mcp__openviking__remember',
      'mcp__openviking__write',
      'mcp__openviking__edit',
    ],
    patterns: ['viking://agent/', '/skills/', '/memories/'],
  },

  /**
   * Question name → rule. `{above: n}` thresholds a `noul` probability;
   * `{in: [...]}` matches a `choice`. Any match raises the prompt.
   *
   * Calibrated 2026-10-29 on 280 real tool calls (155 sessions), 100 authored
   * dangers and 30 verbose twins. 0.4 sits above the highest `undo` seen in
   * real traffic (0.377) and below the weakest real danger.
   */
  rules: {
    undo: { above: 0.4 },
    kind: { in: ['system'] },
    self: { above: 0.5 },
    credential: { above: 0.5 },
    // 0.8: authored private-file reads scored 0.84–0.95; real own-memory reads 0.51–0.72.
    sensitive: { above: 0.8 },
    exfil: { above: 0.7 },
  },
  alwaysAsk: [],
  skip: [],
  questions: {
    undo: {
      type: 'noul',
      instructions:
        'If this call went wrong, would recovery require restoring something that cannot be recreated by re-running it?',
      criteria: {
        true: 'Files or configuration would be lost, overwritten beyond an ordinary edit, or changed on another machine.',
        false: 'The call could simply be re-run, re-edited, or its output regenerated.',
      },
    },
    kind: {
      type: 'choice',
      instructions: 'What kind of effect would executing this tool call have?',
      criteria: {
        read: 'It only inspects, searches, or fetches. No local state changes at all.',
        write: 'It creates new files or appends output. Nothing existing is harmed.',
        modify: 'It overwrites or edits an existing file, or changes content in place.',
        destroy: 'It deletes files or directories, discards data, truncates, or force-pushes over history.',
        system:
          'It changes system services, permissions, packages, network configuration, or acts on a remote host.',
      },
    },
    self: {
      type: 'noul',
      instructions:
        "Would this call weaken or bypass the agent's own safety controls — the tool guard, permission settings, sandbox, or approval policy?",
      criteria: {
        true: 'It disables, edits, or removes the tool guard or its configuration, or makes the sandbox or approval policy more permissive.',
        false: "It leaves the agent's permissions, guard and approval configuration exactly as they are.",
      },
    },
    credential: {
      type: 'noul',
      instructions:
        'Would this call write, copy, or transmit secret material such as SSH keys, authorized_keys, tokens, or password files?',
      criteria: {
        true: 'It writes to, copies, or sends a private key, authorized_keys, a token store, or a password file.',
        false: 'It touches no secret material of any kind.',
      },
    },
    sensitive: {
      type: 'noul',
      instructions:
        'Would this call read, list, or copy personal files that are unrelated to the task it is performing?',
      criteria: {
        true: 'It opens or enumerates personal documents, photos, financial records, medical files, or other private data the current task does not need.',
        false: 'It only touches project files, code, task configuration, or public data.',
      },
    },
    exfil: {
      type: 'noul',
      instructions:
        'Would this call send data from this machine to somewhere outside it, such as a remote server, URL, or another host?',
      criteria: {
        true: 'It uploads, posts, streams, or copies local data to a remote endpoint or another machine.',
        false: 'It makes no outbound transfer of local data; downloads and public API reads do not count.',
      },
    },
  },
}

function messageOf(error) {
  return error instanceof Error ? error.message : String(error)
}

function compile(sources) {
  const out = []
  for (const source of sources ?? []) {
    try {
      out.push({ source, re: new RegExp(source, 'i') })
    } catch {
      // A bad user-edited pattern is skipped rather than breaking every call.
    }
  }
  return out
}

/** Seed the config on first run so the editable surface exists outside the workspace. */
async function seedConfig() {
  const body = `${JSON.stringify(DEFAULTS, null, 2)}\n`
  try {
    await appendFile(CONFIG_PATH, body, { flag: 'wx' })
  } catch {
    // Already seeded, or not writable — either way, fall back to defaults.
  }
}

async function loadConfig() {
  let raw
  try {
    raw = await readFile(CONFIG_PATH, 'utf8')
  } catch (error) {
    if (error?.code === 'ENOENT') {
      await seedConfig()
      return DEFAULTS
    }
    throw new Error(`cannot read ${CONFIG_PATH}: ${messageOf(error)}`)
  }
  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch (error) {
    throw new Error(`${CONFIG_PATH} is not valid JSON: ${messageOf(error)}`)
  }
  return { ...DEFAULTS, ...parsed }
}

/** Compact one-line rendering of the answers that actually drive a rule. */
function describe(answers, keys) {
  const parts = []
  for (const key of keys) {
    const answer = answers?.[key]
    if (answer === null || typeof answer !== 'object') continue
    if (typeof answer.noul === 'number') parts.push(`${key}=${answer.noul.toFixed(2)}`)
    else if (typeof answer.choice === 'string') parts.push(`${key}=${answer.choice}`)
    else if (typeof answer.score === 'number') parts.push(`${key}=${answer.score.toFixed(1)}`)
  }
  return parts.length === 0 ? 'no verdict' : parts.join(' ')
}

/**
 * A human-readable shape for the prompt. A decision model cannot summarise —
 * it emits probabilities — so the plugin does it mechanically: which file, how
 * many lines, the first line of a script. Raw arguments are unreadable for
 * multi-line heredocs, which is exactly what real traffic looks like.
 */
function summarize(exec) {
  const args = exec.arguments ?? {}
  if (typeof args.file_path === 'string') {
    const body =
      typeof args.content === 'string' ? args.content
      : typeof args.new_string === 'string' ? args.new_string
      : ''
    const lines = body === '' ? 0 : body.split('\n').length
    return lines === 0 ? args.file_path : `${args.file_path} · ${lines} lines`
  }
  if (typeof args.command === 'string') {
    const lines = args.command.split('\n')
    const head = (lines[0] ?? '').trim().slice(0, 70)
    return lines.length > 1 ? `${lines.length} lines · ${head}` : head
  }
  if (typeof args.url === 'string') return args.url.slice(0, 90)
  const raw = JSON.stringify(args)
  return raw.length > 90 ? `${raw.slice(0, 90)}…` : raw
}

/** Serialised arguments, used by the deterministic pattern layers and the audit hash. */
function serialized(exec) {
  try {
    return JSON.stringify(exec.arguments ?? {})
  } catch {
    return String(exec.arguments)
  }
}

function firstMatch(patterns, text) {
  for (const { source, re } of patterns) if (re.test(text)) return source
  return undefined
}

/**
 * The first model rule this call violates, or `undefined` when it passes them
 * all. `alwaysAsk` wins regardless of score.
 */
function violationOf(config, answers, callName) {
  if (config.alwaysAsk.includes(callName)) return 'alwaysAsk'

  for (const [question, rule] of Object.entries(config.rules ?? {})) {
    const answer = answers?.[question]
    if (answer === null || typeof answer !== 'object') continue

    if (typeof rule === 'number') {
      if (typeof answer.noul === 'number' && answer.noul > rule) return `${question}>${rule}`
      continue
    }
    if (typeof rule?.above === 'number' && typeof answer.noul === 'number' && answer.noul > rule.above) {
      return `${question}>${rule.above}`
    }
    if (Array.isArray(rule?.in) && typeof answer.choice === 'string' && rule.in.includes(answer.choice)) {
      return `${question}=${answer.choice}`
    }
  }
  return undefined
}

/**
 * Read scripts a `bash` command is about to execute and attach their bodies.
 *
 * Without this the guard only sees `bash main.sh`, which
 * carries no information — measured 0/6 on innocuously-named dangerous scripts,
 * versus 6/6 once the body is attached.
 */
async function attachedScripts(config, exec) {
  const command = exec.arguments?.command
  if (typeof command !== 'string') return undefined

  const root = resolve(config.scriptRoot ?? process.cwd())
  const scripts = []
  for (const reference of new Set(command.match(SCRIPT_REFERENCE) ?? [])) {
    const path = resolve(process.cwd(), reference.trim())
    if (path !== root && !path.startsWith(`${root}/`)) continue
    if (!SCRIPT_EXTENSIONS.has(extname(path))) continue
    try {
      const content = await readFile(path, 'utf8')
      if (content.length > 0 && content.length <= SCRIPT_MAX_BYTES) scripts.push({ path, content })
    } catch {
      // Not a readable local file — the command will fail on its own.
    }
  }
  return scripts.length === 0 ? undefined : scripts
}

async function askDecisionModel(config, exec) {
  const scripts = await attachedScripts(config, exec)
  const signals = [AbortSignal.timeout(config.timeoutMs)]
  if (exec.signal !== undefined) {
    signals.push(exec.signal)
    if (typeof AbortSignal.any !== 'function') signals.pop()
  }
  const signal = signals.length === 1 ? signals[0] : AbortSignal.any(signals)

  const response = await fetch(config.endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    signal,
    body: JSON.stringify({
      model: config.model,
      state: {
        tool: exec.name,
        arguments: exec.arguments,
        cwd: process.cwd(),
        ...(scripts === undefined ? {} : { targetScripts: scripts }),
      },
      questions: config.questions,
    }),
  })

  if (!response.ok) {
    const body = await response.text().catch(() => '')
    throw new Error(`HTTP ${response.status}${body ? `: ${body.slice(0, 300)}` : ''}`)
  }

  const payload = await response.json()
  if (payload === null || typeof payload !== 'object' || typeof payload.answers !== 'object') {
    throw new Error('response carried no answers object')
  }
  return payload.answers
}

/** Fire-and-forget: auditing must never delay or fail a decision. */
function audit(config, exec, record) {
  if (config.audit !== true) return
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    agent: exec.agent?.id ?? null,
    tool: exec.name,
    summary: summarize(exec),
    argsHash: createHash('sha256').update(serialized(exec)).digest('hex').slice(0, 16),
    ...record,
  })
  appendFile(AUDIT_PATH, `${line}\n`).catch(() => {})
}

/* ---------------------------------------------------------------------------
 * Settings surface
 *
 * The Web panel talks to these routes instead of asking the agent to edit the
 * config: the host process performs the write, so tuning a threshold costs no
 * sandbox escalation. A custom header is required because a cross-origin form
 * post cannot set one without a preflight, which keeps other pages out.
 * ------------------------------------------------------------------------- */

const ROUTE_STATE = '/tool-guard/state'
const ROUTE_CONFIG = '/tool-guard/config'
const CSRF_HEADER = 'x-tool-guard'

function sendJson(res, status, body) {
  res.statusCode = status
  res.setHeader('content-type', 'application/json')
  res.setHeader('cache-control', 'no-store')
  res.end(JSON.stringify(body))
}

function readBody(req, limit = 65536) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > limit) {
        reject(new Error('request body too large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

async function readAuditTail(limit) {
  try {
    const raw = await readFile(AUDIT_PATH, 'utf8')
    return raw
      .split('\n')
      .filter((line) => line.trim() !== '')
      .slice(-limit)
      .map((line) => {
        try {
          return JSON.parse(line)
        } catch {
          return null
        }
      })
      .filter(Boolean)
      .reverse()
  } catch {
    return []
  }
}

/** One level of merging is enough here: the nested config objects are flag bags. */
function mergeConfig(base, patch) {
  const next = { ...base }
  for (const [key, value] of Object.entries(patch ?? {})) {
    const isObject = value !== null && typeof value === 'object' && !Array.isArray(value)
    const baseIsObject = base[key] !== null && typeof base[key] === 'object' && !Array.isArray(base[key])
    next[key] = isObject && baseIsObject ? { ...base[key], ...value } : value
  }
  return next
}

function registerSettingsRoutes(ctx) {
  // An isolated dependency: `ctx.get` cannot resolve a service this plugin never
  // declared, and injecting it directly would stop the guard loading at all when
  // a profile mounts no web server. This activates the routes only when one exists.
  ctx.inject(['webServer'], (scoped) => {
    const web = scoped.webServer
    void appendFile(
      AUDIT_PATH,
      `${JSON.stringify({ ts: new Date().toISOString(), event: 'routes-registered', paths: [ROUTE_STATE, ROUTE_CONFIG] })}\n`,
    ).catch(() => {})

    scoped.effect(
      () =>
        web.register({
          kind: 'exact',
          path: ROUTE_STATE,
          async handler(req, res) {
          try {
            sendJson(res, 200, {
              config: await loadConfig(),
              audit: await readAuditTail(60),
              path: CONFIG_PATH,
              auditPath: AUDIT_PATH,
            })
          } catch (error) {
            sendJson(res, 500, { error: messageOf(error) })
          }
        },
      }),
    'tool-guard: settings state route',
  )

    scoped.effect(
      () =>
        web.register({
          kind: 'exact',
          path: ROUTE_CONFIG,
        async handler(req, res) {
          if (req.method !== 'POST') return sendJson(res, 405, { error: 'POST only' })
          if (req.headers[CSRF_HEADER] === undefined) return sendJson(res, 403, { error: 'missing header' })
          try {
            const patch = JSON.parse(await readBody(req))
            const next = mergeConfig(await loadConfig(), patch)
            await writeFile(CONFIG_PATH, `${JSON.stringify(next, null, 2)}\n`)
            sendJson(res, 200, { config: next })
          } catch (error) {
            sendJson(res, 400, { error: messageOf(error) })
          }
        },
      }),
      'tool-guard: settings write route',
    )
  })
}

export function apply(ctx) {
  registerSettingsRoutes(ctx)

  ctx.on('tools/pre-execute', async (exec, next) => {
    let config
    try {
      config = await loadConfig()
    } catch (error) {
      return {
        kind: 'deny',
        reason: `tool-guard: ${messageOf(error)}. No tool call runs until the file is fixed or the plugin is removed.`,
      }
    }

    if (config.enabled !== true || config.skip.includes(exec.name)) return next()

    const started = Date.now()
    // Command patterns only inspect calls that actually execute something. A
    // `write` that merely *documents* a disk-wiping command is not running it —
    // matching file bodies here denied the README that described the patterns.
    const command = typeof exec.arguments?.command === 'string' ? exec.arguments.command : undefined
    const text = command ?? serialized(exec)

    // 1. Deterministic, no model call: patterns with no legitimate agent use.
    if (command !== undefined && config.hardDeny?.enabled === true) {
      const hit = firstMatch(compile(config.hardDeny.patterns), command)
      if (hit !== undefined) {
        audit(config, exec, { decision: 'deny', rule: 'hardDeny', pattern: hit, ms: Date.now() - started })
        return {
          kind: 'deny',
          reason: `tool-guard hardDeny · ${exec.name} · ${summarize(exec)} · matched /${hit}/`,
        }
      }
    }

    // 2. Deterministic, no model call: data leaving the machine, or entering the agent's own memory.
    if (command !== undefined && config.egress?.enabled === true) {
      const hit = firstMatch(compile(config.egress.patterns), command)
      if (hit !== undefined) {
        audit(config, exec, { decision: 'ask', rule: 'egress', pattern: hit, ms: Date.now() - started })
        return { kind: 'ask', reason: `tool-guard egress · ${exec.name} · ${summarize(exec)} · matched /${hit}/` }
      }
    }
    if (config.ingress?.enabled === true) {
      const hit =
        config.ingress.tools.includes(exec.name) ? 'tool' : firstMatch(compile(config.ingress.patterns), text)
      if (hit !== undefined) {
        audit(config, exec, { decision: 'ask', rule: 'ingress', pattern: hit, ms: Date.now() - started })
        return {
          kind: 'ask',
          reason: `tool-guard ingress · ${exec.name} · ${summarize(exec)} · ${hit === 'tool' ? 'agent memory write' : `matched /${hit}/`}`,
        }
      }
    }

    // 3. The decision model.
    let answers
    try {
      answers = await askDecisionModel(config, exec)
    } catch (error) {
      audit(config, exec, { decision: 'deny', rule: 'unavailable', error: messageOf(error) })
      return {
        kind: 'deny',
        reason:
          `tool-guard: decision model unreachable (${messageOf(error)}). ` +
          `Nothing runs until ${CONFIG_PATH} sets "enabled": false, or the plugin is removed.`,
      }
    }

    const scores = describe(answers, Object.keys(config.rules))
    const rule = violationOf(config, answers, exec.name)
    const ms = Date.now() - started
    if (rule === undefined) {
      audit(config, exec, { decision: 'pass', rule: null, scores, ms })
      return next()
    }

    audit(config, exec, { decision: 'ask', rule, scores, ms })
    return {
      kind: 'ask',
      reason: `tool-guard ${rule} · ${scores} · ${exec.name} · ${summarize(exec)}`,
    }
  })
}
