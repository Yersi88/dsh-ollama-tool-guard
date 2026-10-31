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
import { appendFile, readFile, realpath, rename, rm, stat, writeFile } from 'node:fs/promises'
import { createHash, randomUUID } from 'node:crypto'
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
  /**
   * A local tag on purpose: the shipped default has to keep the promise the
   * README makes. `clef-flash` is the small local model — fast enough to sit in a
   * per-call path, and nothing leaves the machine. Any Ollama decision model works;
   * `clef` is the more careful local option and `clef:cloud` trades privacy for
   * size. The settings page names that trade next to the field.
   */
  model: 'clef-flash',
  /**
   * Per-attempt budget. The decision model shares the GPU with the agent it
   * guards, so a request can queue behind the agent's own work: this has to
   * cover a queue, not a typical call.
   */
  timeoutMs: 15000,
  /** Extra attempts after the first. Exhausting them still fails closed. */
  retries: 2,
  /** Exponential backoff base: 300 ms, 600 ms, 1200 ms. */
  retryBackoffMs: 300,
  /** Append one JSONL line per evaluated call. Argument text is never logged. */
  audit: true,

  /**
   * Send the call's own arguments — including whole file bodies for `write`/`edit`
   * — to the decision model. On by default: a model that cannot see the content
   * cannot judge it, and an agent can otherwise simply execute a file whose body
   * nobody inspected. Turn it off only when egress of file content to the model
   * provider is unacceptable; verdicts then rest on the call's shape alone, and
   * the deterministic layers still read script bodies locally for the deny list.
   */
  sendArguments: true,

  /**
   * Stop reviewing file reads and writes that stay inside the workspace. Not a
   * boundary: `bash` is still reviewed even there, and the deterministic layers are
   * unaffected. Off by default, because it is the agent's own working area being
   * left unreviewed.
   */
  trustWorkspace: false,

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
   * Deterministic ingress: remote content landing in an execution sink — where
   * "something arrived from the internet" turns into "something is about to run".
   * A download or a fetch on its own is ordinary traffic and is not flagged; only
   * the hand-off to a shell, an interpreter, or a download-then-execute step is.
   */
  ingress: {
    enabled: true,
    patterns: [
      // fetched content piped straight into a shell or interpreter
      '\\b(?:curl|wget)\\b[^\\n]*\\|\\s*(?:sudo\\s+)?(?:sh|bash|zsh|dash|python3?|node|perl|ruby)\\b',
      // process substitution: bash <(curl …). The word boundary matters — without it
      // the "sh" inside any word pairs up with a later "<(" and fires on prose.
      '\\b(?:sh|bash|zsh|dash|python3?|node|perl|ruby)\\s+<\\(\\s*(?:curl|wget)\\b',
      // download, mark executable, run
      '\\b(?:curl|wget)\\b[^\\n]*&&[^\\n]*\\bchmod\\s+\\+x\\b',
      // clone, then execute something out of the clone
      '\\bgit\\s+clone\\b[^\\n]*&&[^\\n]*\\./',
      // eval of a fetched string
      '\\beval\\s+["\\\']?\\$\\(\\s*(?:curl|wget)\\b',
    ],
  },

  /**
   * Question name → rule. `{above: n}` thresholds a `noul` probability;
   * `{in: [...]}` matches a `choice`. Any match raises the prompt.
   *
   * Calibrated 2026-10-29 on 280 real tool calls (155 sessions), 100 authored
   * dangers and 30 verbose twins — every one of them scored with clef:cloud
   * (27B), which was the default at the time. Decision scores are model-specific,
   * so these thresholds are evidence about that model only: 0.5.0 ships with the
   * 9B clef-flash by default and has not been re-scored against this corpus.
   * Re-measure before assuming they transfer.
   * 0.4 sits above the highest `undo` seen in real traffic (0.377) and below the
   * weakest real danger.
   */
  rules: {
    undo: { above: 0.4 },
    kind: { in: ['system'] },
    // 0.65: 252 real calls (2026-10-29) — 20 of the 26 calls scoring 0.50-0.65 were
    // benign passes, so 0.5 added those 20 prompts (+38% of all prompts) for no gain.
    self: { above: 0.65 },
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
    await appendFile(CONFIG_PATH, body, { flag: 'wx', mode: 0o600 })
  } catch {
    // Already seeded, or not writable — either way, fall back to defaults.
  }
}

let saveChain = Promise.resolve()

/**
 * Serialise saves and swap atomically.
 *
 * A shared `${CONFIG_PATH}.tmp` was itself a corruptor: two saves held the same
 * inode, the shorter write left a tail from the longer one, and the resulting
 * unparseable config denied every tool call with no way to repair it from the UI.
 * One chain plus a unique temp name per save removes both.
 */
function saveConfig(serializedConfig) {
  const run = async () => {
    const temporary = `${CONFIG_PATH}.${process.pid}.${randomUUID()}.tmp`
    try {
      await writeFile(temporary, serializedConfig, { mode: 0o600 })
      await rename(temporary, CONFIG_PATH)
    } catch (error) {
      await rm(temporary, { force: true }).catch(() => {})
      throw error
    }
  }
  saveChain = saveChain.then(run, run)
  return saveChain
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
  return withDefaults(parsed)
}

/** Recursive merge, so a partial nested config keeps every default it does not restate. */
function deepMerge(base, patch) {
  if (patch === null || typeof patch !== 'object' || Array.isArray(patch)) return patch
  const result = { ...base }
  for (const [key, value] of Object.entries(patch)) {
    const baseValue = base?.[key]
    const bothObjects =
      value !== null && typeof value === 'object' && !Array.isArray(value) &&
      baseValue !== null && typeof baseValue === 'object' && !Array.isArray(baseValue)
    result[key] = bothObjects ? deepMerge(baseValue, value) : value
  }
  return result
}

const asArray = (value, fallback) => (Array.isArray(value) ? value : fallback)
const asBool = (value, fallback) => (typeof value === 'boolean' ? value : fallback)

/**
 * The single normalisation for the file loader, the settings routes and the seed.
 *
 * `{ ...DEFAULTS, ...parsed }` replaced whole nested objects, so a config that only
 * said `hardDeny.enabled` silently lost every pattern while still reporting the layer
 * enabled — and `skip: null` threw a TypeError out of the hook. Unknown values now
 * fall back to the default rather than disappearing.
 */
/**
 * Coerce rule members, so a hand-edited `"above": "0.1"` or a null cannot silently
 * delete a threshold. Unknown shapes are dropped; an empty result falls back.
 */
function normaliseRules(value) {
  const source = value !== null && typeof value === 'object' && !Array.isArray(value) ? value : {}
  const out = {}
  for (const [key, rule] of Object.entries(source)) {
    if (typeof rule === 'number' && Number.isFinite(rule)) {
      out[key] = { above: rule }
      continue
    }
    if (rule === null || typeof rule !== 'object' || Array.isArray(rule)) continue
    const next = {}
    const above = Number(rule.above)
    if (rule.above !== undefined && Number.isFinite(above)) next.above = above
    if (Array.isArray(rule.in)) next.in = rule.in.filter((entry) => typeof entry === 'string')
    if (Object.keys(next).length > 0) out[key] = next
  }
  return Object.keys(out).length > 0 ? out : DEFAULTS.rules
}

/** A question without a string `type` cannot be validated, so it cannot be trusted. */
function normaliseQuestions(value) {
  const source = value !== null && typeof value === 'object' && !Array.isArray(value) ? value : {}
  const out = {}
  for (const [key, question] of Object.entries(source)) {
    if (question === null || typeof question !== 'object' || Array.isArray(question)) continue
    if (typeof question.type !== 'string') continue
    out[key] = question
  }
  for (const [key, question] of Object.entries(DEFAULTS.questions)) {
    if (out[key] === undefined) out[key] = question
  }
  return out
}

function withDefaults(parsed) {
  const merged = deepMerge(DEFAULTS, parsed ?? {})
  const section = (key) => {
    const value = merged[key] !== null && typeof merged[key] === 'object' ? merged[key] : {}
    const base = {
      ...DEFAULTS[key],
      ...value,
      enabled: asBool(value.enabled, DEFAULTS[key].enabled),
      patterns: asArray(value.patterns, DEFAULTS[key].patterns),
    }
    return base
  }
  return {
    ...merged,
    enabled: asBool(merged.enabled, DEFAULTS.enabled),
    audit: asBool(merged.audit, DEFAULTS.audit),
    sendArguments: asBool(merged.sendArguments, DEFAULTS.sendArguments),
    trustWorkspace: asBool(merged.trustWorkspace, DEFAULTS.trustWorkspace),
    hardDeny: section('hardDeny'),
    egress: section('egress'),
    ingress: section('ingress'),
    rules: normaliseRules(merged.rules),
    questions: normaliseQuestions(merged.questions),
    alwaysAsk: asArray(merged.alwaysAsk, DEFAULTS.alwaysAsk),
    skip: asArray(merged.skip, DEFAULTS.skip),
    scriptRoot: typeof merged.scriptRoot === 'string' ? merged.scriptRoot : DEFAULTS.scriptRoot,
  }
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
/** Why a rule fired, in words a human can act on. */
const RULE_REASONS = {
  hardDeny: 'matches the catastrophic deny list',
  egress: 'would send data off this machine',
  ingress: 'runs content fetched from the internet',
  undo: 'hard to undo',
  self: "changes the guard's own controls",
  credential: 'touches secrets',
  sensitive: 'reads personal files',
  exfil: 'sends data off this machine',
  alwaysAsk: 'always reviewed',
}

const OPERATIONS = {
  read: 'READING', write: 'WRITING', modify: 'MODIFYING', destroy: 'DELETING', system: 'SYSTEM CHANGE',
}

/** The model's own classification as a verb — the first thing a reviewer needs. */
function headlineOf(answers) {
  const choice = answers?.kind?.choice
  if (typeof choice !== 'string') return 'REVIEW'
  return OPERATIONS[choice] ?? choice.toUpperCase()
}

/**
 * Where the call acts, read from its own arguments rather than the model.
 *
 * A path comparison is deterministic, so it is worth far more than a probability:
 * "OUTSIDE workspace" on a `write` is the difference between a build artefact and
 * a document. Shell commands are scanned for absolute paths; with none, the label
 * falls back to the working directory.
 */
function locationOf(config, exec) {
  const root = resolve(config.scriptRoot ?? process.cwd())
  const prefix = root.endsWith('/') ? root : `${root}/`
  const isInside = (value) => {
    if (typeof value !== 'string' || value === '') return undefined
    const path = resolve(process.cwd(), value)
    return path === root || path.startsWith(prefix)
  }

  const args = exec.arguments ?? {}
  if (typeof args.file_path === 'string') return isInside(args.file_path) ? 'inside workspace' : 'OUTSIDE workspace'
  // grep and glob pass their target as `path`, not `file_path`.
  if (typeof args.path === 'string') return isInside(args.path) ? 'inside workspace' : 'OUTSIDE workspace'
  if (typeof args.url === 'string') return 'network'

  const command = typeof args.command === 'string' ? args.command : ''
  if (command === '') return undefined
  // A heredoc body is text being written, not arguments being acted on: its strings
  // are not paths this call touches. Without this, a script that merely mentions a
  // route like /tool-guard/state was reported as acting outside the workspace.
  const scanned = command.replace(/<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?[\s\S]*?\n\1\b/g, ' ')
  // Quoted text is prose as well: `echo '/etc/passwd'` is not acting on that path.
  const unquoted = scanned.replace(/'[^']*'/g, ' ').replace(/"[^"]*"/g, ' ')
  const found = unquoted.match(/(?:^|[\s;&|=])(\/[A-Za-z0-9._/-]+)/g) ?? []
  const paths = found.map((match) => match.replace(/^[\s;&|=]/, ''))
  const outside = paths.filter((path) => isInside(path) !== true).length
  if (paths.length === 0) {
    // A destructive verb whose target was quoted is a path we deliberately did not
    // read: say so rather than claiming the call stays inside.
    const destructive = ['rm', 'mv', 'cp', 'dd', 'chmod', 'chown', 'truncate', 'shred', 'ln', 'tee', 'install', 'rsync']
    const verbs = unquoted
      .split(/[;&|]/)
      .map((part) => (part.trim().split(/\s+/)[0] ?? '').replace(/^.*\//, ''))
      .filter(Boolean)
    if (verbs.some((verb) => destructive.includes(verb))) return 'location unknown'
    return isInside(process.cwd()) === true ? 'inside workspace' : 'unknown location'
  }
  if (outside === 0) return 'inside workspace'
  return outside === paths.length ? 'OUTSIDE workspace' : 'partly outside workspace'
}

function summarize(exec) {
  const args = exec.arguments ?? {}
  if (typeof args.file_path === 'string') {
    const body =
      typeof args.content === 'string' ? args.content
      : typeof args.new_string === 'string' ? args.new_string
      : ''
    const lines = body === '' ? 0 : body.split('\n').length
    return lines === 0 ? args.file_path : `${args.file_path} · ${lines} ${lines === 1 ? 'line' : 'lines'}`
  }
  if (typeof args.command === 'string') {
    const lines = args.command.split('\n')
    if (/<<-?\s*['"]?[A-Za-z_]/.test(args.command)) {
      // The first line of a heredoc is a redirect, which describes nothing; the
      // interpreter and the first real statement are what a reviewer needs.
      const body = lines.slice(1).filter((line) => line.trim() !== '')
      const firstStatement = (body[0] ?? '').trim().slice(0, 60)
      const interpreter = /python/i.test(lines[0] ?? '') ? 'python script' : 'inline script'
      return `${interpreter}, ${lines.length} ${lines.length === 1 ? 'line' : 'lines'} · first: ${firstStatement}`
    }
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
    // `self` asks whether the call weakens the guard's controls. A read cannot, so a
    // model that scores a `grep` over the plugin's own directory as self-harm is
    // over-reading the words and would prompt on harmless inspection.
    if (question === 'self' && answers?.kind?.choice === 'read') continue

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
  // Only a command that executes the file exposes its body. `cat x.sh` is a read:
  // attaching it would egress the contents and deny on prose in its comments.
  const executes =
    /\b(?:bash|sh|zsh|dash|node|python3?|source)\s+[^\n;&|]*\.(?:sh|bash|zsh|py|js|mjs|cjs|ts)\b/.test(command) ||
    /(?:^|[;&|])\s*\.{0,2}\/[^\s;&|]*\.(?:sh|bash|zsh|py|js|mjs|cjs|ts)\b/.test(command)
  if (!executes) return undefined

  let root
  try {
    root = await realpath(resolve(config.scriptRoot ?? process.cwd()))
  } catch (error) {
    audit(config, exec, { decision: 'pass', rule: 'scriptRoot', error: messageOf(error) })
    return undefined
  }
  const scripts = []
  for (const reference of new Set(command.match(SCRIPT_REFERENCE) ?? [])) {
    try {
      // `realpath` resolves symlinks before the containment test, so a link planted
      // inside the root cannot make the guard read and forward a file outside it.
      const path = await realpath(resolve(process.cwd(), reference.trim()))
      const prefix = root.endsWith('/') ? root : `${root}/`
      if (path !== root && !path.startsWith(prefix)) continue
      if (!SCRIPT_EXTENSIONS.has(extname(path))) continue
      const info = await stat(path)
      if (!info.isFile() || info.size === 0 || info.size > SCRIPT_MAX_BYTES) continue
      const content = await readFile(path, 'utf8')
      if (content.length > 0 && content.length <= SCRIPT_MAX_BYTES) scripts.push({ path, content })
    } catch {
      // Not a readable local file — the command will fail on its own.
    }
  }
  return scripts.length === 0 ? undefined : scripts
}

/** HTTP statuses worth another attempt; anything else is a request defect. */
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504])

function clamp(value, low, high, fallback) {
  if (value === null || value === '' || typeof value === 'boolean') return fallback
  const number = Number(value)
  if (!Number.isFinite(number)) return fallback
  return Math.min(high, Math.max(low, number))
}

/** Cancellable delay, so a cancelled call does not sit through the backoff. */
function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(signal.reason ?? new Error('aborted'))
      return
    }
    const cleanup = () => {
      clearTimeout(timer)
      signal?.removeEventListener?.('abort', onAbort)
    }
    const onAbort = () => {
      cleanup()
      reject(signal.reason ?? new Error('aborted'))
    }
    const timer = setTimeout(() => {
      cleanup()
      resolve()
    }, ms)
    signal?.addEventListener?.('abort', onAbort, { once: true })
  })
}

function retryable(message, status) {
  const error = new Error(message)
  error.retryable = true
  if (status !== undefined) error.status = status
  return error
}

async function attemptOnce(config, body, timeoutMs, callerSignal) {
  const signals = [AbortSignal.timeout(timeoutMs)]
  if (callerSignal !== undefined && typeof AbortSignal.any === 'function') signals.push(callerSignal)
  const signal = signals.length === 1 ? signals[0] : AbortSignal.any(signals)

  let response
  try {
    response = await fetch(config.endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal,
      body,
    })
  } catch (error) {
    if (callerSignal?.aborted === true) throw error
    // A malformed endpoint URL or a wrong argument type cannot succeed on a retry.
    // Only a malformed endpoint is permanent. undici reports a dropped connection
    // as `TypeError: fetch failed`, and that must still be retried.
    if (error instanceof TypeError && /url|parse|invalid/i.test(messageOf(error))) {
      throw new Error(`request failed (${messageOf(error)})`)
    }
    throw retryable(`request failed (${messageOf(error)})`)
  }

  if (!response.ok) {
    // Never keep the server's body: a 400 can echo the request, and this string
    // reaches the audit log through the error field.
    await response.text().catch(() => '')
    const message = `HTTP ${response.status}`
    if (RETRYABLE_STATUS.has(response.status) || response.status >= 500) throw retryable(message, response.status)
    // The default model is local, so a fresh install meets this before anything
    // else works: a bare status code fails closed with no hint about the pull.
    if (response.status === 404) {
      // A `:cloud` tag is not fixed by pulling it: those models need a signed-in
      // Ollama with credit, so the generic advice would send the user the wrong way.
      const remedy = config.model.includes(':cloud')
        ? `Sign this Ollama in to ollama.com — ":cloud" models need an account with credit — or set "model" in ${CONFIG_PATH} to a local tag you have pulled.`
        : `Run "ollama pull ${config.model}" once, or set "model" in ${CONFIG_PATH} to one this endpoint serves.`
      throw new Error(`${message} — model "${config.model}" is not available at ${config.endpoint}. ${remedy}`)
    }
    throw new Error(message)
  }

  let payload
  try {
    payload = await response.json()
  } catch (error) {
    throw retryable(`unparseable response (${messageOf(error)})`)
  }
  const answers = payload?.answers
  if (answers === null || typeof answers !== 'object' || Array.isArray(answers)) {
    throw retryable('response carried no answers object')
  }
  // A model or proxy that stops answering one question must not quietly turn the
  // guard into a no-op: an unanswered question means the verdict is incomplete.
  const missing = Object.entries(config.questions).filter(([key, question]) => {
    const answer = answers[key]
    if (answer === null || typeof answer !== 'object') return true
    if (question.type === 'noul') return typeof answer.noul !== 'number'
    if (question.type === 'choice') return typeof answer.choice !== 'string'
    if (question.type === 'score') return typeof answer.score !== 'number'
    return false
  })
  if (missing.length > 0) {
    throw retryable(`incomplete answers: ${missing.map(([key]) => key).join(', ')}`)
  }
  return answers
}

/**
 * One reviewed call, with bounded retries.
 *
 * A decision model shares the GPU with the agent it is guarding, so a request
 * can queue behind the agent's own work and time out. Retrying covers that:
 * network failures, timeouts, 429/5xx and unparseable bodies are attempted
 * again with exponential backoff, while a 4xx or a caller-initiated abort stops
 * immediately. Exhausting the retries still fails closed.
 */
/**
 * A root-level recursive delete, however the flags are spelled.
 *
 * The regex list only matches the canonical `rm -rf /`, so `-rfv`, `-r -f`,
 * `--recursive --force`, `--` and quoted or `//`-style operands all walked past it.
 * This reads the flags instead of the spelling.
 */
/** Drops heredoc bodies: text being written, not a command being run. */
function stripHeredocs(command) {
  return command.replace(/<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?[\s\S]*?\n\1\b/g, ' ')
}

function isRootWipe(command) {
  // A heredoc body is text being written to a file, not a command: strip it before
  // analysis, or documenting a wipe (or testing for one) is denied as performing it.
  const withoutHeredocs = stripHeredocs(command)
  const joined = withoutHeredocs.replace(/\\\n/g, ' ').replace(/\s+/g, ' ')
  const wrappers = new Set(['sudo', 'env', 'nohup', 'nice', 'time', 'command', 'exec', 'xargs', 'sh', 'bash', 'dash', 'zsh'])
  for (const segment of joined.split(/[;&|(]/)) {
    const tokens = segment.replace(/["']/g, '').split(/\s+/).filter(Boolean)
    let index = 0
    while (index < tokens.length && wrappers.has(tokens[index])) index += 1
    // `bash -c "…"` and `env -i …` interpose flags between the wrapper and the verb.
    while (index < tokens.length && tokens[index].startsWith('-')) index += 1
    const verb = tokens[index] ?? ''
    if (verb !== 'rm' && !verb.endsWith('/rm')) continue
    const rest = tokens.slice(index + 1)
    const flags = rest.filter((token) => token.startsWith('-'))
    const operands = rest.filter((token) => !token.startsWith('-'))
    const recursive = flags.some((f) => f === '--recursive' || (/^-[a-zA-Z]*[rR]/.test(f) && !f.startsWith('--')))
    const force = flags.some((f) => f === '--force' || (/^-[a-zA-Z]*[fF]/.test(f) && !f.startsWith('--')))
    const root = operands.some((token) => /^\/+(?:\.{1,2})?(?:\/|\*)?$/.test(token))
    if (recursive && force && root) return true
  }
  return false
}

async function askDecisionModel(config, exec) {
  const includeArguments = config.sendArguments !== false
  const scripts = includeArguments ? await attachedScripts(config, exec) : undefined
  const body = JSON.stringify({
    model: config.model,
    state: includeArguments
      ? {
          tool: exec.name,
          arguments: exec.arguments,
          cwd: process.cwd(),
          ...(scripts === undefined ? {} : { targetScripts: scripts }),
        }
      : { tool: exec.name, cwd: process.cwd(), shape: shapeOf(exec) },
    questions: config.questions,
  })

  const timeoutMs = clamp(config.timeoutMs, 1000, 120000, 15000)
  // Floored: `retries: 1.5` used to produce 2.5 attempts and run three times.
  const attempts = 1 + Math.floor(clamp(config.retries, 0, 5, 2))
  const backoffBase = clamp(config.retryBackoffMs, 0, 5000, 300)

  let lastError
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await attemptOnce(config, body, timeoutMs, exec.signal)
    } catch (error) {
      lastError = error
      const cancelled = exec.signal?.aborted === true
      if (attempt >= attempts || cancelled || error?.retryable !== true) throw error
      await sleep(backoffBase * 2 ** (attempt - 1), exec.signal)
    }
  }
  throw lastError ?? new Error('decision model did not answer')
}

/**
 * Non-identifying shape of a call, for the audit log.
 *
 * The prompt gets `summarize()` because a human reads it before approving; the log
 * gets this instead. A log outlives the prompt, and it must never carry argument
 * text — a command's first line, a URL query string or a file path is enough to
 * persist a token or a private path forever.
 */
function shapeOf(exec) {
  const args = exec.arguments ?? {}
  const shape = { args: Object.keys(args ?? {}).length }
  try {
    shape.bytes = serialized(exec).length
  } catch {
    shape.bytes = null
  }
  if (typeof args.command === 'string') shape.lines = args.command.split('\n').length
  if (typeof args.file_path === 'string') shape.ext = extname(args.file_path) || null
  return shape
}

/** Fire-and-forget: auditing must never delay or fail a decision. */
function audit(config, exec, record) {
  if (config.audit !== true) return
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    agent: exec.agent?.id ?? null,
    tool: exec.name,
    shape: shapeOf(exec),
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
const ROUTE_TEST = '/tool-guard/test'
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

/** One level of merging was enough for flag bags but not for `rules`; deepMerge replaced it. */

function registerSettingsRoutes(ctx) {
  // An isolated dependency: `ctx.get` cannot resolve a service this plugin never
  // declared, and injecting it directly would stop the guard loading at all when
  // a profile mounts no web server. This activates the routes only when one exists.
  // `connection` joins the same injection: it owns the browser cookie the rest of the
  // host surface is gated on. These two routes read and rewrite the guard's own
  // config, so leaving them open gave any local HTTP client — including a tool call
  // the guard was supposed to be judging — a way to switch the guard off. A profile
  // that mounts no `connection` simply serves no settings page.
  ctx.inject(['webServer', 'connection'], (scoped) => {
    const web = scoped.webServer
    // `connection.requestRejection` is the documented seam for gating another Web
    // route: it applies Connection's Host/Origin checks and browser authentication,
    // returning 401/403 or undefined when the request may proceed. The service has
    // no `isAuthenticated`, and calling one threw into a `catch` that answered 401
    // for every request — the settings page could never load.
    const rejectionOf = (req) => {
      try {
        return scoped.connection.requestRejection({ headers: req.headers })
      } catch {
        return 401
      }
    }
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
          const rejection = rejectionOf(req)
          if (rejection !== undefined) {
            return sendJson(res, rejection, { error: rejection === 401 ? 'not authenticated' : 'forbidden' })
          }
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
          path: ROUTE_TEST,
          async handler(req, res) {
            const rejection = rejectionOf(req)
            if (rejection !== undefined) {
              return sendJson(res, rejection, { error: rejection === 401 ? 'not authenticated' : 'forbidden' })
            }
            if (req.method !== 'POST') return sendJson(res, 405, { error: 'POST only' })
            let config
            try {
              config = await loadConfig()
            } catch (error) {
              return sendJson(res, 200, { ok: false, error: messageOf(error) })
            }
            const started = Date.now()
            try {
              const probe = await fetch(config.endpoint, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                signal: AbortSignal.timeout(Math.min(Number(config.timeoutMs) || 15000, 15000)),
                body: JSON.stringify({
                  model: config.model,
                  state: { tool: 'read', arguments: { file_path: '/etc/hostname' }, cwd: process.cwd() },
                  questions: config.questions,
                }),
              })
              const text = await probe.text().catch(() => '')
              let answered = null
              try {
                const body = JSON.parse(text)
                answered = body?.answers ? Object.keys(body.answers) : null
              } catch {
                answered = null
              }
              sendJson(res, 200, {
                ok: probe.ok && answered !== null,
                status: probe.status,
                model: config.model,
                endpoint: config.endpoint,
                ms: Date.now() - started,
                answers: answered,
                detail: probe.ok ? undefined : text.slice(0, 180),
              })
            } catch (error) {
              sendJson(res, 200, { ok: false, error: messageOf(error), model: config.model, endpoint: config.endpoint })
            }
          },
        }),
      'tool-guard: settings test route',
    )

    scoped.effect(
      () =>
        web.register({
          kind: 'exact',
          path: ROUTE_CONFIG,
        async handler(req, res) {
          const rejection = rejectionOf(req)
          if (rejection !== undefined) {
            return sendJson(res, rejection, { error: rejection === 401 ? 'not authenticated' : 'forbidden' })
          }
          if (req.method !== 'POST') return sendJson(res, 405, { error: 'POST only' })
          if (req.headers[CSRF_HEADER] === undefined) return sendJson(res, 403, { error: 'missing header' })
          try {
            const patch = JSON.parse(await readBody(req))
            const next = withDefaults(deepMerge(await loadConfig(), patch))
            const serializedConfig = `${JSON.stringify(next, null, 2)}\n`
            // Write-then-rename: a concurrent call reads the config on every dispatch,
            // and a truncated read would deny every tool call until the next success.
            await saveConfig(serializedConfig)
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


/**
 * A POST to a loopback service is not egress by itself: `curl -d …` at 127.0.0.1 stays
 * on the box when what answers it is local. It becomes egress when the body names a
 * `:cloud` model — Ollama forwards that prompt to the provider — or when the transport
 * leaves by definition (nc, scp, rsync), or when any URL is not loopback.
 */
function isLocalOnlyPost(command) {
  if (/:cloud\b/.test(command)) return false
  if (/\b(?:nc|ncat|netcat|scp|rsync)\b/.test(command)) return false
  const urls = command.match(/https?:\/\/[^\s'"`]+/g) ?? []
  if (urls.length === 0) return false
  return urls.every((url) =>
    /^https?:\/\/(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])(?::\d+)?(?:[/?]|$)/.test(url),
  )
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
    // Read the bodies before the pattern layers: a `bash boom.sh` whose script is
    // catastrophic has to be denied deterministically, not left to the model.
    const scripts = await attachedScripts(config, exec)

    // 1. Deterministic, no model call: patterns with no legitimate agent use. The
    // command string is matched first, then the body of any script it runs — a wipe
    // that lives inside the script is still a wipe.
    if (command !== undefined && config.hardDeny?.enabled === true) {
      const patterns = compile(config.hardDeny.patterns)
      let hit = isRootWipe(command) ? 'root-level recursive delete' : firstMatch(patterns, command)
      let inScript
      if (hit === undefined) {
        for (const script of scripts ?? []) {
          const bodyHit = isRootWipe(script.content)
            ? 'root-level recursive delete'
            : firstMatch(patterns, script.content)
          if (bodyHit !== undefined) {
            hit = bodyHit
            inScript = script.path
            break
          }
        }
      }
      if (hit !== undefined) {
        audit(config, exec, { decision: 'deny', rule: 'hardDeny', pattern: hit, ms: Date.now() - started })
        return {
          kind: 'deny',
          reason: `tool-guard · DENY · ${locationOf(config, exec) ?? 'unknown location'} · ${RULE_REASONS.hardDeny} · ${exec.name} · ${summarize(exec)}${inScript === undefined ? '' : ` · in ${inScript}`} · matched /${hit}/`,
        }
      }
    }

    // 2. Deterministic, no model call: data leaving the machine, or fetched code about to run.
    if (command !== undefined && config.egress?.enabled === true) {
      const hit = isLocalOnlyPost(command) ? undefined : firstMatch(compile(config.egress.patterns), command)
      if (hit !== undefined) {
        audit(config, exec, { decision: 'ask', rule: 'egress', pattern: hit, ms: Date.now() - started })
        return { kind: 'ask', reason: `tool-guard · EGRESS · ${RULE_REASONS.egress} · ${exec.name} · ${summarize(exec)} · matched /${hit}/` }
      }
    }
    if (command !== undefined && config.ingress?.enabled === true) {
      // Ingress is a shell-shaped risk: remote bytes handed to an interpreter. A call
      // that merely fetches something is ordinary traffic and passes. Heredoc bodies
      // are stripped first — a commit message quoting `bash <(curl …)` is prose.
      const hit = firstMatch(compile(config.ingress.patterns), stripHeredocs(command))
      if (hit !== undefined) {
        audit(config, exec, { decision: 'ask', rule: 'ingress', pattern: hit, ms: Date.now() - started })
        return {
          kind: 'ask',
          reason: `tool-guard · INGRESS · ${RULE_REASONS.ingress} · ${exec.name} · ${summarize(exec)} · matched /${hit}/`,
        }
      }
    }

    // 3. The decision model.
    //
    // `trustWorkspace` is a convenience, not a boundary: file reads and writes inside
    // the workspace are not reviewed. Shell commands are still reviewed even in the
    // workspace, because one `bash` line can reach anywhere and delete anything.
    if (config.trustWorkspace === true && command === undefined && locationOf(config, exec) === 'inside workspace') {
      audit(config, exec, { decision: 'next', rule: 'trustWorkspace', ms: Date.now() - started })
      return next()
    }

    let answers
    try {
      answers = await askDecisionModel(config, exec)
    } catch (error) {
      // A cancelled call is not a guard fault: report the cancellation, not a
      // fail-closed denial, or the operator sees "model unreachable" for their own Esc.
      if (exec.signal?.aborted === true) {
        audit(config, exec, { decision: 'cancel', rule: null, ms: Date.now() - started })
        return { kind: 'cancel' }
      }
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
      reason: `tool-guard · ${headlineOf(answers)} · ${locationOf(config, exec) ?? 'unknown location'} · ${RULE_REASONS[String(rule).split(/[>=]/)[0]] ?? rule} · ${exec.name} · ${summarize(exec)}`,
    }
  })
}
