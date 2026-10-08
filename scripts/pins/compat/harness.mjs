// Shared setup for the compatibility checks. `muniment-pins compat` sets the environment.
import { spawn, execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

export const env = {
  pi: process.env.PI_BINARY,
  packages: process.env.PI_PACKAGES,
  claude: process.env.CLAUDE_CODE_BINARY,
  root: process.env.MUNIMENT_CORE_ROOT ?? resolve(import.meta.dirname, '../../..'),
  capture: process.env.PI_RPC_CAPTURE,
}
export const pins = process.env.PINS_JSON ? JSON.parse(process.env.PINS_JSON) : null
export const ready = Boolean(env.pi && env.packages && pins)

/** The model ids the checks route through the fake gateway. */
export const MODELS = ['anthropic/claude-opus-5-5', 'openai/gpt-6-luna', 'xai/grok-4.7', 'openai/gpt-6-sol']
export const PROVIDER = 'muniment-router'
/** Load failures Pi and the packages print to stderr. */
export const LOAD_FAILURE = /Failed to load extension|extension.*error|errors loading models/i

/** A private Pi home. Pi, the packages, and Claude Code write only here. */
export function workspace(t) {
  const root = mkdtempSync(join(tmpdir(), 'muniment-pins-compat-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  return root
}

// IS_SANDBOX passes through, because Claude Code refuses
// --dangerously-skip-permissions as root without it, and CI runners run as root.
export function piEnv(root, extra = {}) {
  const sandbox = process.env.IS_SANDBOX ? { IS_SANDBOX: process.env.IS_SANDBOX } : {}
  return { PATH: process.env.PATH, HOME: root, USERPROFILE: root, TMPDIR: root, PI_CODING_AGENT_DIR: root, PI_OFFLINE: '1', ...sandbox, ...extra }
}

export function writeModels(root, baseUrl, models = MODELS) {
  writeFileSync(join(root, 'models.json'), JSON.stringify({ providers: { [PROVIDER]: {
    baseUrl: `${baseUrl}/v1`, api: 'openai-completions', apiKey: 'fixture',
    models: models.map(id => ({ id, contextWindow: 128000, maxTokens: 8192, input: ['text'] })),
  } } }))
}

export function packageDir(name) {
  return resolve(env.packages, 'node_modules', name)
}

/** The `-e` arguments for one package's declared extension entries. */
export function packageExtensions(name) {
  const path = packageDir(name)
  const manifest = JSON.parse(readFileSync(join(path, 'package.json'), 'utf8'))
  return manifest.pi.extensions.flatMap(entry => ['-e', resolve(path, entry)])
}

export function allExtensions() {
  return pins.packages.flatMap(({ name }) => packageExtensions(name))
}

/** The extensions muniment-core writes beside every session. */
export function coreExtensions() {
  return ['assistant_identity.mjs', 'routing_progress.mjs']
    .flatMap(file => ['-e', resolve(env.root, 'crates/core/src', file)])
}

/** An extension that records the tools and commands Pi registered once the session starts. */
export function probeExtension(root) {
  const path = join(root, 'probe.mjs')
  const out = join(root, 'probe.json')
  writeFileSync(path, `import { writeFileSync } from 'node:fs'
export default function (pi) {
  pi.on('session_start', () => {
    const entry = item => ({ name: item.name, path: item.sourceInfo?.path ?? null })
    writeFileSync(${JSON.stringify(out)}, JSON.stringify({
      tools: pi.getAllTools().map(entry),
      commands: (pi.getCommands?.() ?? []).map(entry),
    }))
  })
}
`)
  return { args: ['-e', path], read: () => JSON.parse(readFileSync(out, 'utf8')) }
}

export function run(args, { cwd, env: childEnv, timeout = 60000, binary = env.pi } = {}) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(binary, args, { cwd, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`${binary} timed out\n${stderr}`)) }, timeout)
    child.stdout.on('data', data => { stdout += data })
    child.stderr.on('data', data => { stderr += data })
    child.on('error', error => { clearTimeout(timer); reject(error) })
    child.on('close', code => { clearTimeout(timer); resolveRun({ code, stdout, stderr }) })
  })
}

export function jsonEvents(stdout) {
  return stdout.split('\n').filter(line => line.startsWith('{')).map(line => JSON.parse(line))
}

export function assistantReply(events) {
  return events.findLast(event => event.type === 'message_end' && event.message?.role === 'assistant')?.message
}

export function version(binary) {
  return execFileSync(binary, ['--version'], { encoding: 'utf8', timeout: 30000 }).trim()
}

/** Pi in RPC mode. `send` writes one command, `until` waits for a matching frame. */
export function rpc(args, { cwd, env: childEnv }) {
  const child = spawn(env.pi, ['--mode', 'rpc', ...args], { cwd, env: childEnv, stdio: ['pipe', 'pipe', 'pipe'] })
  const frames = []
  const waiters = []
  let buffer = ''
  let stderr = ''
  child.stderr.on('data', data => { stderr += data })
  child.stdout.on('data', data => {
    buffer += data
    let index
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index).trim()
      buffer = buffer.slice(index + 1)
      if (!line.startsWith('{')) continue
      const frame = JSON.parse(line)
      frames.push(frame)
      for (const waiter of [...waiters]) {
        if (waiter.match(frame)) { waiters.splice(waiters.indexOf(waiter), 1); waiter.resolve(frame) }
      }
    }
  })
  return {
    frames,
    stderr: () => stderr,
    send: command => child.stdin.write(`${JSON.stringify(command)}\n`),
    until(match, timeout = 60000) {
      const found = frames.find(match)
      if (found) return Promise.resolve(found)
      return new Promise((resolveFrame, reject) => {
        const waiter = { match, resolve: frame => { clearTimeout(timer); resolveFrame(frame) } }
        const timer = setTimeout(() => {
          waiters.splice(waiters.indexOf(waiter), 1)
          reject(new Error(`no matching RPC frame within ${timeout} ms\n${stderr}`))
        }, timeout)
        waiters.push(waiter)
      })
    },
    close() {
      child.stdin.end()
      child.kill('SIGKILL')
    },
  }
}
