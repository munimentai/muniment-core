// Runs with the verified harness's embedded Bun. Package code is loaded only by install/auth/test actions.
import fs from 'node:fs/promises'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { spawn } from 'node:child_process'
import { randomUUID, createHash } from 'node:crypto'
const root = process.env.MUNIMENT_EXTEND_ROOT
const agent = path.join(root, 'agent')
const directory = path.join(root, 'extensions')
const stateFile = path.join(directory, 'inventory.json')
const adapter = path.join(agent, 'npm/node_modules/pi-mcp-adapter')
const loadAdapter = name => import(pathToFileURL(path.join(adapter, name)).href)
let input = ''
for await (const chunk of process.stdin) input += chunk
const request = JSON.parse(input)
const { action, data = {} } = request
await fs.mkdir(directory, { recursive: true, mode: 0o700 })
async function read() {
  try { return JSON.parse(await fs.readFile(stateFile, 'utf8')) }
  catch (error) { if (error.code === 'ENOENT') return { items: [], threads: {} }; throw error }
}
async function write(state) {
  const temp = `${stateFile}.${randomUUID()}`
  await fs.writeFile(temp, JSON.stringify(state, null, 2), { mode: 0o600 })
  await fs.rename(temp, stateFile)
}
function run(command, args, cwd, timeout = 120000) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, shell: false, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' }, stdio: ['ignore', 'pipe', 'pipe'] })
    let output = ''
    child.stdout.on('data', chunk => { if (output.length < 1000000) output += chunk })
    child.stderr.resume()
    const timer = setTimeout(() => { child.kill(); reject(new Error('The operation timed out.')) }, timeout)
    child.on('error', error => { clearTimeout(timer); reject(error) })
    child.on('exit', code => { clearTimeout(timer); code === 0 ? resolve(output.trim()) : reject(new Error(`${command} failed. Check the source and local tools.`)) })
  })
}
function safeRelative(value) {
  if (!value || path.isAbsolute(value) || value.split(/[\\/]/).includes('..')) throw new Error('Choose a relative path inside the package.')
  return value
}
async function scan(base) {
  const skills = []
  let count = 0, bytes = 0
  const digest = createHash('sha256')
  async function walk(dir, depth) {
    if (depth > 10) throw new Error('The package has too many folder levels.')
    for (const entry of (await fs.readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      if (['.git', 'node_modules', '.muniment-preview.json'].includes(entry.name)) continue
      if (++count > 12000) throw new Error('The package has too many files.')
      const file = path.join(dir, entry.name)
      if (entry.isSymbolicLink()) throw new Error('Package links are not supported. Use regular files.')
      if (entry.isDirectory()) await walk(file, depth + 1)
      else if (entry.isFile()) {
        const stat = await fs.stat(file); bytes += stat.size
        if (bytes > 100 * 1024 * 1024) throw new Error('The package exceeds 100 MB.')
        digest.update(path.relative(base, file)); digest.update(await fs.readFile(file))
        if (entry.name === 'SKILL.md' || (entry.name.endsWith('.md') && path.relative(base, file).startsWith(`commands${path.sep}`))) {
          const text = await fs.readFile(file, 'utf8')
          const name = text.match(/^name:\s*["']?([^\n"']+)/m)?.[1]?.trim() || (entry.name === 'SKILL.md' ? path.basename(dir) : entry.name.slice(0, -3))
          const description = text.match(/^description:\s*["']?([^\n"']+)/m)?.[1]?.trim() || `Instructions for ${name}`
          skills.push({ name, description, path: path.relative(base, file) })
        }
      }
    }
  }
  await walk(base, 0)
  const json = async name => { try { return JSON.parse(await fs.readFile(path.join(base, name), 'utf8')) } catch (e) { if (e.code === 'ENOENT') return null; throw e } }
  const pkg = await json('package.json')
  const manifest = await json('.claude-plugin/plugin.json') || await json('.codex-plugin/plugin.json')
  const mcp = await json('.mcp.json')
  const extensions = pkg?.pi?.extensions || []
  for (const file of extensions) { safeRelative(file); if (!(await fs.stat(path.join(base, file))).isFile()) throw new Error('A plugin entry file is missing.') }
  const dependencies = pkg?.dependencies || {}
  const unsupported = ['hooks', 'agents', 'lspServers', 'outputStyles', 'apps'].filter(key => manifest?.[key])
  if (await json('hooks/hooks.json')) unsupported.push('hooks')
  if (unsupported.length) throw new Error(`This plugin contains unsupported components: ${[...new Set(unsupported)].join(', ')}.`)
  return { name: manifest?.name || pkg?.name || skills[0]?.name || path.basename(base), description: manifest?.description || pkg?.description || '', skills, extensions, dependencies, digest: digest.digest('hex'), servers: mcp?.mcpServers || {} }
}
async function sourceSnapshot(source) {
  const target = path.join(directory, 'packages', randomUUID())
  await fs.mkdir(path.dirname(target), { recursive: true })
  try {
    if (/^https:\/\/github.com\//.test(source)) {
      const url = new URL(source)
      const parts = url.pathname.split('/').filter(Boolean)
      if (parts.length < 2 || url.username || url.password) throw new Error('Use a GitHub repository URL.')
      const repo = `https://github.com/${parts[0]}/${parts[1].replace(/\.git$/, '')}.git`
      const ref = parts[2] === 'tree' ? parts[3] : url.hash.slice(1)
      const args = ['-c', 'core.hooksPath=/dev/null', 'clone', '--depth', '1', '--no-recurse-submodules']
      if (ref) args.push('--branch', ref)
      args.push('--', repo, target)
      await run('git', args)
      const version = await run('git', ['rev-parse', 'HEAD'], target)
      const base = parts[2] === 'tree' && parts.length > 4 ? path.join(target, safeRelative(parts.slice(4).join('/'))) : target
      return { target, base, version }
    }
    if (!path.isAbsolute(source)) throw new Error('Use a GitHub URL or an absolute local folder path.')
    await scan(source)
    await fs.cp(source, target, { recursive: true, dereference: false, filter: p => !['.git', 'node_modules'].includes(path.basename(p)) })
    return { target, base: target, version: randomUUID() }
  } catch (error) { await fs.rm(target, { recursive: true, force: true }); throw error }
}
function validateServer(definition) {
  if (!definition || typeof definition !== 'object' || Array.isArray(definition)) throw new Error('Enter a server configuration.')
  if (definition.url) {
    const url = new URL(definition.url)
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) throw new Error('Use an HTTP or HTTPS server URL without credentials.')
  } else if (typeof definition.command !== 'string' || !definition.command.trim()) throw new Error('Enter a server URL or command.')
  if (definition.args && (!Array.isArray(definition.args) || definition.args.some(a => typeof a !== 'string'))) throw new Error('Server arguments must be a list of text values.')
  // Secrets are references. Bearer tokens use the adapter's OS credential store.
  for (const value of Object.values(definition.headers || {})) if (!/^\$\{[A-Z_][A-Z0-9_]*\}$/.test(value)) throw new Error('Use an environment variable reference for headers, or the token field.')
  for (const value of Object.values(definition.env || {})) if (!/^\$\{[A-Z_][A-Z0-9_]*\}$/.test(value)) throw new Error('Use environment variable references for server secrets.')
  if (definition.oauth?.clientSecret) throw new Error('Use an environment variable for OAuth client credentials.')
  return { ...definition, lifecycle: 'lazy' }
}
const state = await read()
let result
try {
  if (action === 'read') result = state
  else if (action === 'server') {
    const id = data.id || randomUUID()
    const definition = validateServer(data.definition)
    const entry = { id, kind: 'mcp', name: data.name.trim(), description: data.description || '', source: data.source || '', definition, enabled: data.enabled !== false }
    if (!entry.name) throw new Error('Enter a name.')
    if (data.token) {
      if (!definition.url) throw new Error('Tokens require a remote server URL.')
      const { saveBearerTokenForUrl } = await loadAdapter('mcp-bearer-store.ts')
      saveBearerTokenForUrl(`extend-${id}`, data.token, definition.url)
      entry.definition.auth = 'bearer'; entry.definition.bearerTokenStore = true
    }
    state.items = [...state.items.filter(i => i.id !== id), entry]; await write(state); result = state
  } else if (action === 'preview') {
    const snapshot = await sourceSnapshot(data.source)
    try {
      const found = await scan(snapshot.base)
      for (const definition of Object.values(found.servers)) validateServer(definition)
      if (!/^https:\/\/github.com\//.test(data.source)) snapshot.version = found.digest
      const preview = { ...found, ...snapshot, source: data.sourceLabel || data.source, kind: data.kind, id: path.basename(snapshot.target) }
      await fs.writeFile(path.join(snapshot.target, '.muniment-preview.json'), JSON.stringify(preview), { mode: 0o600 })
      result = preview
    } catch (error) { await fs.rm(snapshot.target, { recursive: true, force: true }); throw error }
  } else if (action === 'install') {
    if (!/^[a-z0-9-]+$/.test(data.previewId)) throw new Error('The install preview is invalid.')
    const target = path.join(directory, 'packages', data.previewId)
    const preview = JSON.parse(await fs.readFile(path.join(target, '.muniment-preview.json'), 'utf8'))
    const scanned = await scan(preview.base)
    if (scanned.digest !== preview.digest) throw new Error('The package changed after review. Review it again.')
    for (const definition of Object.values(scanned.servers)) validateServer(definition)
    const chosen = scanned.skills.filter(s => data.skills?.includes(s.path))
    if (preview.kind === 'skill' && !chosen.length) throw new Error('Select at least one skill.')
    if (preview.kind === 'plugin' && !chosen.length && !scanned.extensions.length && !Object.keys(scanned.servers).length) throw new Error('This package has no supported skills, tools, or extensions.')
    if (preview.kind === 'plugin' && Object.keys(scanned.dependencies).length) await run(process.execPath, ['install', '--ignore-scripts', '--no-progress', ...(await fs.access(path.join(preview.base, 'bun.lock')).then(() => true, () => false) ? ['--frozen-lockfile'] : [])], preview.base)
    const old = state.items.find(i => i.id === data.replaceId)
    const entry = { ...preview, ...scanned, skills: chosen, id: old?.id || preview.id, enabled: true, previous: old ? { ...old, previous: undefined } : undefined }
    state.items = [...state.items.filter(i => i.id !== entry.id), entry]; await write(state); result = state
  } else if (action === 'toggle') {
    const item = state.items.find(i => i.id === data.id); if (!item) throw new Error('Extension not found.')
    item.enabled = !!data.enabled; await write(state); result = state
  } else if (action === 'rollback') {
    const item = state.items.find(i => i.id === data.id); if (!item?.previous) throw new Error('No previous version is available.')
    state.items = state.items.map(i => i.id === item.id ? item.previous : i); await write(state); result = state
  } else if (action === 'remove') {
    const item = state.items.find(i => i.id === data.id)
    if (item?.kind === 'mcp' && item.definition.url) {
      const { removeAuth } = await loadAdapter('mcp-auth-flow.ts'); await removeAuth(`extend-${item.id}`)
      const { removeBearerToken } = await loadAdapter('mcp-bearer-store.ts'); removeBearerToken(`extend-${item.id}`)
    }
    state.items = state.items.filter(i => i.id !== data.id); await write(state); result = state
  } else if (action === 'turn') {
    if (!data.threadId || data.threadId.length > 100) throw new Error('Choose a thread.')
    state.turns ||= {}
    state.turns[data.threadId] = { disabled: data.disabled || [], selected: data.selected || [], automatic: !!data.automatic, automaticSelected: [] }
    await write(state); result = state
  } else if (action === 'auth' || action === 'test') {
    const item = state.items.find(i => i.id === data.id || data.id.startsWith(`${i.id}:`))
    const member = item && data.id !== item.id ? data.id.slice(item.id.length + 1) : null
    const definition = member ? item?.servers?.[member] : item?.definition
    if (!definition) throw new Error('Server not found.')
    const name = member ? `extend-${item.id}-${member}` : `extend-${item.id}`
    if (action === 'auth') {
      const { authenticate } = await loadAdapter('mcp-auth-flow.ts')
      await authenticate(name, definition.url, { ...definition, auth: 'oauth' }, { signal: AbortSignal.timeout(120000) })
      definition.auth = 'oauth'; await write(state)
    }
    const { McpServerManager } = await loadAdapter('server-manager.ts')
    const manager = new McpServerManager(directory)
    try {
      const connection = await manager.connect(name, definition, AbortSignal.timeout(20000))
      result = { status: connection.status, tools: connection.tools.map(t => ({ name: t.name, description: t.description })), resources: connection.resources.length }
      item.lastCheck = { status: result.status, tools: result.tools.length }; await write(state)
    } finally { await manager.close(name) }
  } else throw new Error('Unknown extension action.')
  process.stdout.write(`\nMUNIMENT_EXTEND_RESULT=${JSON.stringify({ ok: true, result })}\n`)
} catch (error) {
  // Provider errors can contain tokens and headers. Keep them off the UI/log wire.
  const message = ['auth', 'test'].includes(action) ? 'Connection failed. Check the URL, credentials, and server requirements.' : String(error.message).slice(0, 500)
  process.stdout.write(`\nMUNIMENT_EXTEND_RESULT=${JSON.stringify({ ok: false, error: message })}\n`)
  process.exitCode = 1
}
