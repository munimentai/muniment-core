// Every pinned package loads on the pinned Pi and registers what muniment-core relies on.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { openAiServer } from './fake-upstreams.mjs'
import {
  allExtensions, env, LOAD_FAILURE, MODELS, packageDir, packageExtensions, piEnv, pins, probeExtension,
  PROVIDER, ready, run, workspace, writeModels,
} from './harness.mjs'

/** The tool names the system prompt in `crates/core/src/pi_launch.rs` promises the model. */
function promisedTools() {
  const source = readFileSync(join(env.root, 'crates/core/src/pi_launch.rs'), 'utf8')
  const tools = source.split('\nTools:\n')[1].split('\n\nRules:')[0]
  return tools.split('\n').flatMap(line => line.replace(/^- /, '').split(':')[0].split(',').map(name => name.trim()))
}

async function load(t, extensions) {
  const root = workspace(t)
  const server = await openAiServer()
  t.after(server.close)
  writeModels(root, server.url)
  const probe = probeExtension(root)
  const result = await run(['-p', '--mode', 'json', '--no-session', '--no-extensions', '--no-skills',
    '--no-context-files', ...extensions, ...probe.args, '--provider', PROVIDER, '--model', MODELS[0], 'What is 6 + 6?'],
  { cwd: root, env: piEnv(root) })
  assert.doesNotMatch(result.stderr, LOAD_FAILURE)
  assert.equal(result.code, 0, result.stderr)
  return probe.read()
}

for (const { name, version } of pins?.packages ?? []) {
  test(`${name} ${version} loads and registers tools or commands`, { skip: !ready, timeout: 120000 }, async t => {
    const manifest = JSON.parse(readFileSync(join(packageDir(name), 'package.json'), 'utf8'))
    assert.equal(manifest.version, version)
    const registered = await load(t, packageExtensions(name))
    const own = [...registered.tools, ...registered.commands]
      .filter(item => item.path && resolve(item.path).startsWith(packageDir(name)))
    if (own.length > 0) return
    // A provider-only package registers models instead of tools or commands.
    const root = workspace(t)
    const listed = await run(['--no-extensions', ...packageExtensions(name), '--list-models'], { cwd: root, env: piEnv(root) })
    const providers = listed.stdout.split('\n').slice(1).map(line => line.split(/\s+/)[0]).filter(Boolean)
    assert.ok(providers.length > 0, `${name} registered nothing: ${JSON.stringify(registered)}\n${listed.stderr}`)
  })
}

test('the tools the system prompt names are registered', { skip: !ready, timeout: 120000 }, async t => {
  const registered = await load(t, allExtensions())
  const names = new Set(registered.tools.map(tool => tool.name))
  const missing = promisedTools().filter(name => !names.has(name))
  assert.deepEqual(missing, [], `registered tools: ${[...names].join(', ')}`)
})
