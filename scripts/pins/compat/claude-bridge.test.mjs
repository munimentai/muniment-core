// pi-claude-bridge drives the pinned Claude Code CLI. The bridge points the CLI
// at a fake Anthropic endpoint through ANTHROPIC_BASE_URL, so one real turn runs
// offline: Pi -> bridge -> Agent SDK -> pinned `claude` -> fake Messages API.
import assert from 'node:assert/strict'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'
import { anthropicServer } from './fake-upstreams.mjs'
import {
  assistantReply, env, jsonEvents, LOAD_FAILURE, packageExtensions, piEnv, pins, ready, run, version, workspace,
} from './harness.mjs'

const BRIDGE = 'pi-claude-bridge'
const bridged = ready && Boolean(env.claude) && pins?.packages.some(({ name }) => name === BRIDGE)

test('the Claude Code CLI reports the pinned version', { skip: !bridged }, () => {
  assert.match(version(env.claude), new RegExp(`^${pins.claude_code.version.replaceAll('.', '\\.')}\\b`))
})

test('the bridge runs one turn through the pinned Claude Code CLI', { skip: !bridged, timeout: 180000 }, async t => {
  const root = workspace(t)
  const server = await anthropicServer()
  t.after(server.close)
  writeFileSync(join(root, 'claude-bridge.json'), JSON.stringify({
    askClaude: { enabled: false },
    provider: { plan: 'max', strictMcpConfig: true, pathToClaudeCodeExecutable: env.claude },
  }))
  const childEnv = piEnv(root, {
    ANTHROPIC_BASE_URL: server.url,
    ANTHROPIC_API_KEY: 'fixture',
    CLAUDE_CONFIG_DIR: join(root, '.claude'),
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
    DISABLE_AUTOUPDATER: '1',
  })
  const result = await run(['-p', '--mode', 'json', '--no-session', '--no-extensions', '--no-skills',
    '--no-context-files', '--no-tools', ...packageExtensions(BRIDGE), '--provider', 'claude-bridge',
    '--model', 'claude-opus-5', 'What is 6 + 6?'], { cwd: root, env: childEnv, timeout: 150000 })
  assert.doesNotMatch(result.stderr, LOAD_FAILURE)
  const reply = assistantReply(jsonEvents(result.stdout))
  assert.ok(reply, `${result.stdout}\n${result.stderr}`)
  assert.equal(reply.stopReason, 'stop', `${reply.errorMessage}\n${result.stderr}`)
  assert.ok(reply.content.some(part => part.type === 'text' && part.text.includes('12')), JSON.stringify(reply.content))
  const turns = server.requests.filter(request => request.method === 'POST' && request.url.startsWith('/v1/messages') && !request.url.includes('count_tokens'))
  assert.ok(turns.length > 0, 'the fake Anthropic endpoint saw no Messages request')
  assert.ok(turns.every(request => request.headers['user-agent']?.startsWith(`claude-cli/${pins.claude_code.version}`)),
    turns.map(request => request.headers['user-agent']).join(', '))
})
