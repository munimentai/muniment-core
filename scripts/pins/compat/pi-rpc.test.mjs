// The pinned Pi in RPC mode emits the frames muniment-core's sidecar parser reads:
// the prompt acknowledgement, agent start, tool execution, text deltas, the
// assistant message end with usage, and agent end. `PI_RPC_CAPTURE` keeps the
// frames for the Rust parser check in `crates/core/tests/pi_rpc_frames.rs`.
import assert from 'node:assert/strict'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { openAiServer } from './fake-upstreams.mjs'
import {
  allExtensions, coreExtensions, env, MODELS, packageDir, piEnv, pins, PROVIDER, ready, rpc, workspace, writeModels,
} from './harness.mjs'

test('RPC mode runs a tool turn and lists every package command', { skip: !ready, timeout: 180000 }, async t => {
  const root = workspace(t)
  const target = join(root, 'tool-result.txt')
  const server = await openAiServer({ toolCall: { name: 'write', arguments: { path: target, content: 'once' } } })
  t.after(server.close)
  writeModels(root, server.url)
  const pi = rpc(['--no-session', '--no-extensions', '--no-skills', '--no-context-files', ...allExtensions(),
    ...coreExtensions(), '--provider', PROVIDER, '--model', MODELS[1]], { cwd: root, env: piEnv(root) })
  t.after(() => pi.close())

  const state = (pi.send({ id: 'state', type: 'get_state' }), await pi.until(frame => frame.id === 'state'))
  assert.equal(state.success, true, JSON.stringify(state))
  pi.send({ id: 'turn', type: 'prompt', message: 'Write the file, then answer 6 + 6.' })
  const accepted = await pi.until(frame => frame.id === 'turn' && frame.type === 'response')
  assert.equal(accepted.command, 'prompt')
  assert.equal(accepted.success, true, JSON.stringify(accepted))
  const end = await pi.until(frame => frame.type === 'agent_end', 120000)
  if (env.capture) writeFileSync(env.capture, pi.frames.map(frame => JSON.stringify(frame)).join('\n') + '\n')

  const types = pi.frames.map(frame => frame.type)
  for (const type of ['agent_start', 'turn_start', 'message_start', 'message_update', 'message_end', 'tool_execution_start', 'tool_execution_end', 'turn_end', 'agent_end']) {
    assert.ok(types.includes(type), `no ${type} frame in ${[...new Set(types)].join(', ')}`)
  }
  const toolStart = pi.frames.find(frame => frame.type === 'tool_execution_start')
  assert.equal(toolStart.toolName, 'write')
  assert.equal(typeof toolStart.toolCallId, 'string')
  const toolEnd = pi.frames.find(frame => frame.type === 'tool_execution_end')
  assert.equal(toolEnd.toolCallId, toolStart.toolCallId)
  assert.equal(toolEnd.isError, false, JSON.stringify(toolEnd.result))
  assert.ok(existsSync(target) && readFileSync(target, 'utf8') === 'once')
  const deltas = pi.frames.filter(frame => frame.type === 'message_update' && frame.assistantMessageEvent?.type === 'text_delta')
  assert.equal(deltas.map(frame => frame.assistantMessageEvent.delta).join(''), '12')
  const replies = pi.frames.filter(frame => frame.type === 'message_end' && frame.message?.role === 'assistant')
  const last = replies.at(-1).message
  assert.equal(last.provider, PROVIDER)
  assert.equal(last.model, MODELS[1])
  assert.equal(last.stopReason, 'stop')
  assert.equal(last.usage.cacheRead, 50)
  assert.equal(end.messages.findLast(message => message.role === 'assistant').stopReason, 'stop')

  pi.send({ id: 'commands', type: 'get_commands' })
  const commands = (await pi.until(frame => frame.id === 'commands')).data.commands
  for (const { name } of pins.packages) {
    const own = commands.filter(command => command.source === 'extension' && command.sourceInfo?.path && resolve(command.sourceInfo.path).startsWith(packageDir(name)))
    // pi-claude-bridge registers a provider and tools, not commands.
    if (name === 'pi-claude-bridge') continue
    assert.ok(own.length > 0, `RPC lists no command from ${name}`)
  }
})
