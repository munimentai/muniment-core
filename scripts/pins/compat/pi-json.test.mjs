// The pinned Pi in JSON mode: every package and muniment-core's extensions load,
// and streamed replies from several models end with text, the model, and cache usage.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { openAiServer } from './fake-upstreams.mjs'
import {
  allExtensions, assistantReply, coreExtensions, env, jsonEvents, LOAD_FAILURE, MODELS, piEnv, pins,
  PROVIDER, ready, run, version, workspace, writeModels,
} from './harness.mjs'

test('Pi reports the pinned version', { skip: !ready }, () => {
  assert.equal(version(env.pi), pins.pi.version)
})

test('JSON mode completes streamed replies with cache usage for each model', { skip: !ready, timeout: 300000 }, async t => {
  const root = workspace(t)
  const server = await openAiServer()
  t.after(server.close)
  writeModels(root, server.url)
  const extensions = [...allExtensions(), ...coreExtensions()]
  for (const model of MODELS) {
    const result = await run(['-p', '--mode', 'json', '--no-session', '--no-extensions', '--no-skills',
      '--no-context-files', '--no-tools', ...extensions, '--provider', PROVIDER, '--model', model, 'What is 6 + 6?'],
    { cwd: root, env: piEnv(root) })
    assert.doesNotMatch(result.stderr, LOAD_FAILURE)
    assert.equal(result.code, 0, result.stderr)
    const reply = assistantReply(jsonEvents(result.stdout))
    assert.ok(reply, result.stdout)
    assert.equal(reply.stopReason, 'stop', reply.errorMessage)
    assert.equal(reply.model, model)
    assert.deepEqual(reply.content.filter(part => part.type === 'text'), [{ type: 'text', text: '12' }])
    assert.equal(reply.usage.cacheRead, 50)
  }
  assert.deepEqual(server.requests.filter(request => request.method === 'POST').map(request => request.body.model), MODELS)
})
