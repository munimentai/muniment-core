// Loads the decisions extension against a stand-in Pi and fetch, and checks
// each endpoint's request and reply shape. Usage: node check.mjs <extension> <agent dir>
import assert from 'node:assert/strict'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const [extension, agent] = process.argv.slice(2)
writeFileSync(join(agent, 'classifier-connections.json'), JSON.stringify([
  { id: '1', name: 'Clef · Cloudflare', catalog_id: 'clef', classifier: { kind: 'endpoint', base_url: 'https://api.cloudflare.com/client/v4/accounts/abc/ai/run', api_key: 'cf-key', model: '@cf/cloudflare/clef' } },
  { id: '2', name: 'GPT-6 Luna', catalog_id: 'luna', classifier: { kind: 'endpoint', base_url: 'https://api.openai.com/v1/decisions', api_key: 'oa-key', model: 'gpt-6-luna' } },
  { id: '3', name: 'Jev', catalog_id: 'jev', classifier: { kind: 'typesafe', api_key: 'ts-key', model: 'jev-latest' } },
]))
process.env.PI_CODING_AGENT_DIR = agent
const sent = []
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body)
  sent.push({ url, auth: init.headers.authorization, body })
  const reply = url.includes('cloudflare')
    ? { success: true, result: { state: 'Completed', result: { answers: { mood: { choice: 'sad', confidence: 0.6, probabilities: { happy: 0.4, sad: 0.6 } } } } } }
    : url.includes('openai')
      ? { answers: [{ name: 'mood', type: 'choice', choice: 'happy', confidence: 0.9, probabilities: [{ value: 'happy', probability: 0.95 }, { value: 'sad', probability: 0.05 }] }, { name: 'ok', type: 'predicate', probability: 0.8 }], usage: { input_tokens: 12, output_tokens: 0 } }
      : { answers: { mood: { type: 'choice', choice: 'happy', confidence: 0.7, probabilities: { happy: 0.7, sad: 0.3 } } } }
  return { ok: true, status: 200, json: async () => reply }
}
let provider
await (await import(pathToFileURL(extension).href)).default({ registerProvider: (name, config) => { provider = { name, ...config } } })
assert.equal(provider.name, 'decisions')
assert.deepEqual(provider.models.map(model => model.id), ['@cf/cloudflare/clef', 'gpt-6-luna', 'jev-latest'])
assert.ok(!JSON.stringify(provider.models).includes('-key'))
const classify = provider.classifiers.decisions.classify
const mood = { type: 'choice', instructions: 'Mood?', criteria: { happy: 'Happy', sad: 'Sad' } }
const model = id => ({ ...provider.models.find(entry => entry.id === id), provider: 'decisions' })

const cloudflare = await classify(model('@cf/cloudflare/clef'), { state: { m: 'x' }, questions: { mood } })
assert.equal(cloudflare.stopReason, 'stop')
assert.equal(cloudflare.answers.mood.choice, 'sad')
assert.deepEqual(sent[0].body, { model: '@cf/cloudflare/clef', input: { state: { m: 'x' }, questions: { mood } } })
assert.equal(sent[0].auth, 'Bearer cf-key')

const ok = { type: 'bool', instructions: 'Fine?', criteria: { true: 'Yes', false: 'No' } }
const openai = await classify(model('gpt-6-luna'), { state: { m: 'x' }, questions: { mood, ok } })
assert.equal(openai.stopReason, 'stop', openai.errorMessage)
assert.deepEqual(openai.answers.mood, { type: 'choice', choice: 'happy', confidence: 0.9, probabilities: { happy: 0.95, sad: 0.05 } })
assert.deepEqual(openai.answers.ok, { type: 'bool', probability: 0.8 })
assert.equal(openai.usage.input, 12)
assert.equal(sent[1].body.input, '{"m":"x"}')
assert.equal(sent[1].body.questions[1].type, 'predicate')

const typesafe = await classify(model('jev-latest'), { state: { m: 'x' }, questions: { mood } })
assert.equal(typesafe.answers.mood.choice, 'happy')
assert.equal(sent[2].url, 'https://api.typesafe.ai/v1/systemone')
const refused = await classify(model('jev-latest'), { state: {}, images: [{ type: 'image', data: 'x', mimeType: 'image/png' }], questions: { mood } })
assert.equal(refused.stopReason, 'error')
console.log('ok')
