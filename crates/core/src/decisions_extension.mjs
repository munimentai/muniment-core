// Shares the decision models the user connected in Settings with codemode
// scripts, under the provider `decisions`. Each answers typed questions about
// JSON state through the endpoint its connection names: a System One route,
// Cloudflare Workers AI, or OpenAI's Decisions API. Keys stay in this closure,
// so the model list a script reads carries none.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const API = 'decisions'
const TIMEOUT_MS = 30000
const ZERO = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }

function connections() {
  try {
    const file = join(process.env.PI_CODING_AGENT_DIR ?? '', 'classifier-connections.json')
    const list = JSON.parse(readFileSync(file, 'utf8'))
    return Array.isArray(list) ? list : []
  } catch { return [] }
}

function endpoint(url) {
  try {
    const parsed = new URL(url)
    if (parsed.hostname === 'api.openai.com' && parsed.pathname.endsWith('/decisions')) return 'openai'
    if (parsed.hostname === 'api.cloudflare.com' && parsed.pathname.endsWith('/ai/run')) return 'cloudflare'
    return 'systemone'
  } catch { return null }
}

function decisionQuestion(name, question) {
  if (question.type === 'choice') {
    return { type: 'choice', name, instructions: question.instructions,
      choices: Object.entries(question.criteria).map(([value, description]) => ({ value, description })) }
  }
  if (question.type === 'score') {
    return { type: 'score', name, instructions: question.instructions, levels: question.criteria.map(label => ({ label })) }
  }
  const meanings = [question.criteria?.true && `True means: ${question.criteria.true}`, question.criteria?.false && `False means: ${question.criteria.false}`].filter(Boolean)
  return { type: 'predicate', name, instructions: [question.instructions, ...meanings].join('\n\n') }
}

function request(kind, model, context) {
  if (kind === 'openai') {
    const state = JSON.stringify(context.state)
    const images = context.images ?? []
    const input = images.length ? [{ role: 'user', content: [{ type: 'input_text', text: state },
      ...images.map(image => ({ type: 'input_image', image_url: `data:${image.mimeType};base64,${image.data}` }))] }] : state
    return { model, input, questions: Object.entries(context.questions).map(([name, question]) => decisionQuestion(name, question)) }
  }
  if (context.images?.length) throw new Error('This decision model does not judge images.')
  const body = { model, state: context.state, questions: context.questions }
  return kind === 'cloudflare' ? { model, input: { state: context.state, questions: context.questions } } : body
}

// Every reply shape as System One's answers by question ID.
function answers(kind, body, questions) {
  if (kind === 'openai') {
    const byName = new Map((body.answers ?? []).map(answer => [answer.name, answer]))
    return Object.fromEntries(Object.entries(questions).map(([id, question]) => {
      const answer = byName.get(id)
      if (!answer || answer.type === 'refusal') throw new Error(`No answer for ${id}`)
      if (question.type === 'choice') {
        return [id, { type: 'choice', choice: answer.choice, confidence: answer.confidence,
          probabilities: Object.fromEntries((answer.probabilities ?? []).map(entry => [entry.value, entry.probability])) }]
      }
      if (question.type === 'score') return [id, { type: 'score', score: answer.score, confidence: answer.confidence }]
      return [id, { type: 'bool', probability: answer.probability }]
    }))
  }
  let result = body
  if (kind === 'cloudflare') {
    result = body.result ?? {}
    if (!result.answers && result.state === 'Completed') result = result.result ?? {}
  }
  if (!result.answers || typeof result.answers !== 'object') throw new Error('The decision model sent no answers.')
  return Object.fromEntries(Object.entries(questions).map(([id, question]) => {
    const answer = result.answers[id]
    if (!answer) throw new Error(`No answer for ${id}`)
    return [id, { ...answer, type: question.type }]
  }))
}

function usage(body) {
  const raw = body.usage ?? body.result?.usage ?? {}
  const input = raw.input_tokens ?? raw.prompt_tokens ?? 0
  const output = raw.output_tokens ?? raw.completion_tokens ?? 0
  return { ...ZERO, input, output, totalTokens: input + output, cost: { ...ZERO, total: 0 } }
}

export default function (pi) {
  const targets = new Map()
  const models = []
  for (const connection of connections()) {
    const classifier = connection?.classifier ?? {}
    if (!['endpoint', 'typesafe'].includes(classifier.kind)) continue
    const url = classifier.base_url || (classifier.kind === 'typesafe' ? 'https://api.typesafe.ai/v1/systemone' : '')
    const kind = endpoint(url)
    const model = classifier.model || 'jev-latest'
    if (!kind) continue
    let id = model
    for (let n = 2; targets.has(id); n++) id = `${model}-${n}`
    targets.set(id, { url, key: classifier.api_key, model, kind })
    models.push({ type: 'classifier', id, name: connection.name || model, api: API, baseUrl: url,
      input: kind === 'openai' ? ['text', 'image'] : ['text'], cost: ZERO, contextWindow: 128000 })
  }
  if (!models.length) return
  pi.registerProvider('decisions', {
    // Each connection carries its own key, so the provider's is only a marker that it is ready.
    apiKey: 'connected',
    models,
    classifiers: {
      [API]: {
        classify: async (model, context, options) => {
          const output = { api: API, provider: model.provider, model: model.id, answers: {}, stopReason: 'stop', timestamp: Date.now() }
          const target = targets.get(model.id)
          try {
            if (!target) throw new Error('This decision model is not connected.')
            const signal = options?.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(TIMEOUT_MS)]) : AbortSignal.timeout(TIMEOUT_MS)
            const response = await fetch(target.url, {
              method: 'POST', signal, redirect: 'error',
              headers: { 'content-type': 'application/json', ...(target.key ? { authorization: `Bearer ${target.key}` } : {}) },
              body: JSON.stringify(request(target.kind, target.model, context)),
            })
            if (!response.ok) throw new Error(`The decision model answered ${response.status}.`)
            const body = await response.json()
            output.usage = usage(body)
            output.answers = answers(target.kind, body, context.questions)
          } catch (error) {
            output.answers = {}
            output.stopReason = options?.signal?.aborted ? 'aborted' : 'error'
            output.errorMessage = error instanceof Error ? error.message : 'The decision model failed.'
          }
          return output
        },
      },
    },
  })
}
