import { AsyncLocalStorage } from 'node:async_hooks'
import { streamSimpleOpenAICompletions } from '@mariozechner/pi-ai'

// Scope the fetch hook to this provider. Other providers keep their own transport.
const requests = new AsyncLocalStorage()
const fetchGateway = globalThis.fetch.bind(globalThis)
const stopped = (message) => new Response(JSON.stringify({ error: { message } }), {
  status: 400, headers: { 'Content-Type': 'application/json', 'x-should-retry': 'false' }
})
globalThis.fetch = async (input, init) => {
  const boundary = requests.getStore()
  if (!boundary) return fetchGateway(input, init)
  if (!boundary.ui) return stopped('Chat configuration is temporarily unavailable.')
  const original = new Request(input, init)
  const payload = JSON.parse(await original.text())
  let denial = null
  for (let attempt = 0; attempt < 2; attempt++) {
    if (original.signal.aborted) return stopped('The reply stopped.')
    const answer = await boundary.ui.editor('muniment:chat-grant', JSON.stringify(denial))
    const grant = answer && JSON.parse(answer)
    if (!grant || grant.error) return stopped(grant?.error || 'Chat configuration is temporarily unavailable.')
    if (original.signal.aborted) return stopped('The reply stopped.')
    const headers = new Headers(original.headers)
    headers.set('Authorization', `Bearer ${grant.virtual_key}`)
    payload.model = grant.model
    const response = await fetchGateway(`${grant.gateway_url.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST', headers, body: JSON.stringify(payload), signal: original.signal, redirect: 'error'
    })
    if (response.ok) return response
    const body = await response.json().catch(() => null)
    denial = { status: response.status, body }
    // Rust validates the envelope and performs recovery. Never replay a streamed response.
    if (attempt === 0) continue
    // Apply terminal recovery without starting another gateway request.
    await boundary.ui.editor('muniment:chat-grant', JSON.stringify({ ...denial, terminal: true }))
    return stopped('The model could not complete this reply.')
  }
}

export default function (pi) {
  let ui
  pi.on('session_start', (_event, context) => {
    ui = context.ui
  })
  pi.registerProvider('muniment', {
    baseUrl: process.env.OPENAI_BASE_URL,
    apiKey: 'muniment-runtime-boundary',
    api: 'openai-completions',
    streamSimple: (model, context, options) => requests.run({ ui }, () =>
      streamSimpleOpenAICompletions(model, context, {
        ...options, apiKey: 'muniment-runtime-boundary', maxRetries: 0
      })
    ),
    models: [{
      id: process.env.PI_DEFAULT_MODEL,
      name: process.env.PI_DEFAULT_MODEL,
      reasoning: false,
      input: ['text', 'image'],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 128000,
      maxTokens: 4096,
      compat: {
        supportsDeveloperRole: false,
        supportsStore: false,
        supportsUsageInStreaming: false,
        maxTokensField: 'max_tokens'
      }
    }]
  })
}
