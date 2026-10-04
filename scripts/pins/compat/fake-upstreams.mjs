// Loopback stand-ins for an OpenAI-compatible gateway and the Anthropic Messages API.
import { createServer } from 'node:http'

function listen(handler) {
  const requests = []
  const server = createServer((request, response) => {
    let body = ''
    request.on('data', chunk => { body += chunk })
    request.on('end', () => {
      const entry = { method: request.method, url: request.url, headers: request.headers, body: body ? safeJson(body) : null }
      requests.push(entry)
      handler(entry, response)
    })
  })
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({
    url: `http://127.0.0.1:${server.address().port}`,
    requests,
    close: () => new Promise(done => { server.closeAllConnections?.(); server.close(done) }),
  })))
}

function safeJson(text) {
  try { return JSON.parse(text) } catch { return text }
}

function sse(response, frames, done = true) {
  response.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' })
  for (const frame of frames) response.write(frame)
  if (done) response.write('data: [DONE]\n\n')
  response.end()
}

/**
 * Streams `reply` for every chat completion, with cached prompt tokens in the usage chunk.
 * With `toolCall`, the first completion calls that tool instead.
 */
export function openAiServer({ reply = '12', toolCall = null } = {}) {
  let called = false
  return listen((request, response) => {
    if (request.method !== 'POST') {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify({ object: 'list', data: [] }))
      return
    }
    const model = request.body?.model
    const usage = { choices: [], usage: { prompt_tokens: 100, completion_tokens: 2, total_tokens: 102, prompt_tokens_details: { cached_tokens: 50 }, completion_tokens_details: { reasoning_tokens: 0 } } }
    let chunks
    if (toolCall && !called) {
      called = true
      const call = { index: 0, id: 'call_fixture', type: 'function', function: { name: toolCall.name, arguments: JSON.stringify(toolCall.arguments) } }
      chunks = [
        { choices: [{ index: 0, delta: { role: 'assistant', tool_calls: [call] }, finish_reason: null }] },
        { choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] },
        usage,
      ]
    } else {
      chunks = [
        { choices: [{ index: 0, delta: { role: 'assistant', content: reply }, finish_reason: null }] },
        { choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] },
        usage,
      ]
    }
    sse(response, chunks.map(chunk => `data: ${JSON.stringify({ id: 'fixture', object: 'chat.completion.chunk', created: 0, model, ...chunk })}\n\n`))
  })
}

/** Answers the Messages API with one streamed text block, and counts tokens for any probe. */
export function anthropicServer(reply = '12') {
  return listen((request, response) => {
    if (request.method !== 'POST') {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify({ data: [], has_more: false }))
      return
    }
    if (request.url.includes('count_tokens')) {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify({ input_tokens: 10 }))
      return
    }
    const model = request.body?.model ?? 'claude-fixture'
    const usage = { input_tokens: 100, output_tokens: 2, cache_read_input_tokens: 50, cache_creation_input_tokens: 0 }
    const message = { id: 'msg_fixture', type: 'message', role: 'assistant', model, content: [], stop_reason: null, stop_sequence: null, usage }
    if (request.body?.stream === false) {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify({ ...message, content: [{ type: 'text', text: reply }], stop_reason: 'end_turn' }))
      return
    }
    const event = (type, data) => `event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`
    sse(response, [
      event('message_start', { message }),
      event('content_block_start', { index: 0, content_block: { type: 'text', text: '' } }),
      event('content_block_delta', { index: 0, delta: { type: 'text_delta', text: reply } }),
      event('content_block_stop', { index: 0 }),
      event('message_delta', { delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 2 } }),
      event('message_stop', {}),
    ], false)
  })
}
