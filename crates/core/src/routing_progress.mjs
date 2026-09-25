import { randomUUID, createHash } from 'node:crypto'

const stages = new Set(['choosing-model', 'waiting-for-account', 'fallback', 'thinking'])
const prefix = 'muniment:routing:'

// Each provider request owns its poller. Stop before output or another request,
// and never forward a credential to an endpoint other than the local router.
export default function routingProgress(pi) {
  let active = null
  const metadataType = 'muniment-routing-task'
  const readTask = ctx => {
    const entries = ctx.sessionManager?.getBranch?.() ?? []
    return [...entries].reverse().find(entry => entry.type === 'custom' && entry.customType === metadataType)?.data ?? { task: 'default', failures: 0 }
  }
  pi.registerCommand?.('routing-new-task', {
    description: 'Reconsider model cost and capability for a new task in this thread',
    handler: async (_args, ctx) => {
      pi.appendEntry(metadataType, { task: randomUUID(), failures: 0 })
      ctx.ui.notify('The router will select a model for the new task.', 'info')
    },
  })
  pi.on('tool_result', async (event, ctx) => {
    const previous = readTask(ctx)
    const failed = event.isError === true || (Number.isInteger(event.details?.exitCode) && event.details.exitCode !== 0)
    pi.appendEntry?.(metadataType, { ...previous, failures: failed ? Math.min(100, previous.failures + 1) : 0 })
  })
  async function stop(drain = false) {
    const current = active
    if (!current) return
    if (drain) await current.poll()
    if (active !== current) return
    active = null
    clearInterval(current.timer)
    current.controller?.abort()
  }
  pi.on('before_provider_headers', async (event, ctx) => {
    await stop()
    const model = event.model ?? ctx.model
    if (model?.provider !== 'muniment-router') return
    let url
    try { url = new URL(model.baseUrl) } catch { return }
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') return
    let authorization = Object.entries(event.headers).find(([name]) => name.toLowerCase() === 'authorization')?.[1]
    // Some provider SDKs add Authorization after the header hook.
    if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
      const credential = await ctx.modelRegistry.getApiKeyAndHeaders(model)
      if (!credential?.ok || !credential.apiKey) return
      authorization = `Bearer ${credential.apiKey}`
    }
    const id = randomUUID()
    event.headers['x-muniment-routing-id'] = id
    const sessionId = ctx.sessionManager?.getSessionId?.()
    if (sessionId) {
      const task = readTask(ctx)
      event.headers['x-muniment-thread'] = createHash('sha256').update(sessionId).digest('hex')
      event.headers['x-muniment-task'] = createHash('sha256').update(String(task.task)).digest('hex')
      event.headers['x-muniment-validation-failures'] = String(Math.max(0, Math.min(100, Number(task.failures) || 0)))
    }
    const current = { count: 0, busy: null, timer: null, controller: null }
    current.poll = () => {
      if (active !== current) return Promise.resolve()
      if (current.busy) return current.busy
      current.busy = (async () => {
        current.controller = new AbortController()
        const deadline = setTimeout(() => current.controller?.abort(), 1500)
        try {
          const response = await fetch(new URL(`/v1/routing-progress/${id}`, url), {
            headers: { authorization }, signal: current.controller.signal,
          })
          if (!response.ok) return
          const snapshot = await response.json()
          if (active !== current || !Array.isArray(snapshot.stages)) return
          for (const stage of snapshot.stages.slice(current.count, 64)) {
            current.count++
            if (stages.has(stage)) ctx.ui.notify(`${prefix}${stage}`, 'info')
          }
          if (snapshot.done) await stop()
        } catch { /* Progress never fails a model request. */ }
        finally { clearTimeout(deadline); current.busy = null }
      })()
      return current.busy
    }
    active = current
    current.timer = setInterval(current.poll, 150)
    current.timer.unref?.()
  })
  pi.on('after_provider_response', () => stop(true))
  pi.on('agent_end', () => stop())
  pi.on('session_shutdown', () => stop())
}
