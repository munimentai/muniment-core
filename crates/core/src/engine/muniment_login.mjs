// The account sign-in: one command that runs Pi's own OAuth login for a
// provider inside an RPC process the runtime owns, and reports each step as a
// notify line the runtime parses. The credential lands in Pi's auth.json.
import { ServerResponse } from 'node:http'

// Pi owns validation and token exchange. This isolated sign-in process only
// replaces its local HTML response with Muniment's shared branded page.
export function installLoginPages(success, failure) {
  if (!success || !failure) return () => {}
  const original = ServerResponse.prototype.end
  const originalWriteHead = ServerResponse.prototype.writeHead
  const headers = new WeakMap()
  function writeHead(...args) {
    const supplied = args.at(-1)
    const entries = Array.isArray(supplied)
      ? Array.from({ length: supplied.length / 2 }, (_, i) => [supplied[i * 2], supplied[i * 2 + 1]])
      : supplied && typeof supplied === 'object' ? Object.entries(supplied) : []
    const values = Object.fromEntries(entries.map(([key, value]) => [key.toLowerCase(), value]))
    headers.set(this, {
      html: String(values['content-type'] ?? this.getHeader('content-type') ?? '').startsWith('text/html'),
      fixedLength: values['content-length'] !== undefined || this.hasHeader('content-length'),
    })
    return originalWriteHead.apply(this, args)
  }
  function end(body, ...args) {
    const path = this.req?.url?.split('?')[0]
    const response = headers.get(this)
    if ((path === '/callback' || path === '/auth/callback') &&
        response?.html && !response.fixedLength &&
        typeof body === 'string' && /<!doctype html>/i.test(body) &&
        !this.hasHeader('content-length')) {
      body = this.statusCode >= 200 && this.statusCode < 300 ? success : failure
    }
    return original.call(this, body, ...args)
  }
  ServerResponse.prototype.writeHead = writeHead
  ServerResponse.prototype.end = end
  return () => {
    if (ServerResponse.prototype.end === end) ServerResponse.prototype.end = original
    if (ServerResponse.prototype.writeHead === writeHead) ServerResponse.prototype.writeHead = originalWriteHead
  }
}

export default function (pi) {
  pi.registerCommand("muniment-login", {
    description: "Sign in to a provider account",
    handler: async (args, ctx) => {
      const [provider, type = "oauth"] = String(args ?? "").trim().split(/\s+/)
      const say = (payload) => ctx.ui.notify(JSON.stringify({ muniment: "login", provider, ...payload }), "info")
      const registry = ctx.modelRegistry
      const runtime = registry.runtime ?? registry
      if (typeof runtime.login !== "function") {
        say({ stage: "failed", message: "This harness cannot sign in to an account." })
        return
      }
      const restorePages = installLoginPages(process.env.MUNIMENT_LOGIN_SUCCESS_HTML, process.env.MUNIMENT_LOGIN_ERROR_HTML)
      try {
        say({ stage: "start" })
        const controller = new AbortController()
        const credential = await runtime.login(provider, type, {
          signal: controller.signal,
          prompt: async (prompt) => {
            if (prompt.type === "select") {
              // The browser method is Muniment's: a sign-in never asks which.
              const browser = prompt.options.find((option) => /browser/i.test(`${option.label ?? ""} ${option.id ?? ""}`))
              if (browser) return browser.id
              const labels = prompt.options.map((option) => option.label ?? option.id)
              const chosen = await ctx.ui.select(prompt.message, labels)
              return prompt.options.find((option) => (option.label ?? option.id) === chosen)?.id ?? chosen
            }
            return ctx.ui.input(prompt.message, prompt.placeholder ?? "")
          },
          notify: (event) => say({ stage: "event", event }),
        })
        say({ stage: "done", type: credential?.type ?? "oauth" })
      } catch (error) {
        say({ stage: "failed", message: error instanceof Error ? error.message : String(error) })
      } finally {
        restorePages()
      }
    },
  })
}
