// Fetch only the service origin's icon. Do not send MCP paths, tokens, or headers.
export async function serviceFavicon(serverUrl, request = fetch) {
  try {
    const server = new URL(serverUrl)
    if (!['https:', 'http:'].includes(server.protocol) || server.username || server.password) return null
    const response = await request(new URL('/favicon.ico', server.origin), { signal: AbortSignal.timeout(3000), redirect: 'error', credentials: 'omit' })
    if (!response.ok || !response.body) return null
    const type = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase()
    if (!['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/x-icon', 'image/vnd.microsoft.icon'].includes(type)) { await response.body.cancel(); return null }
    const chunks = [], reader = response.body.getReader()
    let size = 0
    try {
      while (true) {
        const {done, value} = await reader.read()
        if (done) break
        size += value.length
        if (size > 128 * 1024) { await reader.cancel(); return null }
        chunks.push(Buffer.from(value))
      }
    } finally { reader.releaseLock() }
    return size ? `data:${type};base64,${Buffer.concat(chunks).toString('base64')}` : null
  } catch { return null }
}
