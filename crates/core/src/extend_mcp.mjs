// Registers the MCP servers picked for this turn. The runtime writes their
// definitions to the file MUNIMENT_EXTEND_MCP names. A server saved with a
// bearer token gets it from the private token file here, in memory only, so
// the token never reaches the environment the model's commands see.
import { readFileSync } from 'node:fs'

export default function (pi) {
  const file = process.env.MUNIMENT_EXTEND_MCP
  if (!file) return
  const snapshot = JSON.parse(readFileSync(file, 'utf8'))
  let tokens = {}
  try { tokens = JSON.parse(readFileSync(snapshot.tokenFile, 'utf8')) } catch {}
  for (const [name, definition] of Object.entries(snapshot.mcpServers ?? {})) {
    const { bearerToken, ...config } = definition
    if (bearerToken) {
      // The marker names the token's key, which stays the item's id.
      const token = tokens[typeof bearerToken === 'string' ? bearerToken : name]
      if (typeof token !== 'string') continue
      config.headers = { ...config.headers, Authorization: `Bearer ${token}` }
    }
    pi.registerMcpServer(name, config)
  }
}
