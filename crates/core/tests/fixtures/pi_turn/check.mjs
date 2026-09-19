// Runs the identity extension over one recorded turn: the assembled system
// prompt and the provider payload. Prints what the model would receive.
import fs from 'node:fs'

const [extensionPath, promptPath, payloadPath] = process.argv.slice(2)
// This fixture checks prompt rewriting. Harness wire tests cover the bundled model import.
const source = fs.readFileSync(extensionPath, 'utf8').replace(/^import \{ completeSimple \}[^\n]*\n/m, '')
const { default: register } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
const handlers = {}
register({ on: (name, handler) => { handlers[name] = handler } })
const prompt = fs.readFileSync(promptPath, 'utf8')
const payload = JSON.parse(fs.readFileSync(payloadPath, 'utf8'))
const started = await handlers.before_agent_start({ systemPrompt: prompt, prompt: 'what model are you' })
const messages = [{ role: 'system', content: started.systemPrompt }, ...payload.messages.slice(1)]
const request = handlers.before_provider_request({ payload: { ...payload, messages } })
process.stdout.write(JSON.stringify({ systemPrompt: started.systemPrompt, payload: request }))
