// The runtime writes this extension beside the session logs and loads it on
// every launch. The model knows itself as the assistant inside a desktop app
// and nothing more: the harness name and the product name reach neither the
// system prompt nor the tool descriptions. Paths stay as they are, because the
// model reads files by them.

const HARNESS_WORD = /\bpi\b/i

// Every rewrite of prose. Multi-word rules run first, then the two fallbacks.
const PROSE_RULES = [
  [/\bpi-subagents\b/g, 'subagents'],
  [/\bpi-intercom\b/g, 'intercom'],
  [/\bpi-([a-z][\w-]*)/g, '$1'],
  [/\bPi-agent\b/g, 'agent'],
  [/\bPI_\*\s*environment variables\b/g, 'the environment variables'],
  [/\bPi (?=(?:model|agent|provider|tool|core|spawn|task|run|event|thinking|argv|child|children|evidence|prompt|stderr)s?\b)/g, ''],
  [/\x60pi (?=[-\w])/g, '\x60agent '],
  [/\bpi (?=-p\b|--mode\b|-ne\b|-e\b)/g, 'agent '],
  [/\bthe Muniment Home\b/g, 'the Home folder'],
  [/\bMuniment Home\b/g, 'the Home folder'],
  [/\bmuniment\b/gi, 'the app'],
  [/\bpi\b/gi, 'the agent'],
]

// A token with a separator is a path, and a path keeps its name.
const PATH_MARK = '\u0000'

function rewriteProse(text) {
  const paths = []
  const protectedText = text.replace(/\S*[\\/]\S*/g, (token) => {
    paths.push(token)
    return `${PATH_MARK}${paths.length - 1}${PATH_MARK}`
  })
  const rewritten = PROSE_RULES.reduce((current, [pattern, replacement]) => current.replace(pattern, replacement), protectedText)
  return rewritten.replace(/\u0000(\d+)\u0000/g, (_, index) => paths[Number(index)])
}

// A skill that names the harness in its name, its description or its
// location leaves the prompt. When none remains, the skills paragraph goes too.
// The tag names carry an escaped bracket, so the copy lint reads them as regex and not as markup.
const SKILLS_BLOCK = /\n*The following skills provide[\s\S]*?<available_skills\>([\s\S]*?)<\/available_skills\>\n?/

export function neutralSystemPrompt(prompt) {
  if (typeof prompt !== 'string') return prompt
  const withoutHarnessSkills = prompt.replace(SKILLS_BLOCK, (block, inner) => {
    const skills = [...inner.matchAll(/<skill\>[\s\S]*?<\/skill\>/g)].map((match) => match[0])
    const kept = skills.filter((skill) => !HARNESS_WORD.test(skill) && !/\bpi-/i.test(skill))
    if (!kept.length) return '\n'
    return block.replace(inner, `\n  ${kept.join('\n  ')}\n`)
  })
  return withoutHarnessSkills
    .split('\n')
    .map((line) => (/^Current working directory:|^\s*<location\>/.test(line) ? line : rewriteProse(line)))
    .join('\n')
}

function toolName(tool) {
  return tool?.function?.name ?? tool?.name ?? ''
}

const HARNESS_TOOL = /(?:^|[_-])pi(?:$|[_-])/i
const PROSE_KEYS = new Set(['description', 'text', 'content', 'system'])

function rewriteStrings(value, key = '') {
  if (typeof value === 'string') return PROSE_KEYS.has(key) ? rewriteProse(value) : value
  if (Array.isArray(value)) return value.map((entry) => rewriteStrings(entry, key))
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([entryKey, entry]) => [entryKey, rewriteStrings(entry, entryKey)]))
  }
  return value
}

// The provider payload: a tool whose name carries the harness leaves, every
// tool description and every system text is rewritten, and the rest stays.
export function neutralPayload(payload) {
  if (!payload || typeof payload !== 'object') return payload
  const next = { ...payload }
  if (Array.isArray(next.tools)) {
    next.tools = next.tools
      .filter((tool) => !HARNESS_TOOL.test(toolName(tool)))
      .map((tool) => {
        if (Array.isArray(tool?.functionDeclarations)) {
          const declarations = tool.functionDeclarations
            .filter((declaration) => !HARNESS_TOOL.test(declaration?.name ?? ''))
            .map((declaration) => rewriteStrings(declaration))
          return { ...tool, functionDeclarations: declarations }
        }
        return rewriteStrings(tool)
      })
  }
  if (typeof next.system === 'string') next.system = neutralSystemPrompt(next.system)
  else if (Array.isArray(next.system)) {
    next.system = next.system.map((entry) => (typeof entry?.text === 'string' ? { ...entry, text: neutralSystemPrompt(entry.text) } : entry))
  }
  if (next.systemInstruction && typeof next.systemInstruction === 'object') next.systemInstruction = rewriteStrings(next.systemInstruction)
  if (Array.isArray(next.messages)) {
    next.messages = next.messages.map((message) => {
      if (message?.role !== 'system' && message?.role !== 'developer') return message
      if (typeof message.content === 'string') return { ...message, content: neutralSystemPrompt(message.content) }
      return rewriteStrings(message)
    })
  }
  return next
}

export default function (pi) {
  pi.on('before_agent_start', (event) => ({ systemPrompt: neutralSystemPrompt(event.systemPrompt) }))
  pi.on('before_provider_request', (event) => neutralPayload(event.payload))
}
