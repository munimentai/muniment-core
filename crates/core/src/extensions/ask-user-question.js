// Included in the bundled Pi extension. The desktop renders the editor payload
// as a questionnaire while Pi waits for its correlated RPC response.
function registerUserQuestion(pi) {
  pi.registerTool({
    name: 'ask_user_question',
    label: 'Ask a question',
    description: 'Ask the user for missing requirements or a choice that affects the result. Use this tool instead of listing questions in chat. Ask only what cannot be inferred from the conversation or available files. The user can select choices or write an answer. This is not a permission or approval tool.',
    parameters: {
      type: 'object', additionalProperties: false, required: ['questions'],
      properties: { questions: { type: 'array', minItems: 1, maxItems: 4, items: {
        type: 'object', additionalProperties: false, required: ['id', 'question'],
        properties: {
          id: { type: 'string', minLength: 1, maxLength: 80 },
          question: { type: 'string', minLength: 1, maxLength: 2000 },
          multiSelect: { type: 'boolean' },
          options: { type: 'array', maxItems: 6, items: {
            type: 'object', additionalProperties: false, required: ['label'],
            properties: { label: { type: 'string', minLength: 1, maxLength: 200 }, description: { type: 'string', maxLength: 500 } }
          } }
        }
      } } }
    },
    async execute(_id, args, signal, _update, context) {
      if (new Set(args.questions.map(q => q.id)).size !== args.questions.length) throw new Error('Question ids must be unique.');
      if (signal?.aborted) return { content: [{ type: 'text', text: 'The question was cancelled.' }] };
      let abort;
      const cancelled = new Promise(resolve => { abort = () => resolve(undefined); });
      signal?.addEventListener('abort', abort, { once: true });
      let value;
      try {
        value = await Promise.race([
          context.ui.editor('muniment:ask_user_question', JSON.stringify(args)), cancelled,
        ]);
      } finally {
        signal?.removeEventListener('abort', abort);
      }
      if (value === undefined || signal?.aborted) {
        return { content: [{ type: 'text', text: 'The user did not answer. Do not infer an answer.' }], details: { cancelled: true } };
      }
      const result = JSON.parse(value);
      if (!Array.isArray(result.answers) || result.answers.length !== args.questions.length) throw new Error('The answers are incomplete.');
      for (const question of args.questions) {
        const matches = result.answers.filter(answer => answer.id === question.id);
        const answer = matches[0];
        if (matches.length !== 1 || !Array.isArray(answer.selected) || typeof answer.text !== 'string'
          || (!answer.selected.length && !answer.text.trim())
          || (!question.multiSelect && answer.selected.length > 1)
          || answer.selected.some(label => !(question.options || []).some(option => option.label === label))) {
          throw new Error('The answer does not match the question.');
        }
      }
      return { content: [{ type: 'text', text: JSON.stringify(result) }], details: result };
    }
  });
}

registerUserQuestion(pi);
