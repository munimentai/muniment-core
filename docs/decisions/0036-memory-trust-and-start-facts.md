# 0036 — Fact trust, start facts and runtime-owned memory

- Status: proposed

## Context

Memory facts are Markdown files under the Home, one fact per file. A chat
reached a fact only when the model called `memory-search`, so a fact helped
only when the model thought to look. A fact saved after the model read a web
page, a file or a tool result could carry instructions from that content into
every later chat that recalled it. The desktop also wrote memory files and
opened the run journal in its own process beside the runtime.

## Decision

### Trust

Each fact file records its trust on the line after its source:

```
# Title

Source: thread:<thread> run:<run>
Trust: conversation

The fact.
```

- `user`: written or edited in Settings. Editing a fact confirms it.
- `conversation`: saved by the model before any tool in its run returned
  outside content. Memory search, agent tools, questions to the user,
  creation plans, artifact publishing, `write` and `edit` return none.
- `external`: saved by the model after any other tool, such as web search,
  fetch, browser, shell, file reads or an integration, ran in the same run. A
  fact without a trust line is external.

The runtime decides the trust from the run's journaled tool calls when it
saves the fact. The model cannot set it.

### Start facts

Every chat with recall on starts with up to 2 KB of user and conversation
facts in its system prompt, labelled as data. The runtime counts the facts
each memory search returns in `memory-usage.json` in the private profile, and
the most recalled facts come first, then the newest. External facts never
start a chat. They stay reachable through memory search, and their file text
shows their trust.

### Runtime ownership

The runtime is the one process that reads and writes memory files and opens
the run journal. The desktop reaches the profile, facts, deleted facts and
recall settings through nine `memory_` actions of `models.request`. The runtime
names legacy session folders when it opens its journal.

## Consequences

- A fact the user states in conversation reaches later chats without a search.
- Text from a web page or file cannot reach a later chat unless the model
  searches for it or the user confirms the fact.
- Memory settings need the runtime. When it is not running, Settings shows the
  background service error.
- Facts saved before this change start as external until the user edits them.
