# 0035 — Keyless web search as a loopback SearXNG endpoint

- Status: proposed

## Context

Pi's web tools come from the pi-web-access extension. It registers
`web_search`, `fetch_content` and `get_search_content`, and it reads its
providers from `web-search.json` in Pi's agent directory. Every provider it
implements needs a key or a server, except a shared free endpoint whose rate
limits other users exhaust. Muniment needs web search that works on first
launch with no key and no setup.

## Decision

### The engine

`muniment-search` is Muniment's own keyless metasearch. It queries Brave,
DuckDuckGo, Wikipedia, Yahoo and Bing the way a browser does, parses their
result pages, and merges them. Each engine has one session: its own cookie
jar, a same-origin `Referer`, a random 1–3 s gap between requests, one retry
on a reset connection, and a cooldown after a block. A block is a status
other than 200, a final URL under `/sorry/` or `/captcha`, or a page with no
results (Wikipedia excepted). The word "captcha" in a page body is no signal.
Metasearch merges results by normalized URL, interleaves them by rank in the
configured engine order, applies `site:` and `-site:` filters to result hosts,
and returns at most 20 results. The host enables, disables and orders the
engines through `Config`.

### The provider contract

The engine joins pi-web-access as its `searxng` provider. No SearXNG
software runs, and Muniment installs none. The engine answers the SearXNG
JSON format itself:

- `GET {base}/search?q=…&format=json[&time_range=day|week|month|year]`.
- `site:` and `-site:` terms arrive inside `q`.
- The answer is `{"query", "results": [{"url", "title", "content"}],
  "unresponsive_engines"}`, where `content` is the snippet.
- A format other than `json` answers 400. A missing or wrong bearer token
  answers 401. When every engine fails, the answer is 503, so the client moves
  on to its next provider.
- `GET /healthz` takes no token.

The server listens on `127.0.0.1` at an ephemeral port, refuses non-loopback
peers, and limits a request head to 64 KiB. It writes `{port, token}` to the
endpoint file the host names, `<agent>/muniment-search-endpoint.json`,
readable by its owner only. The token is 32 random bytes in hex, compared in
constant time. pi-web-access sends it through `searxngHeaders` as
`Authorization: Bearer <token>`. The runtime owns the server's start and stop.

### Settings

Core's `search_settings` record, `search-settings.json` in the state
directory and readable by its owner only, holds the search settings:

- `order`: the providers pi-web-access tries, each on or off. An entry is
  `muniment` (this engine), `exa` (keyless without a key) or a pi-web-access
  provider that has a key.
- `engines`: the enabled engines.
- `keys`: each provider's key, with the base URL or zone fields some
  providers read. A client reads a key only as set or not and its last four
  characters.

On each Pi launch and after each change, core writes the record into
`web-search.json`: each provider's key fields, `searxngBaseUrl` and
`searxngHeaders` while the server runs, and `searchRouting` with the enabled
providers in order and `muniment` as `searxng`. Every other key stays as the
user wrote it. With no provider to route to, `webSearch.enabled` is false,
so Pi registers no `web_search` tool. pi-web-access reads the file once per
Pi process, so a change reaches the next launch. The engine set reaches the
running server at once, on the same port and token.

### The loopback exemption

pi-web-access sends SearXNG requests through its SSRF guard, which refuses
loopback addresses unless `ssrf.allowRanges` covers them. That range would
also let `fetch_content` reach every loopback service, so Muniment leaves
`allowRanges` alone. A patched pi-web-access exempts the configured SearXNG
base URL from the guard, as it exempts its Firecrawl, Crawl4AI, Brave, Exa
and Tavily base URLs. Core applies the patch to the pinned package.

### The transport

Requests go through the `Transport` trait.

- The default is `ureq` with rustls, ring and the OS certificate verifier,
  all already in the core lock. It needs no native build tools on the Linux,
  macOS and Windows CI machines.
- Brave goes through the system `curl` program when one is present. Brave
  answers 429 to the rustls handshake from an address it has flagged, and it
  lets curl's handshake through. The engine finds `curl` on `PATH` once and
  checks that `curl --version` runs; macOS, most Linux distributions and
  Windows 10 and later ship it. Each request runs `curl` with arguments and
  no shell, ignores `.curlrc`, allows HTTPS only, and sends the same user
  agent and headers as the `ureq` transport. The cookie jar and the response
  body live in a private temporary directory per session. Without a working
  `curl`, Brave uses `ureq`. No build links libcurl.
- Each engine report names the transport the engine used.
- `wreq` with a Chrome profile is the next transport. It waits for its Chrome
  profiles on crates.io, and it needs cmake and libclang on every CI machine.

## Consequences

Search works without a key. Users who add Firecrawl, Tavily, Exa or Brave keys
keep those providers in their own slots. An engine that changes its markup
returns no results and counts as blocked until its parser changes. The saved
page in `crates/search/tests/fixtures/` pins each parser.
