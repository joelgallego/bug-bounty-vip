# bug-bounty.vip

Detects new bug bounty programs and scope expansions across seven platforms,
runs recon on the new targets, and publishes the result at
**[www.bug-bounty.vip](https://www.bug-bounty.vip)**.

## What it does

Every 30 minutes it polls the public feeds of **HackerOne, Bugcrowd, Intigriti,
YesWeHack, Federacy, GObugfree and Standoff 365** and looks for two kinds of
event: a program that just appeared, or new assets added to the scope of one
that already existed.

Each event is enriched — bounty range, API docs, OAuth, tech stack — and the new
targets get recon: certificate transparency, passive sources, DNS bruteforce,
HTTP probing and port scanning. The result is a report per event, plus the whole
dataset as JSON.

Scope changes are the useful signal: a program that suddenly adds
`payments.example.com` to its scope is announcing that something new is exposed.

## Philosophy

**Free, and free forever.**

- **No accounts, no paywall, no "premium" tier.** Everything is public.
- **No ads, no analytics, no cookies.** The site is static HTML and JSON served
  by Cloudflare. Your theme, your language and your active filters go in
  `localStorage` and that's all — there is not a single `document.cookie` in it,
  and the page loads no third-party resources whatsoever.
- **Open source.** This repository is the engine that builds the site.
- **Funded by donations**, not by selling anything. There is nothing to upsell.

## What is deliberately not here

- **The data.** No program database, no recon output, no feeds. The published
  JSON is served by the site.
- **The acquisition layer** for platforms that need a session or interception to
  be read. That code stays private on purpose: it is what could cost access to
  the sources, and publishing it helps nobody. Concretely, `sync.py` reads a
  local feed for GObugfree that this repository does not generate.
- **Credentials.** Anything that needs a secret reads it from a file outside the
  working tree, never from the code. Nothing secret belongs in a file that gets
  published.
- **The frontend.** `web/` — the page, the translations, the icons — is not here
  yet, so this repository is the engine rather than the whole site. Nor are the
  systemd units that schedule it, or the recon wordlists and resolvers that the
  pipeline expects under `recon_assets/`.

## How it is built

| Piece | Role |
|---|---|
| `sync.py` | Polls the feeds, detects events, queues recon, publishes |
| `recon_worker.py` + `recon_pipeline.py` + `recon_scope.py` | Permanent worker consuming the recon queue in three phases, and the recon layers |
| `export_json.py` | Turns the database into the JSON the site serves |
| `publicar.py` | The only thing that triggers a deploy on its own (lock + debounce). `export_json.py --deploy` is the manual override and skips both on purpose |
| `fetch_standoff.py`, `fetch_marketplace.py` | Own feeds for platforms that need more than a feed |
| `respaldo.py` + `generar_feeds.rb` | Local feed generation when the upstream source is down |
| `enrich_*.py`, `tecnologias.py`, `valor_assets.py` | Field enrichment |
| `vendor/bounty-targets/` | Upstream crawler, vendored (see attribution) |

Python 3 and SQLite. Python dependencies are in `requirements.txt` (`requests`
and `tldextract`); `generar_feeds.rb` needs the Ruby gems listed in `Gemfile`.
The recon layers shell out to external binaries that are not installed from
here: `subfinder`, `dnsx`, `httpx`, `naabu`, `gau`, `gotator`, `puredns` and
`massdns`, plus `nuclei` and `webanalyze` for enrichment.

## Attribution

- [`arkadiyt/bounty-targets-data`](https://github.com/arkadiyt/bounty-targets-data)
  and [`arkadiyt/bounty-targets`](https://github.com/arkadiyt/bounty-targets),
  both MIT, by [@arkadiyt](https://github.com/arkadiyt). The crawler is vendored
  under `vendor/bounty-targets/` with its license, and it is what makes the local
  fallback feeds possible when the upstream dumps stall.
- The program data itself belongs to the platforms and to the companies running
  the programs. This project only aggregates what they publish.

## Status

The site is live and this repository mirrors the code that runs it: development
happens in a private working tree and is copied here. It is the engine of a
running service, not a turnkey tool — it expects a populated SQLite database and
the recon tooling installed.

## License

MIT, see [LICENSE](LICENSE). The data is a separate question and is not covered
by it.
