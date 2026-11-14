# Reference library

What published MCP server packages declare, release by release.

Drift detection compares a server with its own earlier state, so a server that was tampered
with before the first scan becomes its own baseline. The library gives a second point of
comparison: the declarations the package's publisher actually shipped.

## How it is built

For every package in `catalog.json`, each stable release on npm is installed into a throwaway
directory with install scripts disabled, started over stdio, and asked for `tools/list`. No tool
is called. Packages that need an API key to start are given a placeholder value, which is enough
for them to list their tools.

    data/index.json               package -> release -> publication date, outcome, manifest digest
    data/manifests/<sha256>.json  tool declarations, stored once per distinct content

Releases are third-party code. Build the library in a disposable environment (the `reference`
workflow does this on a hosted runner), not on a workstation.

## Verdicts

`identify` compares a server's declared tools with every release in the library.

| Verdict | Meaning |
|---|---|
| `match` | Identical to at least one published release. The matching releases are named. |
| `subset` | Every declared tool is identical to the release's tool of the same name; some are absent, as when a deployment disables tools. |
| `deviation` | Mostly a release's tools, at least one of them byte-identical, with others added or redefined. The differing tools are named. |
| `unknown` | Nothing in the library resembles it. No claim is made. |

The release is found from the declarations themselves. The version a server reports about itself
is not used: several official packages report a version that differs from their npm release.

## Limits

- A match says the declarations are the publisher's. It says nothing about what the code behind
  them does.
- Only packages in the catalog can be recognized. Most hosted MCP servers are bespoke and will be
  `unknown`.
- A server that rewrote every tool of a release shares nothing byte-identical with it and is
  reported as `unknown`, not as a deviation.
- npm only for now.

## Usage

    python3 -m reference build --latest 40
    python3 -m reference summary
    python3 -m reference history @modelcontextprotocol/server-filesystem
    python3 -m reference identify tools.json
    python3 -m reference survey
