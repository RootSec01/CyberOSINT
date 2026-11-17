<p align="center">
  <img src="docs/images/logo.png" alt="Raqeeb" width="120">
</p>

<h1 align="center">Raqeeb</h1>

<p align="center">
  Find exposed MCP servers, read what they declare, and notice when that changes.<br>
  No dangerous tool is ever invoked.
</p>

<p align="center">
  <a href="https://github.com/RootSec01/CyberOSINT/actions/workflows/tests.yml"><img alt="tests" src="https://github.com/RootSec01/CyberOSINT/actions/workflows/tests.yml/badge.svg"></a>
  <a href="https://github.com/RootSec01/CyberOSINT/actions/workflows/observatory.yml"><img alt="observatory" src="https://github.com/RootSec01/CyberOSINT/actions/workflows/observatory.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-6E7781"></a>
</p>

![Scan map of a lab server whose read_file tool differs from the published release](docs/images/scan-map.png)

![The altered tool beside the published text, with the hidden character shown](docs/images/tool-comparison.png)

AI agents reach real systems through the Model Context Protocol. An MCP server lists the tools an
agent may call: run a command, query a database, read a file. Port and CVE scanners can tell you the
server is reachable. They cannot tell you what an agent connected to it is able to do, or that the
answer changed after last week's redeploy.

Raqeeb is entered in SAIF 2026 under the name CyberOSINT.

## What it does

1. **Discover** MCP servers tied to an organization from Shodan, Censys and Certificate Transparency.
2. **Negotiate** the real protocol (`server/discover`, falling back to `initialize`) and read `tools/list`.
3. **Classify** each declared tool by capability and run passive detectors over the declarations.
4. **Grade** every statement by how it was established (see evidence levels).
5. **Monitor** each server: typed drift between scans, a manifest fingerprint, alerts on escalation only.

## Field study

`observatory/` re-reads a fixed sample of public MCP servers every day and records what each one
declares. The sample was drawn once, with a fixed seed, from the official MCP Registry
(62,855 records read; 35,077 credential-free remote endpoints on 26,445 hosts; 500 sampled, one per
host).

Latest snapshot, 16 November 2026 (third daily run from GitHub Actions):

| Outcome | Endpoints |
|---|---:|
| Listed its tools with no credentials | 302 |
| Asked for authentication | 149 |
| Listed in the registry but not answering as MCP (13 with a server error) | 32 |
| Unreachable | 16 |
| Resolved to a non-public address, not contacted | 1 |

On 14 November a second run from a different network 73 minutes after the first reached 303
servers, and all 297 seen from both places returned identical tool declarations.

How often the declarations change, counting only servers that listed tools in both runs:

| | Changed | Share |
|---|---:|---:|
| 14 to 15 November | 9 of 302 | 3.0% |
| 15 to 16 November | 13 of 301 | 4.3% |
| At least once in the two days | 19 of 301 | 6.3% |

Redefining existing tools is the common change (7 and 10 servers); adding tools is next (3 and 6);
one server removed tools.

The rules were also run over what the 302 servers declare (3,302 tools). These are counts of what
the rules match, not confirmed weaknesses, and no server is named:

| Rule | Servers | Tools |
|---|---:|---:|
| Tools classified as sensitive, listed with no credentials | 205 (67.9%) | |
| Tool classified as handling credentials | 136 (45.0%) | 448 |
| Description directs the use of other tools | 21 (7.0%) | 39 |
| Filesystem path argument with no constraint | 11 (3.6%) | 15 |
| Model-directed instruction text in a declaration | 10 (3.3%) | 11 |
| Command execution tool | 5 (1.7%) | 5 |

The third row matters for the MCPTox result below. Read by hand, most of the 39 descriptions are
ordinary guidance such as "call this before product_update". The structural rule cannot tell a
publisher's own workflow hint from an injected order, so on live servers it raises an alarm on
about 1.2% of tools, against none on the 634 held-out package declarations.

`python3 -m observatory analysis` reproduces every figure in this section
([observatory/analysis.json](observatory/analysis.json)). Method, data layout and opt-out are
described in [observatory/README.md](observatory/README.md). Every run is a commit in this repository.

## Reference library

Drift detection compares a server with its own earlier state, so a server that was altered before
the first scan becomes its own baseline. `reference/` adds a second point of comparison: what the
package's publisher actually shipped. Each stable npm release of 30 widely used MCP server packages
was installed in a throwaway directory, started over stdio and asked for `tools/list`.

| | |
|---|---:|
| Releases installed | 706 |
| Releases that listed their tools | 673 |
| Distinct tool manifests | 336 |
| Release-to-release steps | 643 |
| Steps where the declarations changed | 310 |
| Steps that added at least one tool | 96 |
| Steps that only redefined existing tools | 201 |

`python3 -m reference summary` reproduces the table. Given a server's `tools/list`, `identify`
answers `match`, `subset`, `deviation` or `unknown` and names the release and the tools that differ
([reference/README.md](reference/README.md)).

Every scan now carries this verdict. `python3 -m lab.tampering` serves the published
`server-filesystem` 2.3.0 declarations twice on loopback, once as shipped and once with a hidden
sentence appended to one description. Both are first scans, so drift has nothing to compare:
the first is reported as `match`, the second as `deviation` naming `read_file`, with the published
and observed text side by side and an alert (`lab/tampering_result.json`).

None of the 287 hosted servers in the field study is a deployment of these 30 packages; all are
`unknown`. The library applies to self-hosted deployments of published packages, not to bespoke
hosted services.

## Evaluation on third-party material

`evaluation/` scores the platform on servers and data it did not write. What would count as a
result was written down before each run, and the `evaluation` workflow produces the result files
from pinned commits of the sources.

**Damn Vulnerable MCP Server**, 15 challenges, handshake and `tools/list` only
([expectations](evaluation/dvmcp_expectations.json), [results](evaluation/dvmcp_results.json)):

| | |
|---|---:|
| Weakness visible in what the server declares (in scope) | 6 |
| Detected | 5 |
| Missed (challenge 9: nothing in the declaration shows the tool reaches a shell) | 1 |
| Weakness needs a tool call or lies in server logic (out of scope) | 9 |

This run also showed that the protocol client did not carry the session id that servers built with
the official SDK require, and read zero tools from them. That is fixed and covered by a test.

**MCPTox** (AAAI 2026): 485 poisoned tool descriptions written for 45 real servers. The clean set is
the 2,121 distinct tool declarations of the reference library
([protocol](evaluation/mcptox_protocol.json), [results](evaluation/mcptox_results.json)).

The first run scored the marker-based detectors as they were: 14 of 485 poisonings found (2.9%),
71 false alarms on the clean set. These poisonings contain no suspicious words. What they share is
structure: the description of one tool gives the agent orders about a different tool. A detector
for that structure was then written using 16 of the 45 servers and 15 of the 30 packages, frozen,
and scored once on the rest:

| Held out, never used for development | |
|---|---:|
| Poisoned descriptions (29 servers) | 258 |
| Detected | 215 (83.3%) |
| Clean tool declarations (15 packages) | 634 |
| False alarms | 0 |

On the development part it finds 206 of 227 with 24 false alarms in 1,487 clean declarations; that
figure is in-sample. Development and held-out entries come from the same benchmark, so the attack
style is shared, and a poisoning that names no other tool is outside this detector. On 302 live
registry servers the same rule matches 39 of 3,302 tools, mostly legitimate workflow hints (see
Field study), so its alarms need a person's review. Comparing a
declaration with the published release does not depend on wording at all, which is what the
reference library is for.

## Evidence levels

| Level | Meaning |
|---|---|
| `OBSERVED` | A protocol or metadata fact seen directly. |
| `INFERRED` | Reasoned from a schema or description. Not confirmed behaviour. |
| `DEMONSTRATED` | A read-only canary ran against an authorized loopback lab server. |
| `VERIFIED` | Reserved. The external, non-executing path never reaches it. |

## Detectors

| Slug | Finding | MITRE | OWASP MCP Top 10 |
|---|---|---|---|
| `rce` | Exposed command-execution capability | T1059 | MCP05 |
| `open_capability` | Sensitive capability listed without authentication | T1190 | MCP07 |
| `path_traversal` | Potentially unconstrained filesystem path | T1083 | none |
| `secrets_leakage` | Secret or credential exposure | T1552 | MCP01 |
| `prompt_injection` | Prompt-injection markers in a declaration | AML.T0051.001 (ATLAS) | MCP06 |
| `tool_poisoning` | Hidden content in a declaration | T1036 | MCP03 |
| `tool_poisoning` | Description that directs the use of other tools | AML.T0051.001 (ATLAS) | MCP03 |

`path_traversal` has no close OWASP MCP Top 10 category and is left unmapped.

## Results on synthetic data

**Lifecycle demo.** `python3 -m lab.lifecycle` drives the real HTTP API against a loopback MCP server
that is redeployed three times (`lab/lifecycle_result.json`):

| Stage | Lab profile | Severity | Dangerous tools | Alerts |
|---|---|---|---:|---:|
| Baseline | read-only tools, no auth | Medium | 0 | 0 |
| Exposure | shell, SQL and file tools, no auth | Critical | 3 | 1 |
| Remediation | read-only tools again | Medium | 0 | 1 (kept as history) |

**Detector benchmark.** 72 labelled declarations in `benchmark/`, 12 of them ambiguous and excluded
from scoring.

| Split | Scored | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Development | 50 | 37 | 1 | 258 | 4 | 97.4% | 90.2% | 93.7% |
| Holdout | 10 | 8 | 0 | 52 | 0 | 100% | 100% | 100% |
| Combined | 60 | 45 | 1 | 310 | 4 | 97.8% | 91.8% | 94.7% |

These cases are synthetic and were labelled by one author, and the holdout comes from the same
design. They measure regression, not field accuracy. Three of them were written for a rule
(harmless name, dangerous wording) that was removed after it produced 17 false alarms and one
detection on real data; they are now counted as misses.

## Run it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m pytest -q

cd dashboard && npm install && npm run build && cd ..
python3 -m lab.tampering --serve --port 8000        # http://127.0.0.1:8000
```

`lab.tampering --serve` keeps four loopback servers and the console running: the published
filesystem server, the same release with one altered description, an open lab server and one
that asks for a credential. `lab.lifecycle --serve` shows one server changing across three scans.

## Evidence that can be checked elsewhere

Every scan has a reference (`SCN-…`) and can be exported as a signed file from its server's
Scans tab or from a case. The file holds the scan record, the declarations that were read, the
provenance verdict and the findings, signed with the installation's Ed25519 key.

```bash
python3 -m raqeeb.evidence key                                   # this installation's key id
python3 -m raqeeb.evidence verify SCN-20261116-0002.evidence.json --key <key id>
python3 -m raqeeb.manage verify-audit                            # the audit log's hash chain
```

`verify` needs only this file and the `cryptography` package. A valid signature shows the file
was not changed after signing; that it came from a given installation holds only when the key
id matches the one that installation publishes. The audit chain shows that an entry was edited
or removed. It does not stop someone with database access from rebuilding the chain.

To run the API on its own: copy `.env.example` to `.env`, then `uvicorn raqeeb.main:app`.

With `APP_ENV=production` the application refuses unsafe settings at startup
(`raqeeb/deployment_config.py`). Use PostgreSQL (`requirements-production.txt`) and run
`python3 -m raqeeb.prepare_production_schema` once on a new, empty database.

## Console

The dashboard at `/` is live: it refreshes itself from the database and shows servers by
risk, open findings and cases, the latest changes and activity, and a written briefing
composed offline from stored rows. Four roles scope what a member can do:

| Role | Can |
|---|---|
| Owner | Everything, including managing admins |
| Admin | Manage members and case rules; work findings and cases |
| Analyst | Add servers, run scans, work findings and cases |
| Viewer | Read only |

Each server can be rescanned on its own schedule (Settings, Monitoring, or the server page).
Scheduled scans run as `raqeeb` when `SCHEDULER_ENABLED=true` is set in `.env`. A scan raises an
alert when tools are added or redefined, when the server deviates from its published release,
when exposure rises, or when a server that answered stops answering; alerts appear in the top bar
and are posted to `ALERT_WEBHOOK_URL` when set. Every case and server has a downloadable
investigation report (summary, method, differences, findings, timeline, scans and evidence
integrity) that prints to PDF from the browser.

The served demo (`python3 -m lab.tampering --serve`) adds a team, more servers copied from
published releases, and two changes that happen while it runs, so alerts arrive live.

Scanning is limited to an authorized scope: loopback is always allowed, standing ranges
come from `AUTHORIZED_CIDRS` in the server environment, and temporary grants are issued
through `/api/authorize`. Raqeeb refuses any target outside this scope.

## Safety and scope

- Detectors read declarations only. No tool on a third-party server is ever called.
- Active checks need operator authorization, and DNS TXT ownership proof can be enforced.
- The canary runs only on loopback, against an allow-listed read-only tool.
- The lab server and the demos refuse to start in production.

## Layout

```
raqeeb/        platform: API, protocol negotiation, detectors, drift, storage
observatory/   daily field study of public MCP servers, with its data
reference/     what published MCP server packages declare, release by release
lab/           loopback MCP server and the lifecycle demo
benchmark/     labelled declarations and the offline scorer
evaluation/    scoring against third-party vulnerable servers
dashboard/     React interface
tests/         test suite
```

## References

1. Censys, *MCP Servers on the Internet*, May 2026. <https://censys.com/blog/mcp-servers-on-the-internet/>
2. Microsoft Security Blog, *When configuration becomes a vulnerability*, 14 May 2026. <https://www.microsoft.com/en-us/security/blog/2026/05/14/configuration-becomes-vulnerability-exploitable-misconfigurations-ai-apps/>
3. Wiz, *The risk hiding behind exposed MCP servers*, 28 Jul 2026. <https://www.wiz.io/blog/the-risk-hiding-behind-exposed-mcp-servers>
4. OWASP MCP Top 10. <https://owasp.org/www-project-mcp-top-10/>
5. MITRE ATT&CK <https://attack.mitre.org/> and MITRE ATLAS <https://atlas.mitre.org/>

## License

MIT. See [LICENSE](LICENSE).
