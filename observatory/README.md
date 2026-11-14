# Observatory

A fixed sample of public MCP servers, re-read on a schedule, to measure how often
the tools a server declares change after it has been published.

## What a run does

For each sampled endpoint: one handshake (`initialize`, or `server/discover` on
stateless servers) and `tools/list`. No credentials are sent and no tool is ever
called. An endpoint that asks for authentication is recorded as such and left alone.

## Where the endpoints come from

The official MCP Registry. An endpoint is eligible when its listing is the active,
latest version and declares a `streamable-http` remote over HTTPS that needs no
template values and no required headers. The sample is drawn once with a fixed
seed, one endpoint per hostname, and stored in `data/sample.json`.

## Data layout

    data/sample.json            the endpoints under observation
    data/runs/<time>-<vantage>.json   one record per endpoint per run
    data/manifests/<sha256>.json      tool declarations, stored once per distinct content

A run refers to manifests by digest, so a server that did not change adds no file
and a change shows up as a new digest in the next run.

## Usage

    python3 -m observatory sample
    python3 -m observatory snapshot --vantage kali
    python3 -m observatory status

## Opting out

Operators can open an issue on this repository; their hostname is added to
`data/excluded_hosts.txt` and is skipped from then on.
