# Deploying Raqeeb

Raqeeb is a long-running service: the API, the console and the scheduler run in one process
next to PostgreSQL. Shared web hosting cannot keep it running, so deploy it on a VPS. The files
here run three containers: `db` (PostgreSQL 16), `app` (Raqeeb) and `web` (Caddy, which obtains
and renews the HTTPS certificate). Only ports 80 and 443 are published; the database and the app
are reachable only inside the compose network.

## 1. Server and domain

1. A VPS with Ubuntu 24.04 and Docker (on Hostinger: the Docker VPS template). 2 GB RAM is enough.
2. In your DNS, point an `A` record for the domain (for example `raqeeb.example.com`) at the VPS IP.
3. Open the firewall for SSH, HTTP and HTTPS only:

```bash
ufw allow OpenSSH && ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 8443/tcp && ufw --force enable
```

## 2. Code and settings

```bash
git clone https://github.com/RootSec01/CyberOSINT.git /opt/raqeeb
cd /opt/raqeeb/deploy
cp env.example .env
chmod 600 .env
```

Fill in `.env`. Generate each secret separately:

```bash
openssl rand -hex 24   # POSTGRES_PASSWORD
openssl rand -hex 32   # JWT_SECRET
openssl rand -hex 32   # OWNERSHIP_SECRET
```

Also set `DOMAIN`, `ACME_EMAIL`, `OPERATOR_NAME`, `OPERATOR_CONTACT` and `TIMEZONE`.
Raqeeb refuses to start in production with a weak secret, without HTTPS enforcement or
without rate limiting.

## 3. Start

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f app
```

The app creates any missing tables on start (it never alters an existing one) and then serves
the console. Caddy obtains the certificate on the first request to `https://DOMAIN`.

## 4. First administrator

```bash
docker compose exec app python -m raqeeb.manage create-user --username rami --role admin
```

The command asks for the password twice. Platform administrators can take the console offline
(Settings, Platform) and issue temporary scan grants. Everyone else is added by an administrator
or team owner in Settings, Members, and signs in directly with the password set there.

## 5. Public showcase

The `showcase` container serves the tampering demonstration on `https://SHOWCASE_DOMAIN`, or on
`https://DOMAIN:8443` when no separate name is set (`ROOT_DOMAIN`, if set, redirects there): the
as-shipped and altered copies of server-filesystem, the lab estate and the scheduled changes that
raise alerts. It sits on a network with no route out, so the only servers it can reach are the lab
listeners inside it. One server alternates between its release and a planted change every
`SHOWCASE_CYCLE_MINUTES`, so the console keeps raising alerts, and every `SHOWCASE_RESET_MINUTES`
the process exits and the container starts it again from an empty database. Caddy shows a short
"starting over" page during that minute.

Visitors enter without an account, through a read-only viewer: they can open every page and
download reports, but cannot add, scan, change, submit or delete anything, and there is no sign-in
form at all: `/api/login` answers 404 once the demo data is staged. Each visit is written to the
showcase's activity log with its address. Set two separate secrets (`openssl rand -hex 32`); the
container refuses to start otherwise.

```bash
docker compose up -d --build showcase web
docker compose logs --tail 20 showcase
```

## 6. Updates

```bash
cd /opt/raqeeb && git pull && cd deploy && docker compose up -d --build
```

## 7. Backups

```bash
docker compose exec -T db pg_dump -U raqeeb raqeeb | gzip > raqeeb-$(date +%F).sql.gz
docker run --rm -v raqeeb_evidence:/e -v "$PWD":/b alpine tar czf /b/evidence-$(date +%F).tgz -C /e .
```

The evidence volume holds the signing key; losing it means old evidence files can no longer be
checked against this installation.

## What faces the internet

- Routes from the earlier OSINT console (`/api/scan`, `/api/runs`, `/api/ownership`, ...) answer
  404 unless `LEGACY_API=true`. Only MCP servers can be added.
- API documentation (`/docs`, `/openapi.json`) is off in production.
- Loopback and private addresses are never scanned in production. Registry servers must resolve
  to public addresses; your own servers must be inside `AUTHORIZED_CIDRS` or a temporary grant.
- Every sign-in, refused sign-in and rate-limited attempt is recorded with its address and browser.
  Administrators see them in Activity.
- Every response carries a content security policy, `X-Frame-Options: DENY`, `nosniff`, a strict
  referrer policy and HSTS. Sign-ins, failed sign-ins and every change are written to the sealed
  audit log.
- Outbound scans leave from the VPS address and identify themselves as
  `Raqeeb/2.0 (+https://DOMAIN/about)`. The `/about`, `/terms` and `/privacy` pages and
  `/.well-known/security.txt` tell server operators who is reading and how to opt out.
