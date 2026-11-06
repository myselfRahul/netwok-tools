# Sentinel — Authorized Vulnerability Assessment Platform

A small, self-hosted TCP exposure assessment application designed for a trusted home lab or internal network. It is not a replacement for a full vulnerability scanner such as InsightVM or authenticated configuration assessment.

## Requirements

- Node.js **22.13 or newer** (uses the built-in `node:sqlite` module)
- npm
- A Linux environment (Ubuntu recommended)
- Network authorization for every target

## Install on Ubuntu / Termux proot-distro

```bash
# Check your environment
node --version
npm --version

# Node must be >= 22.13. If not, install a supported Node release first.
mkdir -p ~/apps/sentinel
cd ~/apps/sentinel
# Extract the supplied ZIP here, then:
npm install --omit=dev
cp .env.example .env
nano .env
```

Set a unique admin password of at least 16 characters and configure `AUTHORIZED_CIDRS` with only networks you own or are explicitly authorized to assess. Do not use `0.0.0.0/0`, public ranges, or networks belonging to others.

```bash
npm test
npm run check
npm start
```

The `start` script loads `.env` using Node.js `--env-file`; do not start with `node server.js` unless you have exported all required variables in the shell.

Open `http://127.0.0.1:3000` on the same device. The default bind address is loopback-only.

## Termux notes

```bash
pkg update
pkg install nodejs-lts git unzip
node --version
```

If the Termux Node package is older than 22.13, use a supported Node.js distribution compatible with your device. Node's SQLite module is built into Node and does not require a native SQLite npm addon.

For proot-distro Ubuntu, install Node.js >=22.13 inside the Ubuntu environment; do not assume the host Termux Node binary is available inside proot.

## Configuration

See `.env.example`. Important variables:

- `HOST`: defaults to `127.0.0.1`; keep loopback unless protected by a TLS reverse proxy.
- `ADMIN_USER`, `ADMIN_PASSWORD`: initial administrator credentials. The initial user is created on first startup.
- `AUTHORIZED_CIDRS`: comma-separated IPv4 addresses/CIDRs. Every expanded target must be inside these ranges.
- `MAX_TARGETS`: maximum targets per job.
- `MAX_CONCURRENCY`: maximum worker count.
- `MAX_PORTS`: maximum ports per job.

Changing `ADMIN_PASSWORD` after the initial user has been created does not rotate the stored password. Password rotation should be performed through a future admin-management feature or by resetting the local database after backing it up.

## Security model and limitations

- Explicit IPv4/CIDR allowlist; no hostnames, URLs, IPv6 or public Internet discovery.
- Session cookie is HttpOnly and SameSite=Strict; production mode adds Secure.
- WebSocket upgrade requires a valid session and same-origin browser request.
- State-changing HTTP actions require CSRF token.
- Browser output uses DOM text nodes, not untrusted HTML interpolation.
- Port findings are exposure indicators with remediation guidance, not confirmed vulnerabilities.
- The banner reader is passive. It does not send exploit payloads.
- Use HTTPS via a reverse proxy before exposing the dashboard beyond localhost. Set `NODE_ENV=production` when serving through HTTPS.
- In this starter implementation sessions are in-memory and are invalidated on restart. Jobs/results persist in SQLite; in-memory execution state does not survive restart.
- For multi-user or Internet-facing deployments, add durable session storage, account lifecycle management, backup/restore, MFA, centralized secrets, stronger audit retention, and a hardened reverse proxy.

## Tests

```bash
npm test
npm run check
```

## Backup

Stop the service, then copy `data/assessment.sqlite` to a protected backup location. The database contains usernames, job metadata and scan results. Protect it as security-sensitive data.
