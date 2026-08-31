# Nuclei Dashboard

Nuclei Dashboard is an internal, multi-tenant network discovery and vulnerability-management platform for organizations that are authorized to scan client networks.

It gives an IT, security, MSP, or vulnerability-management team one central place to define client environments, deploy remote LAN scanning Agents, run WAN and LAN discovery/vulnerability scans, track Assets and Findings over time, retain raw scanner evidence, and provide scoped read-only reporting access.

The platform is designed so that an entry-level technician can follow the normal workflow without needing to understand every backend component, while experienced technicians can still see exactly how scanning, authorization, evidence, and version tracking work.

> **Important:** Only scan systems and networks that you are authorized to assess.

To get a working system: [install the central server](#install-the-central-server), then [add a remote Site Agent](#add-a-remote-site-agent) if you need LAN scans.

`MASTER_PLAN.md` is the architecture and product source of truth. Developer migration, TLS, and upgrade notes are in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

---

## Table of contents

- [What Nuclei Dashboard does](#what-nuclei-dashboard-does)
- [Important terminology](#important-terminology)
- [Core capabilities](#core-capabilities)
- [How the system is organized](#how-the-system-is-organized)
- [Scanning workflow](#scanning-workflow)
- [Install the central server](#install-the-central-server)
- [Add a remote Site Agent](#add-a-remote-site-agent)
- [Creating and running scans](#creating-and-running-scans)
- [Scanner and template version control](#scanner-and-template-version-control)
- [Raw scan evidence](#raw-scan-evidence)
- [Roles and access](#roles-and-access)
- [Security model](#security-model)
- [Operations and troubleshooting](#operations-and-troubleshooting)
- [Updating the central server](#updating-the-central-server)
- [Updating a Site Agent](#updating-a-site-agent)
- [Backups](#backups)
- [Local frontend development](#local-frontend-development)

---

# What Nuclei Dashboard does

Nuclei Dashboard manages vulnerability-scanning work across multiple clients, locations, and networks.

A common MSP example looks like this:

```text
MSP / Security Team
        |
        v
Nuclei Dashboard
        |
        +---- Client A (Tenant)
        |       |
        |       +---- Headquarters (Site)
        |       |       |
        |       |       +---- 10.10.0.0/24 (Network)
        |       |       +---- Site Agent
        |       |
        |       +---- Branch Office (Site)
        |               |
        |               +---- 192.168.20.0/24 (Network)
        |               +---- Site Agent
        |
        +---- Client B (Tenant)
                |
                +---- Site / Networks / Agents
```

LAN scans are performed by approved Agents located at the client Site.

WAN scans are performed by the central scanner.

The platform then stores normalized inventory and vulnerability information in PostgreSQL and retains the original compressed scanner output separately as raw evidence.

---

# Important terminology

Understanding these terms makes the rest of the application much easier to use.

| Term | Meaning |
|---|---|
| **Tenant** | A client or customer managed in Nuclei Dashboard. A Tenant is not a self-service customer account. |
| **Site** | A physical or logical client location, such as Headquarters, Branch Office, or Datacenter. |
| **Network** | An authorized LAN network/CIDR that belongs to a Site. |
| **WAN Target** | An authorized public IP, CIDR, or FQDN that may be scanned by the central scanner. |
| **Agent** | A remote Linux Docker worker placed at a Site to perform LAN scans. |
| **Scan Definition** | A reusable configuration describing targets, stages, exclusions, intensity, and schedule. |
| **Scan Run / Scan Job** | One actual execution of a Scan Definition. The execution snapshot preserves what was authorized and configured for that run. |
| **Asset** | A long-lived identity representing a discovered system or device over time. |
| **Finding** | Vulnerability evidence discovered during scanning and associated with Assets. |
| **Raw Evidence** | Original gzip-compressed scanner JSONL retained separately from normalized database records. |

---

# Core capabilities

## Multi-tenant client management

Nuclei Dashboard separates client environments into Tenants.

Within each Tenant you can manage:

- Sites
- LAN Networks
- WAN Targets
- Agents
- Scan Definitions
- Assets
- Findings
- Treatments
- Alerts
- Reports
- Historical Scan Runs

Physical Tenant deletion is intentionally blocked so historical evidence cannot be removed through a cascading Tenant delete.

---

## Site and Network management

Each LAN Network belongs to a Site.

This is important because different clients or Sites may use the same RFC1918 ranges. For example:

```text
Tenant A / Headquarters / 192.168.1.0/24
Tenant B / Branch Office / 192.168.1.0/24
```

These are treated as separate network contexts.

Agents are assigned to Sites and can be explicitly authorized for the Networks they are allowed to scan.

---

## LAN and WAN scanning

The scanner runtime uses ProjectDiscovery tools:

- **Naabu** — host and port discovery
- **httpx** — HTTP/HTTPS fingerprinting
- **Nuclei** — vulnerability detection using Nuclei templates

Typical execution is:

```text
Authorized Target
      |
      v
Naabu discovery
      |
      v
httpx fingerprinting
      |
      v
Nuclei vulnerability scan
      |
      v
Normalized Assets / Findings
      +
Raw scanner evidence
```

A Scan Definition can enable or disable individual stages.

---

## Scan scheduling

Scan Definitions support:

- Manual execution
- Daily schedules
- Weekly schedules
- Monthly schedules
- Advanced cron schedules

The application also records the definition revision and execution snapshot so historical Scan Runs can be understood later even if the Scan Definition changes.

---

## Scan exclusions

Exclusions can remove authorized scope.

They may be configured at different levels, including:

- Global
- Tenant
- Site
- Network
- Scan

Exclusions are designed to reduce scope, not expand it.

---

## Agent dispatch

LAN Networks can use:

- **Any Available** — an eligible healthy Agent may claim the work.
- **Preferred + Failover** — a preferred Agent receives claim priority, with eligible Agents available for failover according to the configured behavior.

Agents still must be authorized for the Site/Network involved.

A healthy Agent keeps sending heartbeats while a scan is running. Health is not based on scan completion. Job polling asks the server only for work that Agent is eligible to claim.

---

## Asset inventory and identity

The platform builds longer-lived Asset records from scan observations instead of treating every discovered IP as a completely unrelated device forever.

Asset information can include:

- Hostnames
- IP addresses
- Services
- Device classification
- Identifiers
- Observations
- Tags
- Correlation information
- Related Findings
- Historical events

---

## Vulnerability Findings

Nuclei findings are normalized and tracked over time.

The application supports:

- Open/resolved technical state
- Finding history
- Reappearance/reopen tracking
- Consecutive clean-scan handling
- Evidence relationships
- Priority information
- Treatment information
- Related compliance/control references

---

## Vulnerability intelligence

The central API can enrich CVE-related information using:

- NVD
- FIRST EPSS
- CISA Known Exploited Vulnerabilities (KEV)

An optional NVD API key may be configured with `NVD_API_KEY`.

Do not commit a real API key to Git.

Nuclei Dashboard operational priority (for example P1-P4) is the application's own prioritization and should not be presented as an NVD, FIRST, or CISA rating.

---

## Alerts and audit history

The platform provides operational alerts and auditing for security-relevant and administrative activity.

SMTP can be configured in **Admin → Settings** for email delivery where supported by the alert policy.

Audited operations include important administrative and Agent lifecycle actions.

---

## Reports and Viewer access

Reports can expose historical operational and security information without giving the recipient administrative access.

Viewer access is explicitly Tenant-scoped.

A Viewer can be granted:

- specific Tenants; or
- all-Tenant read access when intentionally configured.

Viewer access is still read-only and is not equivalent to Admin access.

---

## Raw scanner evidence

Normalized records are stored in PostgreSQL.

Raw Naabu, httpx, and Nuclei evidence is stored separately in the central `scan-artifacts` Docker volume.

The default raw-evidence retention period is 365 days and can be changed in:

**Admin → Settings**

Historical normalized information can remain after raw evidence expires.

---

## Runtime and version provenance

Nuclei Dashboard records scanner/runtime version information so an operator can tell which versions are currently installed on an Agent and which versions were used for a historical Scan Run.

Tracked versions include:

- Nuclei Dashboard scanner runtime
- Nuclei
- Nuclei templates
- Naabu
- ProjectDiscovery httpx

A successful real scan is not allowed to silently complete without the required version provenance for the tools actually used.

---

# How the system is organized

The central installation is a Docker Compose stack.

```text
Browser / Technician
        |
        | HTTPS :8118
        v
      Caddy
       /  \
      /    \
     v      v
 React     FastAPI
  UI         API
              |
              v
         PostgreSQL
              |
              +---- metadata / configuration
              +---- Assets / Findings / history
              +---- audit records
              +---- raw-artifact metadata

Central WAN Scanner
        |
        +---- Naabu
        +---- httpx
        +---- Nuclei

Remote Site Agent
        |
        | outbound HTTPS only
        v
Central API
```

### Main containers

| Service | Purpose |
|---|---|
| `postgres` | PostgreSQL database |
| `api` | FastAPI backend |
| `scheduler` | Control-plane APScheduler (exactly one process) |
| `web` | React frontend |
| `scanner` | Central WAN scanner |
| `caddy` | HTTPS entry point / reverse proxy |
| `nuclei-agent` | Not started on the central host. Deploy a remote Agent from the dashboard instead. |

The central API automatically applies the repository's Alembic schema on startup. A normal Docker installation does **not** require a separate manual `alembic upgrade head`.

---

# Scanning workflow

A normal technician workflow is:

1. Create the **Tenant**.
2. Create the client's **Site**.
3. Add the authorized LAN **Networks** to the Site.
4. Create a Site **Agent**.
5. Deploy the Agent on a Linux host at that Site.
6. Approve the Agent after its first enrollment.
7. Authorize the Agent for the Networks it may scan.
8. Add any authorized **WAN Targets** for central scanning.
9. Create a **Scan Definition**.
10. Select discovery, fingerprinting, vulnerability stages, intensity, exclusions, and schedule.
11. Run the scan or allow the scheduler to run it.
12. Review Assets, Findings, Alerts, raw evidence, and reports.

---

# Install the central server

Do this first. Do not start a remote Agent until the dashboard opens over HTTPS and `/api/health` returns `{"ok":true}`.

When this section is done you will have:

- the dashboard in a browser at `https://YOUR_SERVER:8118`
- an administrator login
- PostgreSQL, the API, the web UI, Caddy, and the central WAN scanner running
- one Tenant, one Site, and one LAN Network ready for an Agent later

A Site Agent is **not** required to start the server. WAN scans use the central scanner. LAN scans need [Add a remote Site Agent](#add-a-remote-site-agent) after this section.

---

## What you need

Use a Linux host with Docker for a real install (Ubuntu 22.04/24.04 is a good default). Docker Desktop or Colima on a Mac is fine for a first lab.

You need:

- a computer you can SSH to (or sit at)
- Git
- Docker Engine and Docker Compose v2 (`docker compose`, not the old `docker-compose`)
- OpenSSL (to create secrets and, for a first lab, a certificate)
- **TCP port 8118** free on this host
- inbound TCP 8118 from the browsers that will use the dashboard
- inbound TCP 8118 from any Site Agent you add later
- outbound Internet during the first image build (Nuclei, Naabu, httpx, and templates are downloaded once and pinned)
- disk for PostgreSQL and retained raw scan evidence

You also need the address others will use to reach this host: a DNS name **or** the host’s IP. Do not use `localhost` or `127.0.0.1` if Agents or other machines will connect.

Only scan networks you are authorized to assess.

---

## 1. Install Docker, Git, and OpenSSL (if they are missing)

On Ubuntu or Debian:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git openssl
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
```

Log out and log back in (or reboot) so the `docker` group applies. Then check:

```bash
git --version
openssl version
docker --version
docker compose version
```

You should see `Docker Compose version v2` or newer.

If `docker` says permission denied, either log out and back in again or prefix commands with `sudo`.

---

## 2. Clone the repository

```bash
cd ~
git clone https://github.com/JustinTDCT/nuclei-dashboard.git
cd nuclei-dashboard
```

Later commands in this section assume you are in that directory.

---

## 3. Find the address the dashboard will use

On the server:

```bash
hostname -I
```

Pick the IP that other machines can actually reach. If you have a DNS name that points at this host, use the name instead.

Examples used below:

```text
YOUR_SERVER=10.20.30.40
```

or:

```text
YOUR_SERVER=nuclei.example.com
```

Replace those with your values everywhere they appear.

---

## 4. Create `.env`

```bash
cp .env.example .env
```

The example file may contain a lab IP such as `10.150.10.155`. That is **not** a default you should keep. Replace it with `YOUR_SERVER`.

Generate four different secrets:

```bash
openssl rand -hex 32
openssl rand -hex 32
openssl rand -hex 32
```

Use a different output for each of `POSTGRES_PASSWORD`, `SECRET_KEY`, and `SCANNER_TOKEN`. The API will not start if those are empty, the word `changeme`, or copied from each other.

Open the file:

```bash
nano .env
```

Set at least:

```dotenv
POSTGRES_USER=nuclei
POSTGRES_PASSWORD=paste-the-first-openssl-value
POSTGRES_DB=nuclei

SECRET_KEY=paste-the-second-openssl-value
SCANNER_TOKEN=paste-the-third-openssl-value

ADMIN_USERNAME=admin
ADMIN_PASSWORD=choose-a-strong-admin-password
ADMIN_EMAIL=admin@localhost

PUBLIC_URL=https://YOUR_SERVER:8118
SITE_ADDRESS=https://YOUR_SERVER:8118

AGENT_TLS_VERIFY=1
SCAN_DRY_RUN=0
```

`PUBLIC_URL` and `SITE_ADDRESS` must be the same URL people type in a browser, including `https://` and `:8118`.

Leave `SETTINGS_ENCRYPTION_KEY` empty until you store an SMTP password in **Admin → Settings**. If you add an SMTP password later, generate a Fernet key first:

```bash
python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Put that value in `SETTINGS_ENCRYPTION_KEY` and recreate the API container. Do not reuse `SECRET_KEY` or `SCANNER_TOKEN` for it.

Save the file (`Ctrl+O`, Enter, `Ctrl+X` in nano).

---

## 5. Create a TLS certificate

Caddy will not start without both of these files:

```text
certs/cert.pem
certs/key.pem
```

```bash
mkdir -p certs
```

Choose **one** method.

### Fastest first install: self-signed certificate

This encrypts traffic. Browsers and Agents will not trust it until you import the public certificate. Use this for a lab or a first bring-up.

**IP address:**

```bash
openssl req -x509 \
  -newkey rsa:4096 \
  -sha256 \
  -days 825 \
  -nodes \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -subj "/CN=10.20.30.40" \
  -addext "subjectAltName=IP:10.20.30.40" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"
```

**DNS name:**

```bash
openssl req -x509 \
  -newkey rsa:4096 \
  -sha256 \
  -days 825 \
  -nodes \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -subj "/CN=nuclei.example.com" \
  -addext "subjectAltName=DNS:nuclei.example.com" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"
```

Replace the IP or hostname with `YOUR_SERVER`. The name or IP in `PUBLIC_URL` **must** appear in the certificate SAN.

```bash
chmod 600 certs/key.pem
chmod 644 certs/cert.pem
openssl x509 -in certs/cert.pem -noout -text | grep -A2 "Subject Alternative Name"
```

### Publicly trusted certificate

Copy your issued certificate (and chain, if required) and the matching private key:

```bash
cp /path/to/server-cert.pem certs/cert.pem
cp /path/to/server-key.pem certs/key.pem
chmod 600 certs/key.pem
chmod 644 certs/cert.pem
```

The certificate must be valid for the hostname in `PUBLIC_URL`.

### Internal / private CA

Issue a server certificate for the same hostname or IP as `PUBLIC_URL`. Copy the **server** cert and key into `certs/` as above.

Keep the **CA** certificate for Agents and administrator browsers. Never copy `certs/key.pem` to an Agent.

---

## 6. Open port 8118 if a firewall is on

Ubuntu with `ufw`:

```bash
sudo ufw allow 8118/tcp
sudo ufw status
```

On a cloud VM, also allow TCP 8118 in that provider’s security group.

---

## 7. Start the central stack

Confirm Compose can read your files:

```bash
docker compose config >/dev/null && echo "compose ok"
```

Start everything:

```bash
docker compose up -d --build
```

The first build downloads pinned Naabu, ProjectDiscovery httpx, Nuclei, and Nuclei templates. That often takes **10–20 minutes**. Leave it running.

These six services should start:

```text
postgres
api
scheduler
web
scanner
caddy
```

Do not start the optional `nuclei-agent` profile on this host. That is not how you add a remote Site Agent.

---

## 8. Confirm it is healthy

```bash
docker compose ps
```

Every service above should be running (or healthy). Then check two things separately.

**Reachability** (no certificate verification). Use `-k` whenever you are only asking “is the port open?” A self-signed cert makes a plain `curl https://...` fail with `curl: (60) SSL certificate problem: self-signed certificate`. That is not a down server.

```bash
curl -k https://YOUR_SERVER:8118/api/health
```

**Certificate verification** (required before Agents use this URL). On the server:

```bash
curl --cacert certs/cert.pem https://YOUR_SERVER:8118/api/health
```

Publicly trusted certificates can omit `--cacert` and `-k`. Internal CA:

```bash
curl --cacert /path/to/internal-ca.pem https://YOUR_SERVER:8118/api/health
```

You want:

```json
{"ok":true}
```

The host or IP in the URL must be the same one on the certificate (the SAN you printed in step 5) and the same one in `PUBLIC_URL`. If the cert was issued for `10.150.10.155` and you curl `10.150.125.70`, `--cacert` fails even though `curl -k` succeeds.

If that fails:

```bash
docker compose logs --tail=100 api
docker compose logs --tail=100 caddy
```

Typical problems:

- `.env` still has empty or placeholder secrets
- `certs/cert.pem` or `certs/key.pem` missing
- `PUBLIC_URL` / `SITE_ADDRESS` still set to the example lab IP
- curl used a different IP or DNS name than the certificate SAN
- port 8118 blocked
- first build still running (`docker compose logs -f scanner`)

---

## 9. Sign in

In a browser open exactly the URL from `PUBLIC_URL`, for example:

```text
https://10.20.30.40:8118
```

Sign in with `ADMIN_USERNAME` and `ADMIN_PASSWORD` from `.env`.

If you used a self-signed certificate, the browser will warn until you trust `certs/cert.pem` (the public file only — never `certs/key.pem`). A permanent certificate warning is not the intended production state.

`ADMIN_USERNAME` / `ADMIN_PASSWORD` / `ADMIN_EMAIL` create the first administrator on an empty database. After that user exists you can remove `ADMIN_PASSWORD` from `.env`. Changing those variables later does **not** reset an existing admin password.

---

## 10. Point Agents at this server

In the left sidebar open **Admin → Settings**.

Set:

- **Central host or IP** — `YOUR_SERVER` (the same name or IP as in `PUBLIC_URL`, without `https://`)
- **Central port** — `8118`
- **Agents use HTTPS** — checked

Save.

Do not put `localhost` or `127.0.0.1` here. Remote Agents cannot reach those addresses.

SMTP, retention, scanner limits, and approved scanner versions can wait. You can leave them at the defaults for a first install.

---

## 11. Create the first Tenant, Site, and LAN Network

These are required before a remote Agent can do LAN work. WAN-only use still needs a Tenant.

1. Open **Tenants**.
2. Enter a name such as `Acme Manufacturing` and click **Create tenant**.
3. Click the new Tenant.
4. Open the **sites** tab.
5. Enter a Site name such as `Hartford Headquarters` and click **Create site**.
6. Under **Networks**, enter a name such as `Corporate LAN` and a CIDR such as `10.20.0.0/24`, then click **Add network**.

The CIDR must be a network you are authorized to scan from a future Agent at that Site.

Optional: open the **WAN targets** tab and add a public IP, public CIDR, or FQDN. Private, loopback, link-local, multicast, reserved, cloud-metadata, and ranges larger than 65,536 addresses are rejected.

---

## Central server checklist

```text
[ ] docker compose ps shows postgres, api, scheduler, web, scanner, and caddy running
[ ] curl -k https://YOUR_SERVER:8118/api/health returns {"ok":true}
[ ] curl --cacert certs/cert.pem (or a public CA) also returns {"ok":true} for that same URL
[ ] the dashboard opens in a browser
[ ] you can sign in as the administrator
[ ] Admin → Settings has the reachable central host and port 8118
[ ] a Tenant exists
[ ] that Tenant has a Site
[ ] that Site has an authorized LAN Network
```

The **central server is installed**. Continue only when every box is checked.

---

# Add a remote Site Agent

A Site Agent is a small Docker worker you place **on the customer LAN**. It makes outbound HTTPS to the dashboard on TCP 8118, then runs Naabu / httpx / Nuclei against Networks you authorize.

Start this section only after the [central server](#install-the-central-server) is healthy at the **same URL** the Agent will use.

---

## What the Agent host needs

- Linux with Docker Engine and Docker Compose v2 (same install as step 1 of the server, if needed)
- outbound HTTPS to `https://YOUR_SERVER:8118`
- outbound Internet for the **first** image build
- reachability to the LAN CIDRs this Agent will scan
- disk for the image and two Docker volumes (`agent-keys`, `nuclei-templates`)

The downloaded Compose file uses `network_mode: host` so the Agent can see site RFC1918 addresses. Keep that unless you have a tested alternative.

You do **not** copy the whole Nuclei Dashboard repo onto the Agent host.

---

## 1. Prove the Agent host can reach the dashboard

You have not created `~/nuclei-agent` yet. This step only checks that the Agent machine can talk to the dashboard. Certificate files come later, in step 4.

A self-signed cert makes a plain `curl https://...` fail with `curl: (60)`. Skip verification here:

```bash
curl -k https://YOUR_SERVER:8118/api/health
```

You want `{"ok":true}`. `-k` only proves the host, port, and API respond. It is not how the Agent will connect.

If the certificate is already publicly trusted, you can also run the same URL without `-k`. For a self-signed or internal CA, wait until step 4 — `~/nuclei-agent/agent-certs/ca.pem` does not exist yet.

Use the same hostname or IP that is on the server certificate and in `PUBLIC_URL`. That same value becomes `CENTRAL_URL` in step 3.

---

## 2. Create the Agent in the dashboard

On a computer that can open the dashboard:

1. Open **Tenants** and click the client.
2. Open the **agents** tab (or the **sites** tab — both can create an Agent).
3. Enter an Agent name such as `Agent-HQ-01`.
4. Select the Site you created earlier.
5. Click **Create agent**.

The page shows a UUID and an enrollment secret. Treat the secret like a password.

Immediately download both files:

- **Download docker-compose.yml** — saved as `agent-<UUID>.yml`
- **Download .env** — saved as `agent-<UUID>.env`

The enrollment secret is already inside the `.env` file. You will not need to type it by hand.

---

## 3. Copy the files onto the Agent host

On the Agent host:

```bash
mkdir -p ~/nuclei-agent
```

Copy the two downloaded files into that directory (USB, `scp`, etc.). Example from the machine that downloaded them:

```bash
scp agent-********-****-****-****-************.yml \
    agent-********-****-****-****-************.env \
    user@AGENT_HOST:~/nuclei-agent/
```

On the Agent host, rename them so everyday commands stay short:

```bash
cd ~/nuclei-agent
mv agent-*.yml docker-compose.yml
mv agent-*.env agent.env
chmod 600 agent.env
```

If you prefer to keep the UUID filenames, use `-f agent-<UUID>.yml --env-file agent-<UUID>.env` on every `docker compose` command instead.

Open `agent.env` and confirm:

```dotenv
CENTRAL_URL=https://YOUR_SERVER:8118
TLS_VERIFY=1
```

`CENTRAL_URL` must be the same URL that passed `curl -k` in step 1 (same scheme, host or IP, and port as `PUBLIC_URL` and the certificate SAN). You verify the cert in the next step.

---

## 4. Trust the server certificate (if it is not public)

### Publicly trusted certificate

Nothing else to copy. Skip to step 5.

### Self-signed certificate

On the **central server**, the public certificate is `certs/cert.pem`. Copy **only that file** to the Agent host. Do not copy `certs/key.pem`.

```bash
cd ~/nuclei-agent
mkdir -p agent-certs
# after you have copied cert.pem onto this host:
cp /path/to/copied-central-cert.pem agent-certs/ca.pem
```

Edit `agent.env` and set:

```dotenv
TLS_VERIFY=1
TLS_CA_FILE=/certs/ca.pem
```

`/certs/ca.pem` is the path **inside** the container. The Compose file mounts `./agent-certs` there.

Now that the file exists, verify TLS with the **same** host or IP that passed `curl -k` in step 1:

```bash
cd ~/nuclei-agent
curl --cacert ./agent-certs/ca.pem https://YOUR_SERVER:8118/api/health
```

You want `{"ok":true}`. A bare `curl https://...` (no `-k`, no `--cacert`) still fails on a self-signed cert (`curl: (60)`). That is expected. If `-k` worked and `--cacert` does not, the URL does not match the certificate name/IP, or `ca.pem` is not the server’s public cert (or its issuing CA). Regenerate the server certificate for the address Agents actually use, or change `CENTRAL_URL` / `PUBLIC_URL` to that address — do not invent a second IP.

### Internal CA

Put the **CA** certificate (the issuer, not the server private key) at `~/nuclei-agent/agent-certs/ca.pem` and set the same `TLS_CA_FILE` line.

### Lab-only bypass

`TLS_VERIFY=0` turns verification off. Use it only for temporary lab debugging, not as a normal setting.

---

## 5. Start the Agent

```bash
cd ~/nuclei-agent
docker compose --env-file agent.env up -d --build
```

Always pass `--env-file agent.env` (or the downloaded `agent-<UUID>.env`) on rebuild and recreate. Without it the container can come up healthy but fail TLS verification because `TLS_CA_FILE` is empty.

The first build pulls the pinned `scan_runtime` commit from GitHub and installs the same scanner tools as the central scanner. That can take a while.

```bash
docker compose ps
docker compose logs -f nuclei-agent
```

You should see the Agent connect and enroll, then wait for approval. `Ctrl+C` stops following logs; the container keeps running.

If the container name is not `nuclei-agent`, `docker compose ps` will show the actual name.

---

## 6. Approve the Agent

Back in the dashboard, **Tenants → (client) → agents**:

1. Find the Agent. Status should be pending approval after a successful enroll.
2. Confirm the UUID matches the files you deployed.
3. Click **Approve**.

After approval, the enrollment secret is no longer used for normal authentication. The Agent keeps a private key in the `agent-keys` Docker volume.

---

## 7. Authorize it for LAN Networks

Approval does not grant scan rights.

1. Open **Tenants → (client) → sites**.
2. Select the Site.
3. On the Network card, check the Agent under **Authorized agents**.
4. Leave **Dispatch** on **Any Available** unless you have a preferred Agent.
5. Click **Save network**.

The Agent must belong to the same Site as the Network.

---

## 8. Confirm it is online

In **agents**, the row should show **online** and a recent last-seen time. A long scan must not flip it to Offline; heartbeats run on a separate loop.

Optional, on the Agent host:

```bash
docker compose exec nuclei-agent nuclei -version
docker compose exec nuclei-agent naabu -version
docker compose exec nuclei-agent pd-httpx -version
```

---

## 9. Run a small first LAN scan

1. **Tenants → (client) → scans**.
2. Create a LAN Scan Definition that targets the Network you authorized.
3. For the first run, keep the target small and intensity conservative.
4. Start the run.

Confirm the job is claimed by **this** Agent, Assets appear, and (if you enabled vulnerability scanning) Findings or clean coverage appear. Raw evidence is stored on the **central** server, not on the Agent.

---

## Protect the Agent identity

Do **not** run:

```bash
docker compose down -v
```

`-v` deletes volumes, including `agent-keys`. If that key is lost, create a **new** Agent in the dashboard and deploy new files. Do not reuse the old UUID.

---

## Remote Agent checklist

```text
[ ] curl -k from the Agent host returns {"ok":true}
[ ] curl --cacert ./agent-certs/ca.pem (or a public CA) also succeeds for that same URL
[ ] Agent created on the correct Tenant and Site
[ ] docker-compose.yml and agent.env are on the Agent host
[ ] certificate trust matches the server (public, CA file, or self-signed)
[ ] docker compose ps shows the Agent running
[ ] Agent approved in the dashboard
[ ] Agent checked on the Network and Save network clicked
[ ] Agent shows online
[ ] a small authorized LAN scan completes
```

---

# Creating and running scans

A Scan Definition is created through the dashboard wizard.

## Target scope

Choose:

- **LAN** — uses Site Networks and a remote Agent.
- **WAN** — uses authorized WAN Targets and the central scanner.

---

## Scan stages

### Discovery

Discovers reachable systems.

When port discovery is set to `none`, or when port scan targets are limited to detected hosts, discovery uses a short TCP probe. Naabu `-sn` is not used because it requires root and the Agent does not run as root.

### Port discovery

Available modes include:

- None
- Common
- Deep
- Custom

### Fingerprinting

Uses ProjectDiscovery httpx to collect HTTP/HTTPS information such as:

- title
- technology hints
- web server information
- TLS information where available

### Vulnerability

Uses Nuclei.

You can configure:

- severities
- tags

---

## Scan intensity

The UI provides intensity presets and advanced/custom limits for scanner behavior such as:

- rates
- concurrency
- timeouts
- retries

Use conservative settings when you do not understand the capacity or sensitivity of the target environment.

---

## Schedule

Available schedule types include:

- Manual
- Daily
- Weekly
- Monthly
- Advanced cron

---

## Dry-run mode

For lab/testing purposes, the scanner runtime supports:

```dotenv
SCAN_DRY_RUN=1
```

Dry-run mode emits sample results without performing a normal scanner execution against the target network.

Dry runs do not fabricate genuine raw scanner evidence or pretend that tools were executed when they were not.

The normal central `.env.example` uses:

```dotenv
SCAN_DRY_RUN=0
```

---

# Scanner and template version control

Scanner versions are intentionally tracked.

The build uses pins from:

```text
scan_runtime/pinned_versions.json
```

Current tracked fields are:

```text
runtime_version
nuclei_version
nuclei_templates_version
naabu_version
httpx_version
```

The backend has a corresponding approved-version baseline.

---

## Installed version vs approved version

These are two different concepts.

**Installed version** means what an Agent reports it currently has.

**Approved version** means what the central system currently considers the expected version.

Changing an approved version in:

**Admin → Settings → Approved scanner versions**

does **not**:

- remotely upgrade an Agent;
- rebuild a remote container;
- replace an Agent image;
- automatically modify a Site host.

It changes the central comparison state.

Possible status includes:

- Matches approved
- Mismatch
- Not reported
- No approved version configured

---

## Verify scanner versions inside an Agent

Open a shell in the Agent container, or run commands using Docker Compose.

Examples:

```bash
docker compose exec nuclei-agent nuclei -version
docker compose exec nuclei-agent nuclei -tv -disable-update-check
docker compose exec nuclei-agent naabu -version
docker compose exec nuclei-agent pd-httpx -version
```

The Nuclei scan command disables normal template update behavior during ordinary scanning.

---

## Historical Scan Run versions

A Scan Run's recorded version provenance belongs to that historical run.

If an Agent is upgraded later, that should not rewrite the versions recorded for old Scan Runs.

---

# Raw scan evidence

Raw scanner output is retained separately from PostgreSQL.

The central Compose stack uses:

```text
scan-artifacts
```

for raw evidence.

Typical raw evidence includes gzip-compressed JSONL generated from scanner stages.

PostgreSQL stores metadata such as:

- Scan Job relationship
- Tenant
- tool
- stage
- size
- SHA-256
- retention date
- provenance
- availability/deletion state

The raw bytes themselves are stored on the Docker volume.

---

## Retention

Default retention is:

```text
365 days
```

Configure it in:

**Admin → Settings → Raw scan artifact retention**

Changing retention affects newly stored raw evidence according to the current application behavior.

Normalized Assets, Findings, Scan history, and other historical records are separate from the raw-file retention lifecycle.

---

# Roles and access

| Role | Access |
|---|---|
| **Admin** | System settings, user management, administrative functions, and normal operational access |
| **User** | Operational management such as Tenants, Sites, Networks, Agents, scans, Assets/Findings workflows, and alerts as allowed by the application |
| **Viewer** | Read-only access to explicitly granted Tenant information and reports; no administrative control |

Viewer grants may also have expiration.

A Viewer cannot use Viewer access as a substitute for Admin privileges.

---

# Security model

Nuclei Dashboard includes several controls intended to prevent a scanner worker or user interface action from becoming unrestricted scanning authority.

## Agent communication

Site Agents make outbound connections to the central dashboard.

A normal remote deployment does not require the central server to initiate an inbound management connection to the Agent.

---

## Agent identity

The initial enrollment secret is used during enrollment.

After approval, Agent authentication is tied to its generated key material and UUID.

The private key persists in the Agent's `agent-keys` Docker volume.

---

## Tenant/Site/Network boundaries

Agent identity is not accepted as authority for arbitrary Tenant or Site scope.

The central server determines whether an Agent is eligible and authorized for the requested work.

---

## Immutable Scan Run context

A queued/executing Scan Run uses a stored execution snapshot.

This protects historical interpretation of:

- target scope
- stages
- intensity
- exclusions
- dispatch information
- schedule information

Editing the Scan Definition later does not turn an old Scan Run into a different historical event.

---

## Version provenance

Real successful runs require the appropriate tool/runtime version evidence for the stages that were actually used.

The system should fail closed rather than silently mark the run successful without required provenance.

---

## TLS

Remote Agent TLS verification is on by default.

Use a trusted public certificate or configure the correct internal CA.

---

## Secrets

The application will not start with empty, known-placeholder, or reused `SECRET_KEY` / `SCANNER_TOKEN` / database password values. `ADMIN_PASSWORD` is required only for initial bootstrap. Compose has no insecure fallbacks for the required variables.

The public HTTPS listener does not expose `/api/internal/scanner`. The central scanner reaches that API on the Docker network only.

`GET /api/admin/settings` returns a masked SMTP password. Leave the field blank to keep the stored value. The password is still stored plaintext in `Setting.value` JSON.

Staff tokens are invalidated when that user's password is reset.

Do not commit:

- `.env`
- real passwords
- enrollment secrets
- scanner tokens
- NVD API keys
- TLS private keys

---

## Compliance note

Control mappings and collected evidence can support compliance work, but a mapping does not automatically mean a control is implemented, assessed, satisfied, or certified.

---

# Operations and troubleshooting

## Central stack status

```bash
docker compose ps
```

---

## Central API logs

```bash
docker compose logs --tail=200 api
```

---

## Scheduler logs

```bash
docker compose logs --tail=200 scheduler
```

---

## Caddy/TLS logs

```bash
docker compose logs --tail=200 caddy
```

If Caddy repeatedly fails to start, first confirm:

```text
certs/cert.pem
certs/key.pem
```

both exist and form a valid matching certificate/key pair.

---

## Central scanner logs

```bash
docker compose logs --tail=200 scanner
```

---

## Agent logs

On a remote Site host:

```bash
docker compose logs --tail=200 nuclei-agent
```

or:

```bash
docker compose logs -f nuclei-agent
```

---

## Agent cannot reach central server

Check:

1. The Agent's `CENTRAL_URL`.
2. DNS resolution.
3. Routing/firewall access to TCP 8118.
4. TLS certificate name.
5. Internal CA configuration if applicable.
6. Whether TLS verification errors appear in Agent logs.

Reachability (no cert verification):

```bash
curl -k https://YOUR_SERVER:8118/api/health
```

A bare `curl https://...` without `-k` or `--cacert` fails with `curl: (60) SSL certificate problem: self-signed certificate`. That is expected on a self-signed install.

Then verify with the same host or IP as the certificate SAN:

```bash
curl --cacert ./agent-certs/ca.pem \
  https://YOUR_SERVER:8118/api/health
```

If `-k` works and `--cacert` does not, the Agent URL does not match the cert, or the CA file is wrong.

---

## Agent remains pending

Check:

1. Agent container logs.
2. The UUID matches the Agent created in the dashboard.
3. The enrollment secret is the one generated for that Agent.
4. The central URL is correct.
5. The Agent appears in the dashboard.
6. A technician with the required permissions has approved it.

---

## Agent is approved but receives no LAN work

Check:

1. Agent is online/healthy.
2. Agent belongs to the correct Site.
3. Networks belong to that Site.
4. Agent is authorized for those Networks.
5. The Scan Definition targets those Networks.
6. Dispatch configuration allows that Agent to claim the run.
7. Exclusions have not removed all effective scope.

---

## Version shows Not reported

Older Agents may not have sent runtime inventory yet.

Rebuild/redeploy the Agent using the current scanner runtime code when appropriate:

```bash
docker compose --env-file agent.env up -d --build
```

Then check Agent logs and version status again.

---

## Version shows Mismatch

A mismatch does not automatically mean the Agent is broken.

It means at least one installed version does not match the centrally approved version.

Compare the individual fields in the dashboard before changing anything.

There is no automatic remote upgrade action in the current version.

---

# Updating the central server

Before an update:

1. Confirm you have a usable backup.
2. Record the current Git commit/version.
3. Review release/change notes.
4. Do not delete persistent Docker volumes unless a documented recovery procedure explicitly requires it.

Typical update flow:

```bash
cd nuclei-dashboard
git pull
docker compose build api scheduler scanner web
docker compose up -d
```

If Caddy or Compose configuration also changed, recreating the full stack is reasonable:

```bash
docker compose up -d --build
```

The API applies the repository's Alembic migrations during startup.

Do not manually edit old/frozen Alembic migration files on an installed system.

---

# Updating a Site Agent

An Agent rebuild clones the pinned `scan_runtime` commit from GitHub (the `#<40-character-sha>:scan_runtime` value in the downloaded Compose file) and installs the scanner tools for that revision.

A container **restart is not enough** after Agent/runtime changes on the central server. Download a fresh Compose file if the dashboard pin changed, then rebuild the image. Do not use `docker compose down -v`.

From the Agent directory (`~/nuclei-agent` if you followed the install):

```bash
docker compose --env-file agent.env up -d --build
```

If you kept the UUID filenames instead:

```bash
docker compose \
  -f agent-<UUID>.yml \
  --env-file agent-<UUID>.env \
  up -d --build
```

Then verify:

```bash
docker compose ps
docker compose logs --tail=100 nuclei-agent
```

Do not use `docker compose down -v` during a routine update because that can delete the Agent identity volume.

---

# Backups

At minimum, plan for these data categories.

## PostgreSQL

The `postgres-data` volume contains the primary application database.

It includes normalized operational and historical information.

Use a real PostgreSQL backup procedure appropriate for your environment rather than relying only on copying a live volume.

---

## Raw scanner evidence

The `scan-artifacts` volume contains retained raw scanner files.

If raw evidence must survive central-host failure, include this volume in the backup design.

---

## TLS certificate/key

The central server uses host files:

```text
./certs/cert.pem
./certs/key.pem
```

Back them up according to your organization's certificate/private-key procedures.

Protect the private key.

---

## Remote Agent key volume

The Agent's:

```text
agent-keys
```

volume contains its private identity key.

Loss of this volume means the approved Agent identity cannot simply be recreated by typing the same UUID.

---

# Local frontend development

For frontend development:

```bash
cd frontend
npm install
npm run dev
```

The Vite development server proxies `/api` to:

```text
http://127.0.0.1:8000
```

For production deployment, use the Docker Compose stack rather than the Vite development server.

---

# Additional references

- [`MASTER_PLAN.md`](MASTER_PLAN.md) — canonical architecture and implementation plan
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — development, migration, TLS, Viewer, and upgrade details
- [`scan_runtime/pinned_versions.json`](scan_runtime/pinned_versions.json) — pinned scanner/runtime/tool/template versions
- [`agent/docker-compose.yml`](agent/docker-compose.yml) — standard remote Site Agent Compose definition

---

# Quick reference

## Start central server

```bash
docker compose up -d --build
```

## Check central server

```bash
docker compose ps
docker compose logs --tail=100 api caddy scanner
```

## API health

Reachability (no cert verification):

```bash
curl -k https://YOUR_SERVER:8118/api/health
```

Public certificate:

```bash
curl https://YOUR_SERVER:8118/api/health
```

Self-signed or internal CA (verification):

```bash
curl --cacert certs/cert.pem https://YOUR_SERVER:8118/api/health
```

## Start Agent with renamed files

```bash
docker compose --env-file agent.env up -d --build
```

## Start Agent with original downloaded filenames

```bash
docker compose \
  -f agent-<UUID>.yml \
  --env-file agent-<UUID>.env \
  up -d --build
```

## Agent logs

```bash
docker compose logs -f nuclei-agent
```

## Verify Agent scanner versions

```bash
docker compose exec nuclei-agent nuclei -version
docker compose exec nuclei-agent nuclei -tv -disable-update-check
docker compose exec nuclei-agent naabu -version
docker compose exec nuclei-agent pd-httpx -version
```
