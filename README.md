# Nuclei Dashboard

Nuclei Dashboard is an internal, multi-tenant network discovery and vulnerability-management platform for organizations that are authorized to scan client networks.

It gives an IT, security, MSP, or vulnerability-management team one central place to define client environments, deploy remote LAN scanning Agents, run WAN and LAN discovery/vulnerability scans, track Assets and Findings over time, retain raw scanner evidence, and provide scoped read-only reporting access.

The platform is designed so that an entry-level technician can follow the normal workflow without needing to understand every backend component, while experienced technicians can still see exactly how scanning, authorization, evidence, and version tracking work.

> **Important:** Only scan systems and networks that you are authorized to assess.

`MASTER_PLAN.md` is the canonical architecture and product source of truth. Development, migration, TLS, and upgrade notes are in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

---

## Table of contents

- [What Nuclei Dashboard does](#what-nuclei-dashboard-does)
- [Important terminology](#important-terminology)
- [Core capabilities](#core-capabilities)
- [How the system is organized](#how-the-system-is-organized)
- [Scanning workflow](#scanning-workflow)
- [Installation overview](#installation-overview)
- [Part 1 — Central Server Installation](#part-1--central-server-installation)
- [Part 2 — Site Agent Installation](#part-2--site-agent-installation)
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
| `web` | React frontend |
| `scanner` | Central WAN scanner |
| `caddy` | HTTPS entry point / reverse proxy |
| `nuclei-agent` | Optional LAN Agent profile; normally deployed separately at client Sites |

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

# Installation overview

Installation is intentionally split into two independent stages.

```text
PART 1
Central Server
    |
    |  Get this fully working first
    v
Dashboard reachable over HTTPS
Admin can sign in
API health returns OK
Central WAN scanner is running
    |
    v
PART 2
Site Agent
    |
    |  Deploy after the central server works
    v
Agent enrolls
Agent is approved
Agent is authorized for LAN Networks
Agent becomes available for LAN scans
```

Do **not** begin Agent troubleshooting until the central server is healthy and reachable at the exact URL the Agent will use.

---

# Part 1 — Central Server Installation

This section gets the **core Nuclei Dashboard server** running.

When Part 1 is complete, you should have:

- PostgreSQL running;
- the FastAPI backend running;
- the React frontend running;
- Caddy serving the dashboard over HTTPS;
- the central WAN scanner running;
- the database schema automatically migrated;
- a working administrator login;
- `/api/health` returning `{"ok":true}`.

The central server does **not** require a Site Agent in order to start.

---

## 1.1 Central server requirements

A Linux Docker host is recommended.

The central server needs:

- Docker Engine
- Docker Compose v2 (`docker compose`)
- Git
- OpenSSL for certificate generation/inspection
- TCP port **8118** available
- inbound TCP 8118 from administrators who use the dashboard
- inbound TCP 8118 from Site Agents
- outbound Internet access during scanner image builds
- enough storage for PostgreSQL
- enough storage for retained raw scan evidence
- a TLS certificate and matching private key

Supported scanner build architectures:

- `amd64` / `x86_64`
- `arm64` / `aarch64`

The TLS certificate may be:

- publicly trusted;
- issued by your organization's internal CA; or
- self-signed.

---

## 1.2 Clone the repository

```bash
git clone https://github.com/JustinTDCT/nuclei-dashboard.git
cd nuclei-dashboard
```

---

## 1.3 Create the central environment file

Copy the example:

```bash
cp .env.example .env
```

Edit it:

```bash
nano .env
```

or:

```bash
vi .env
```

At minimum, review and change:

```dotenv
POSTGRES_PASSWORD=use-a-strong-database-password

SECRET_KEY=use-a-long-random-secret
SCANNER_TOKEN=use-a-different-long-random-secret

ADMIN_USERNAME=admin
ADMIN_PASSWORD=use-a-strong-admin-password
ADMIN_EMAIL=admin@example.com

PUBLIC_URL=https://dashboard.example.com:8118
SITE_ADDRESS=https://dashboard.example.com:8118
```

### Important: replace the example IP

The current `.env.example` contains the environment-specific address:

```text
10.150.10.155
```

Do **not** leave that value in a new installation unless that is actually your server's address.

Use the hostname or IP technicians and Agents will really use.

Examples:

```dotenv
PUBLIC_URL=https://nuclei.example.com:8118
SITE_ADDRESS=https://nuclei.example.com:8118
```

or:

```dotenv
PUBLIC_URL=https://10.20.30.40:8118
SITE_ADDRESS=https://10.20.30.40:8118
```

### Generate strong random values

Example:

```bash
openssl rand -hex 32
```

Run it separately for:

- `SECRET_KEY`
- `SCANNER_TOKEN`

Use separate strong passwords for:

- `POSTGRES_PASSWORD`
- `ADMIN_PASSWORD`

Do not reuse one secret everywhere.

> `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `ADMIN_EMAIL` seed the first administrator on an empty database. Changing those environment values later is not the normal procedure for resetting an existing administrator password.

---

## 1.4 Choose the central server certificate method

Caddy requires these exact files:

```text
./certs/cert.pem
./certs/key.pem
```

Create the directory first:

```bash
mkdir -p certs
```

Choose **one** of the following certificate methods.

---

## 1.4A Publicly trusted certificate

Use this option if you already have a certificate from a public CA.

Copy the certificate/chain:

```bash
cp /path/to/server-cert.pem certs/cert.pem
```

Copy the matching private key:

```bash
cp /path/to/server-key.pem certs/key.pem
```

Protect the private key:

```bash
chmod 600 certs/key.pem
chmod 644 certs/cert.pem
```

The certificate must contain the hostname used in `PUBLIC_URL`.

Example:

```dotenv
PUBLIC_URL=https://nuclei.example.com:8118
```

requires a certificate valid for:

```text
nuclei.example.com
```

---

## 1.4B Internal CA certificate

Use this option if your organization already operates an internal/private certificate authority.

Issue a server certificate for the exact hostname or IP used in:

```dotenv
PUBLIC_URL=
```

Copy the issued server certificate/chain:

```bash
cp /path/to/server-cert.pem certs/cert.pem
```

Copy the matching server private key:

```bash
cp /path/to/server-key.pem certs/key.pem
```

Protect the key:

```bash
chmod 600 certs/key.pem
chmod 644 certs/cert.pem
```

Agents will later need the **CA certificate** that issued this server certificate.

Do **not** copy the central server's private key to an Agent.

---

## 1.4C Self-signed certificate

Use this option for a lab, test environment, small internal deployment, or another environment where you can explicitly trust the certificate on every browser and Agent.

A self-signed certificate still encrypts traffic, but it is not trusted automatically.

### Example: hostname and IP

Assume the dashboard will be reached as:

```text
https://nuclei-dashboard.example.local:8118
```

and the server IP is:

```text
10.20.30.40
```

Run:

```bash
openssl req -x509 \
  -newkey rsa:4096 \
  -sha256 \
  -days 825 \
  -nodes \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -subj "/CN=nuclei-dashboard.example.local" \
  -addext "subjectAltName=DNS:nuclei-dashboard.example.local,IP:10.20.30.40" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"
```

Replace:

```text
nuclei-dashboard.example.local
10.20.30.40
```

with your real values.

### Hostname only

```bash
openssl req -x509 \
  -newkey rsa:4096 \
  -sha256 \
  -days 825 \
  -nodes \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -subj "/CN=nuclei-dashboard.example.local" \
  -addext "subjectAltName=DNS:nuclei-dashboard.example.local" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"
```

### IP only

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

### Protect the self-signed private key

```bash
chmod 600 certs/key.pem
chmod 644 certs/cert.pem
```

### Verify the certificate SAN

```bash
openssl x509 \
  -in certs/cert.pem \
  -noout \
  -text | grep -A2 "Subject Alternative Name"
```

The exact hostname/IP used in `PUBLIC_URL` must appear in the SAN.

### Verify the certificate and key match

```bash
openssl x509 -noout -modulus -in certs/cert.pem | openssl sha256
openssl rsa  -noout -modulus -in certs/key.pem  | openssl sha256
```

The two hashes should match.

### Configure `.env`

Example:

```dotenv
PUBLIC_URL=https://nuclei-dashboard.example.local:8118
SITE_ADDRESS=https://nuclei-dashboard.example.local:8118
```

---

## 1.5 Verify certificate files exist

From the repository root:

```bash
ls -l certs/cert.pem certs/key.pem
```

Both files must exist before Caddy can start correctly.

---

## 1.6 Validate the Compose configuration

```bash
docker compose config
```

Resolve errors before continuing.

---

## 1.7 Build and start the central server

Run:

```bash
docker compose up -d --build
```

The central stack starts:

```text
postgres
api
web
scanner
caddy
```

The first scanner image build downloads the pinned:

- Naabu release
- ProjectDiscovery httpx release
- Nuclei release
- Nuclei templates release

The build does not intentionally follow ProjectDiscovery `latest`.

---

## 1.8 Confirm containers are running

```bash
docker compose ps
```

Expected central services:

```text
postgres
api
web
scanner
caddy
```

The optional `nuclei-agent` profile is not required for the central server.

---

## 1.9 Check central server logs

API:

```bash
docker compose logs --tail=100 api
```

Caddy:

```bash
docker compose logs --tail=100 caddy
```

WAN scanner:

```bash
docker compose logs --tail=100 scanner
```

Follow them live:

```bash
docker compose logs -f api caddy scanner
```

---

## 1.10 Verify API health

### Publicly trusted certificate

```bash
curl https://dashboard.example.com:8118/api/health
```

### Internal CA

```bash
curl --cacert /path/to/internal-ca.pem \
  https://dashboard.example.com:8118/api/health
```

### Self-signed certificate

Use the public self-signed certificate itself as the trust anchor:

```bash
curl --cacert certs/cert.pem \
  https://nuclei-dashboard.example.local:8118/api/health
```

Expected response:

```json
{"ok":true}
```

Do not use `curl -k` as normal production validation because it disables certificate verification.

---

## 1.11 Open the dashboard

Browse to the exact URL configured in `PUBLIC_URL`.

Example:

```text
https://nuclei-dashboard.example.local:8118
```

Sign in with:

```text
ADMIN_USERNAME
ADMIN_PASSWORD
```

from `.env`.

Do not assume:

```text
https://localhost:8118
```

will work unless the certificate is valid for `localhost`.

---

## 1.12 Trust a self-signed certificate on administrator workstations

If you used a self-signed certificate, browsers will normally warn until the certificate is trusted.

Distribute only:

```text
certs/cert.pem
```

to managed administrator workstations and import it into the trusted certificate store according to your organization's procedures.

Never distribute:

```text
certs/key.pem
```

A permanent browser certificate warning should not be treated as normal operation.

---

## 1.13 Complete the first central configuration

After login, open:

**Admin → Settings**

Review:

- Central host/IP
- Central port
- Agents use HTTPS
- SMTP settings
- Default timezone
- Scanner limits
- Raw evidence retention
- Approved scanner versions
- Vulnerability intelligence options

The Agent-facing central host must be reachable from remote Sites.

Do not use:

```text
localhost
127.0.0.1
```

for remote Agents.

---

## 1.14 Create the first Tenant and Site

Example Tenant:

```text
Acme Manufacturing
```

Example Site:

```text
Hartford Headquarters
```

Add authorized LAN Networks to the Site.

Example:

```text
Corporate LAN
10.20.0.0/24
```

If WAN scanning is needed, add authorized WAN Targets separately.

At this point the **central server installation is complete**.

Before moving to Part 2, verify all of the following:

```text
[ ] docker compose ps shows the central services running
[ ] /api/health returns {"ok":true}
[ ] the dashboard opens over HTTPS
[ ] certificate validation works
[ ] administrator login works
[ ] Central host/port in Admin Settings is correct
[ ] a Tenant exists
[ ] a Site exists
[ ] authorized LAN Networks are configured
```

---

# Part 2 — Site Agent Installation

This section starts **after the central server is already working**.

A Site Agent performs LAN scanning from inside a customer/client Site.

The Agent:

- runs on Linux with Docker;
- makes outbound HTTPS connections to the central server;
- does not need the full central application copied locally;
- builds the scanner runtime from the GitHub repository;
- keeps its private Agent identity key in a Docker volume;
- must be approved and authorized before it can perform normal LAN work.

---

## 2.1 Site Agent requirements

The remote Agent host needs:

- Linux
- Docker Engine
- Docker Compose v2
- outbound HTTPS access to the central dashboard on TCP 8118
- outbound Internet access during Agent image builds
- network reachability to the LAN Networks it is authorized to scan
- enough local storage for the Docker image and Agent volumes

The generated Agent configuration uses:

```yaml
network_mode: host
```

Keep host networking unless you deliberately redesign and validate LAN reachability.

---

## 2.2 Verify the central server from the Agent host

Do this **before creating/troubleshooting the Agent container**.

### Public certificate

```bash
curl https://dashboard.example.com:8118/api/health
```

Expected:

```json
{"ok":true}
```

If this does not work, fix:

- DNS;
- routing;
- firewall;
- central server;
- certificate validity;

before continuing.

---

## 2.3 Create the Agent in Nuclei Dashboard

In the dashboard:

1. Open the correct Tenant.
2. Open/select the correct Site.
3. Create a new Agent.

The Agent receives:

- a UUID;
- an enrollment secret.

Treat the enrollment material as sensitive.

---

## 2.4 Download the Agent deployment files

Download:

- **Compose**
- **Env**

The current UI downloads names similar to:

```text
agent-<UUID>.yml
agent-<UUID>.env
```

There are two deployment methods.

---

## 2.5 Option A — Keep the downloaded filenames

On the Agent host:

```bash
mkdir -p ~/nuclei-agent
cd ~/nuclei-agent
```

Copy both downloaded files into that directory.

Run:

```bash
docker compose \
  -f agent-<UUID>.yml \
  --env-file agent-<UUID>.env \
  up -d --build
```

Example:

```bash
docker compose \
  -f agent-12345678-1234-1234-1234-123456789abc.yml \
  --env-file agent-12345678-1234-1234-1234-123456789abc.env \
  up -d --build
```

---

## 2.6 Option B — Rename the Agent files

This is usually easier for ongoing maintenance.

```bash
mkdir -p ~/nuclei-agent
cd ~/nuclei-agent
```

Copy the downloaded files into the directory and rename them:

```bash
mv agent-<UUID>.yml docker-compose.yml
mv agent-<UUID>.env agent.env
```

Do not start the Agent yet if you still need to configure certificate trust.

---

## 2.7 Configure Agent certificate trust

Choose the method that matches the certificate used on the central server.

---

## 2.7A Central server uses a publicly trusted certificate

Normally no extra CA file is required.

Confirm `agent.env` points to the correct URL:

```dotenv
CENTRAL_URL=https://dashboard.example.com:8118
TLS_VERIFY=1
```

Then continue to [2.8 Start the Agent](#28-start-the-agent).

---

## 2.7B Central server uses an internal CA

The Agent must trust the CA that issued the central server certificate.

From the Agent directory:

```bash
mkdir -p agent-certs
```

Copy the **CA certificate**, not the central server private key:

```bash
cp /path/to/internal-ca.pem agent-certs/ca.pem
```

Edit `agent.env`:

```dotenv
CENTRAL_URL=https://nuclei-dashboard.example.local:8118
TLS_VERIFY=1
TLS_CA_FILE=/certs/ca.pem
```

Test from the Agent host:

```bash
curl --cacert ./agent-certs/ca.pem \
  https://nuclei-dashboard.example.local:8118/api/health
```

Expected:

```json
{"ok":true}
```

---

## 2.7C Central server uses a self-signed certificate

The Agent must explicitly trust the public self-signed certificate.

On the **central server**, the public certificate is:

```text
certs/cert.pem
```

Copy only that public certificate to the Site Agent host.

Do **not** copy:

```text
certs/key.pem
```

On the Agent host:

```bash
cd ~/nuclei-agent
mkdir -p agent-certs
```

Place the central public certificate at:

```text
agent-certs/ca.pem
```

Example:

```bash
cp /path/to/copied-central-cert.pem agent-certs/ca.pem
```

Edit `agent.env`:

```dotenv
CENTRAL_URL=https://nuclei-dashboard.example.local:8118
TLS_VERIFY=1
TLS_CA_FILE=/certs/ca.pem
```

Test certificate validation from the Agent host:

```bash
curl --cacert ./agent-certs/ca.pem \
  https://nuclei-dashboard.example.local:8118/api/health
```

Expected:

```json
{"ok":true}
```

If validation fails, check:

1. `CENTRAL_URL` uses a hostname/IP present in the certificate SAN.
2. DNS resolves correctly.
3. TCP 8118 is reachable.
4. `agent-certs/ca.pem` is the correct public certificate.
5. The certificate is not expired.

---

## 2.7D Lab-only TLS verification bypass

For temporary lab troubleshooting only:

```dotenv
TLS_VERIFY=0
```

Do not use disabled TLS verification as the normal production configuration.

---

## 2.8 Start the Agent

### If using renamed files

```bash
docker compose --env-file agent.env up -d --build
```

### If keeping the UUID filenames

```bash
docker compose \
  -f agent-<UUID>.yml \
  --env-file agent-<UUID>.env \
  up -d --build
```

The first build installs the project's pinned:

- Naabu
- ProjectDiscovery httpx
- Nuclei
- Nuclei templates

---

## 2.9 Verify the Agent container

```bash
docker compose ps
```

View logs:

```bash
docker compose logs -f nuclei-agent
```

The Agent should:

1. connect to the central server;
2. enroll;
3. wait for approval.

---

## 2.10 Approve the Agent

Back in Nuclei Dashboard:

1. Locate the Agent.
2. Confirm its Site and identity.
3. Confirm it is the Agent you just deployed.
4. Approve it.

After approval, the enrollment secret is no longer the Agent's normal authentication mechanism.

---

## 2.11 Authorize the Agent for LAN Networks

Approval does not mean unrestricted scanning.

Configure the Agent for the Networks it is allowed to scan.

Verify:

- Agent belongs to the correct Site;
- Network belongs to the correct Site;
- Agent is authorized for that Network;
- dispatch mode is correct.

Available dispatch models include:

- Any Available
- Preferred + Failover

---

## 2.12 Confirm Agent health

The Agent should eventually appear online/healthy.

A running scan must not make the Agent look Offline. The Agent heartbeats on its own control loop while one scan worker executes.

Check:

```bash
docker compose logs --tail=100 nuclei-agent
```

In the dashboard review:

- status;
- online state;
- last seen;
- runtime version;
- Nuclei version;
- template version;
- Naabu version;
- httpx version;
- approved-version status.

---

## 2.13 Verify installed scanner versions

From the Agent host:

```bash
docker compose exec nuclei-agent nuclei -version
docker compose exec nuclei-agent nuclei -tv -disable-update-check
docker compose exec nuclei-agent naabu -version
docker compose exec nuclei-agent pd-httpx -version
```

The dashboard should receive Agent runtime inventory during heartbeat reporting.

Inventory is sent when the Agent starts, when installed versions change, and on a periodic refresh. Ordinary heartbeats can be empty authenticated pings, or they can include the current job and activity while a scan is running.

---

## 2.14 Protect the Agent identity volume

The Agent private key is stored in the Docker volume:

```text
agent-keys
```

Do **not** use this during routine maintenance:

```bash
docker compose down -v
```

`-v` deletes Compose-managed volumes.

If the Agent private key is lost, do not try to impersonate/reconstruct the old Agent from its UUID.

Create and enroll a new Agent.

---

## 2.15 Run a first LAN scan

After the Agent is:

- approved;
- online;
- assigned to the correct Site;
- authorized for the target Networks;

create or use a LAN Scan Definition.

For the first validation scan, use a small authorized target and conservative settings.

Confirm:

1. the Scan Run is claimed by the expected Agent;
2. discovery completes;
3. Assets/Devices appear as expected;
4. Findings appear if vulnerability scanning is enabled;
5. raw evidence is recorded;
6. runtime/tool/template provenance is visible on the Scan Run.

At this point the **Site Agent installation is complete**.

Agent completion checklist:

```text
[ ] Agent host can validate central HTTPS
[ ] Agent files are installed
[ ] correct CA/self-signed certificate is trusted if required
[ ] Agent container is running
[ ] Agent enrolled
[ ] Agent approved
[ ] Agent authorized for correct Networks
[ ] Agent reports online/healthy
[ ] runtime/tool/template inventory is visible
[ ] a small authorized LAN test scan completes successfully
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

When port discovery is set to `none`, discovery may use Naabu host-discovery behavior where required.

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

Example test from the Agent host:

```bash
curl https://dashboard.example.com:8118/api/health
```

With an internal CA:

```bash
curl --cacert ./agent-certs/ca.pem \
  https://dashboard.example.com:8118/api/health
```

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
docker compose build api scanner web
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

An Agent rebuild retrieves the current `scan_runtime` source used by its Compose build context and installs the pinned tool/template releases defined by that revision.

Scale S1 lives in the Agent image (independent heartbeat/control loop, persistent HTTPS client, scan-stage progress logs, and the httpx DIT stub that prevents a runtime Hugging Face download). After this change, rebuild the Agent image. A container restart of an old image is not enough.

From the Agent directory:

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

```bash
curl https://dashboard.example.com:8118/api/health
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
