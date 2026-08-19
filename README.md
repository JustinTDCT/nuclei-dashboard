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
- [Requirements](#requirements)
- [Central server installation](#central-server-installation)
- [First login and initial configuration](#first-login-and-initial-configuration)
- [Remote Site Agent installation](#remote-site-agent-installation)
- [Agent TLS with an internal CA](#agent-tls-with-an-internal-ca)
- [Agent approval and network authorization](#agent-approval-and-network-authorization)
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

# Requirements

## Central server

A Linux Docker host is recommended.

You need:

- Docker Engine
- Docker Compose v2 (`docker compose`)
- Git
- Enough storage for PostgreSQL and retained raw scanner evidence
- TCP port **8118** reachable by the administrators who use the dashboard
- TCP port **8118** reachable by remote Agents
- Outbound Internet access during image builds so the scanner image can retrieve its pinned ProjectDiscovery releases
- A TLS certificate and matching private key — public CA, internal CA, or self-signed

The scanner build supports:

- `amd64` / `x86_64`
- `arm64` / `aarch64`

## Remote Site Agent

A Site Agent should run on a Linux Docker host that:

- can reach the LAN networks it is authorized to scan;
- can make outbound HTTPS connections to the central dashboard;
- can reach GitHub/ProjectDiscovery during an Agent image build;
- has Docker Engine and Docker Compose v2.

The generated Agent Compose configuration uses:

```yaml
network_mode: host
```

Keep host networking unless you deliberately redesign and validate LAN reachability.

---

# Central server installation

## 1. Clone the repository

```bash
git clone https://github.com/JustinTDCT/nuclei-dashboard.git
cd nuclei-dashboard
```

---

## 2. Create the environment file

```bash
cp .env.example .env
```

Open `.env` in an editor.

For example:

```bash
nano .env
```

or:

```bash
vi .env
```

### Values that must be reviewed before startup

At minimum, change these values:

```dotenv
POSTGRES_PASSWORD=use-a-strong-database-password
SECRET_KEY=use-a-long-random-secret
SCANNER_TOKEN=use-a-different-long-random-secret

ADMIN_USERNAME=admin
ADMIN_PASSWORD=use-a-strong-admin-password
ADMIN_EMAIL=your-admin-email@example.com

PUBLIC_URL=https://dashboard.example.com:8118
SITE_ADDRESS=https://dashboard.example.com:8118
```

The repository's current example file contains an environment-specific `10.150.10.155` address. **Do not leave that address in a new installation unless it is actually the address of your server.**

`PUBLIC_URL` is especially important because the backend uses it when determining the central address Agents should use.

The current Caddy configuration listens on HTTPS port `8118` directly; `SITE_ADDRESS` does not replace the need for a correct certificate.

### Generate random secrets

One simple option on Linux is:

```bash
openssl rand -hex 32
```

Run it separately for values such as:

- `SECRET_KEY`
- `SCANNER_TOKEN`

Use a separate strong password for:

- `POSTGRES_PASSWORD`
- `ADMIN_PASSWORD`

Do not reuse the same secret for all settings.

> `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `ADMIN_EMAIL` are used to seed the first administrator on an empty database. Changing the environment value later should not be treated as a password-reset procedure for an already-created administrator.

---

## 3. Install the TLS certificate

The current Caddy configuration expects these exact files:

```text
./certs/cert.pem
./certs/key.pem
```

Create the directory:

```bash
mkdir -p certs
```

Copy your certificate and key:

```bash
cp /path/to/server-certificate.pem certs/cert.pem
cp /path/to/server-private-key.pem certs/key.pem
```

`cert.pem` should be the server certificate/chain appropriate for the hostname clients will use.

`key.pem` must be the matching private key.

Example public URL:

```text
https://dashboard.example.com:8118
```

The certificate must be valid for the hostname or IP address users and Agents actually connect to.

### Publicly trusted certificate

If the certificate chains to a CA trusted by the Agent's operating system/container, no extra Agent CA file is required.

### Self-signed certificate

A self-signed certificate is suitable for a lab, test environment, small internal deployment, or another environment where you can explicitly trust the certificate on every browser and Agent that connects to the dashboard.

A self-signed certificate is **not automatically trusted**. The connection is still encrypted, but clients must be told to trust the certificate.

The most important requirement is that the certificate's **Subject Alternative Name (SAN)** contains the exact hostname and/or IP address used to reach Nuclei Dashboard.

For example, if the dashboard will be reached as:

```text
https://nuclei-dashboard.example.local:8118
```

and its server IP is:

```text
10.20.30.40
```

generate the certificate from the repository root with:

```bash
mkdir -p certs

openssl req -x509   -newkey rsa:4096   -sha256   -days 825   -nodes   -keyout certs/key.pem   -out certs/cert.pem   -subj "/CN=nuclei-dashboard.example.local"   -addext "subjectAltName=DNS:nuclei-dashboard.example.local,IP:10.20.30.40"   -addext "keyUsage=critical,digitalSignature,keyEncipherment"   -addext "extendedKeyUsage=serverAuth"
```

Replace:

```text
nuclei-dashboard.example.local
10.20.30.40
```

with the actual hostname and IP address for your installation.

If the dashboard will only be accessed by hostname, the SAN can contain only the DNS name:

```bash
openssl req -x509   -newkey rsa:4096   -sha256   -days 825   -nodes   -keyout certs/key.pem   -out certs/cert.pem   -subj "/CN=nuclei-dashboard.example.local"   -addext "subjectAltName=DNS:nuclei-dashboard.example.local"   -addext "keyUsage=critical,digitalSignature,keyEncipherment"   -addext "extendedKeyUsage=serverAuth"
```

If the dashboard will only be accessed by IP address:

```bash
openssl req -x509   -newkey rsa:4096   -sha256   -days 825   -nodes   -keyout certs/key.pem   -out certs/cert.pem   -subj "/CN=10.20.30.40"   -addext "subjectAltName=IP:10.20.30.40"   -addext "keyUsage=critical,digitalSignature,keyEncipherment"   -addext "extendedKeyUsage=serverAuth"
```

After generation, protect the private key:

```bash
chmod 600 certs/key.pem
chmod 644 certs/cert.pem
```

Verify that the certificate and key match:

```bash
openssl x509 -noout -modulus -in certs/cert.pem | openssl sha256
openssl rsa  -noout -modulus -in certs/key.pem  | openssl sha256
```

The two SHA-256 results should match.

Verify the SAN:

```bash
openssl x509 -in certs/cert.pem -noout -text | grep -A2 "Subject Alternative Name"
```

Then configure `.env` to use the same hostname or IP that appears in the SAN:

```dotenv
PUBLIC_URL=https://nuclei-dashboard.example.local:8118
SITE_ADDRESS=https://nuclei-dashboard.example.local:8118
```

Start or restart the central stack:

```bash
docker compose up -d --build
```

Test the server certificate directly:

```bash
curl --cacert certs/cert.pem   https://nuclei-dashboard.example.local:8118/api/health
```

Expected response:

```json
{"ok":true}
```

#### Trusting the self-signed certificate on a Site Agent

Because the certificate is self-signed, the Agent must explicitly trust it.

On the Agent host:

```bash
cd ~/nuclei-agent
mkdir -p agent-certs
```

Copy **only the public certificate** to the Agent host:

```bash
cp /path/to/cert.pem agent-certs/ca.pem
```

Do **not** copy `key.pem` to the Agent.

In `agent.env`:

```dotenv
TLS_VERIFY=1
TLS_CA_FILE=/certs/ca.pem
```

Then recreate the Agent:

```bash
docker compose --env-file agent.env up -d
```

Test from the Agent host:

```bash
curl --cacert ./agent-certs/ca.pem   https://nuclei-dashboard.example.local:8118/api/health
```

If the Agent still reports an HTTPS or certificate error, check:

1. The hostname in `CENTRAL_URL` matches a DNS SAN in the certificate.
2. If using an IP address, the IP appears as an `IP:` SAN.
3. `agent-certs/ca.pem` contains the public self-signed certificate.
4. `TLS_CA_FILE=/certs/ca.pem` is set in `agent.env`.
5. The Agent Compose file mounts `./agent-certs` to `/certs`.
6. The certificate has not expired.

#### Trusting the certificate in a browser

Browsers and operating systems will normally warn about a self-signed certificate until it is manually trusted.

For an internal environment, import `certs/cert.pem` into the workstation or browser's trusted certificate store according to your organization's policy.

Never distribute:

```text
certs/key.pem
```

Only the public certificate should be distributed for trust.

A browser warning should not be treated as a normal permanent operating state. Either trust the self-signed certificate on managed workstations or use a certificate issued by your internal/public CA.

#### Replacing or renewing a self-signed certificate

The example certificate above is valid for 825 days.

Before it expires, generate a replacement with the same required SANs, replace:

```text
certs/cert.pem
certs/key.pem
```

and recreate Caddy:

```bash
docker compose up -d caddy
```

If the self-signed certificate itself changes, Agents and workstations that trusted the old certificate must also be updated to trust the new public certificate.

### Internal/private CA certificate

If your organization already operates an internal CA, using a CA-issued server certificate is generally easier to manage than distributing a unique self-signed server certificate to every client.

The central Caddy server still uses:

```text
certs/cert.pem
certs/key.pem
```

Remote Agents also need to trust your internal CA. See [Agent TLS with an internal CA](#agent-tls-with-an-internal-ca).

> Do not copy the server's private key to an Agent.

---

## 4. Validate the Compose configuration

Before starting the stack:

```bash
docker compose config
```

Resolve any errors before continuing.

---

## 5. Build and start the central stack

```bash
docker compose up -d --build
```

The first scanner build downloads the project's pinned:

- Naabu release
- httpx release
- Nuclei release
- Nuclei templates release

It does not intentionally follow ProjectDiscovery's `latest` release during the build.

---

## 6. Check container status

```bash
docker compose ps
```

You should see the normal central services running:

```text
postgres
api
web
scanner
caddy
```

The `nuclei-agent` service is an optional profile and is not required for the normal central stack.

---

## 7. Check logs if necessary

Useful commands:

```bash
docker compose logs --tail=100 api
docker compose logs --tail=100 caddy
docker compose logs --tail=100 scanner
```

Follow logs live:

```bash
docker compose logs -f api caddy scanner
```

---

## 8. Test API health

With a publicly trusted certificate:

```bash
curl https://dashboard.example.com:8118/api/health
```

Expected result:

```json
{"ok":true}
```

With an internal CA, use that CA for the test:

```bash
curl --cacert /path/to/your-ca.pem \
  https://dashboard.example.com:8118/api/health
```

Do not use `curl -k` as a normal production validation method because it disables certificate verification.

---

## 9. Open the dashboard

Browse to the exact hostname/IP covered by the certificate, for example:

```text
https://dashboard.example.com:8118
```

Sign in with the first-admin credentials configured in `.env`.

Do not assume `https://localhost:8118` will work unless your certificate is actually valid for `localhost`.

---

# First login and initial configuration

After signing in:

## 1. Review Admin settings

Open:

**Admin → Settings**

Review:

- Central host/IP
- Central port
- Whether Agents use HTTPS
- SMTP configuration
- Default timezone
- Raw evidence retention
- Scanner limits
- Approved scanner/tool/template versions
- Vulnerability intelligence settings

For remote Agents, the central host must be an address the remote Site can actually route to.

Do not configure an Agent-facing central host as `localhost`.

---

## 2. Create a Tenant

A Tenant normally represents one managed client/customer.

Example:

```text
Acme Manufacturing
```

---

## 3. Create a Site

Example:

```text
Hartford Headquarters
```

A Site can have its own timezone.

---

## 4. Add LAN Networks

Example:

```text
Name: Corporate LAN
CIDR: 10.20.0.0/24
```

Only add networks you are authorized to scan.

---

## 5. Add WAN Targets if needed

WAN targets are separate from Site LAN Networks.

Authorized WAN targets can be:

- IP
- CIDR
- FQDN

WAN scans run from the central scanner.

---

# Remote Site Agent installation

A Site Agent performs LAN scanning from inside the remote/client network.

The Agent does **not** need the entire central application repository copied to the Site.

The generated Compose configuration builds `scan_runtime` from the GitHub repository.

---

## Step 1. Create the Agent in the dashboard

Navigate to the Tenant/Site and create a new Agent.

The new Agent has:

- an Agent UUID;
- an enrollment secret used for initial enrollment.

Treat the enrollment material as sensitive.

---

## Step 2. Download the Agent files

The UI provides:

- **Compose**
- **Env**

At the current code version, the downloaded files are named similar to:

```text
agent-<UUID>.yml
agent-<UUID>.env
```

They are **not** automatically named `docker-compose.yml` and `agent.env`.

There are two safe ways to deploy them.

---

## Option A — Keep the downloaded filenames

Create a directory on the remote Linux host:

```bash
mkdir -p ~/nuclei-agent
cd ~/nuclei-agent
```

Copy both downloaded files into this directory.

Then run:

```bash
docker compose \
  -f agent-<UUID>.yml \
  --env-file agent-<UUID>.env \
  up -d --build
```

Replace `<UUID>` with the actual filename.

Example:

```bash
docker compose \
  -f agent-12345678-1234-1234-1234-123456789abc.yml \
  --env-file agent-12345678-1234-1234-1234-123456789abc.env \
  up -d --build
```

---

## Option B — Rename the files to simpler names

From the Agent directory:

```bash
mv agent-<UUID>.yml docker-compose.yml
mv agent-<UUID>.env agent.env
```

Then run:

```bash
docker compose --env-file agent.env up -d --build
```

This is usually easier for ongoing maintenance.

---

## Alternative — Download the standard Agent Compose file

You may use the Agent environment file from the dashboard with the standard Compose file from the repository.

On the Site host:

```bash
mkdir -p ~/nuclei-agent
cd ~/nuclei-agent

curl -fsSL -o docker-compose.yml \
  https://raw.githubusercontent.com/JustinTDCT/nuclei-dashboard/main/agent/docker-compose.yml
```

Place/rename the downloaded Agent environment file as:

```text
agent.env
```

Then run:

```bash
docker compose --env-file agent.env up -d --build
```

---

## Step 3. Confirm the Agent container is running

```bash
docker compose ps
```

View logs:

```bash
docker compose logs -f nuclei-agent
```

On first connection, the Agent should enroll and then wait for approval.

---

# Agent TLS with an internal CA

TLS verification is enabled by default.

That should remain enabled in production.

## Publicly trusted central certificate

If the central dashboard uses a publicly trusted certificate, normally no additional Agent configuration is needed.

---

## Internal/private CA

On the remote Agent host:

```bash
cd ~/nuclei-agent
mkdir -p agent-certs
cp /path/to/your-ca.pem agent-certs/ca.pem
```

The file should be the CA certificate needed to validate the central server certificate.

Do **not** copy the central server's private key.

Edit `agent.env` and set:

```dotenv
TLS_VERIFY=1
TLS_CA_FILE=/certs/ca.pem
```

The Compose configuration mounts:

```text
./agent-certs
```

on the host to:

```text
/certs
```

inside the container.

Restart/recreate the Agent:

```bash
docker compose --env-file agent.env up -d
```

### Lab-only TLS bypass

For temporary lab troubleshooting only:

```dotenv
TLS_VERIFY=0
```

Do not use disabled TLS verification as the normal production configuration.

---

# Agent approval and network authorization

Starting the container does not automatically give it unrestricted scanning authority.

A typical flow is:

```text
Agent starts
   |
   v
Initial enrollment
   |
   v
pending approval
   |
   v
Technician/Admin approves Agent
   |
   v
Agent receives approved authenticated access
   |
   v
Agent may claim only work it is eligible/authorized to perform
```

After the Agent appears in the dashboard:

1. Confirm it is the Agent you just deployed.
2. Review its Site.
3. Approve it.
4. Authorize it for the appropriate Site Networks.
5. Configure Network dispatch behavior if required.
6. Confirm the Agent shows online/healthy.

A revoked Agent cannot continue reporting runtime inventory or performing normal approved Agent work.

---

## Protect the Agent key volume

After enrollment/approval, the Agent's private key is stored in the Docker volume:

```text
agent-keys
```

Do not casually run:

```bash
docker compose down -v
```

`-v` deletes Compose-managed volumes.

If the approved Agent's private key volume is lost, the Agent identity cannot simply be reconstructed from its UUID. Create/re-enroll a new Agent instead of trying to fake the old identity.

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
