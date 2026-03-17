# 🔍 PeerGlass — Internet Resource Intelligence

![PeerGlass Branding](gitlab-repo-img-pg-01.jpg)

> **Protocol note:** PeerGlass uses **RDAP** (Registration Data Access Protocol —
> RFC 7480–7484). RDAP (RFC 7480–7484) is the IANA-mandated JSON successor
> to legacy plain-text WHOIS.
> Where you see *"historical-whois"* in source code or API responses, that is
> RIPE Stat's own name for their endpoint — it is not our protocol choice.

Query all **5 global Regional Internet Registries** simultaneously using RDAP,
validate routes via **RPKI**, inspect **BGP** routing visibility, trace full
**historical allocation timelines**, discover **IXP peering data** via PeeringDB,
and monitor **network health** — all from natural language in Claude or via REST API.

---

## What Are the 5 RIRs?

Think of the internet's IP address space like a global land registry.
IANA (the root) delegates large blocks to 5 regional bodies:

| RIR | Region | Countries |
|-----|--------|-----------|
| 🌍 **AFRINIC** | Africa | 54 |
| 🌏 **APNIC** | Asia-Pacific | 56 economies |
| 🌎 **ARIN** | North America | USA, Canada, Caribbean |
| 🌎 **LACNIC** | Latin America & Caribbean | 33 |
| 🌍 **RIPE NCC** | Europe, Middle East, Central Asia | 75+ |

---

## Quick Start

### Install

```bash
git clone https://github.com/duksh/peerglass
cd peerglass
pip install -e .
```

### Configure MCP Clients (Claude and others)

PeerGlass runs as a standard MCP stdio server (`mcp.run()` in `server.py`),
so any MCP-compatible AI client can use it — not just Claude Desktop.

For Claude Desktop, edit
`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "peerglass": {
      "command": "peerglass",
      "args": []
    }
  }
}
```

If `peerglass` is not in your PATH, use:

```json
{
  "mcpServers": {
    "peerglass": {
      "command": "python",
      "args": ["/full/path/to/peerglass/server.py"]
    }
  }
}
```

Restart Claude Desktop. All **42 tools** become immediately available.

### Start the REST API

```bash
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

Interactive docs at: http://localhost:8000/docs

### Start the Web UI

```bash
cd ui
npm install
npm run dev        # Dev server at http://localhost:5173
```

For production build:

```bash
cd ui
npm run build      # Output in ui/dist/
```

Set `VITE_API_BASE_URL` to point at your PeerGlass API deployment:

```bash
VITE_API_BASE_URL=https://api.peerglass.io npm run build
```

---

## Example Queries (Natural Language in Claude)

**Phase 1 — Registry lookups:**
```
"Who owns the IP address 185.220.101.1?"
"What is the abuse contact for 8.8.8.8?"
"Who is AS13335 registered to?"
"Are all 5 RIR RDAP servers online right now?"
```

**Phase 2 — Routing security:**
```
"Is the route 1.1.1.0/24 via AS13335 RPKI valid?"
"Is 8.8.8.0/24 currently visible in the global BGP table?"
"What prefixes is AS15169 (Google) announcing right now?"
"Find all internet resources registered to Cloudflare globally."
```

**Phase 3 — Historical intelligence:**
```
"Show me the full registration history of 8.8.8.0/24."
"Has the prefix 192.0.2.0/24 ever been transferred between organizations?"
"Give me the global IPv4 exhaustion stats for all 5 RIRs."
"Show me the prefix hierarchy for 1.1.1.0/24 — parent blocks and sub-assignments."
```

**Phase 4 — Peering, IXPs, health & monitoring:**
```
"Who does AS13335 (Cloudflare) peer with at internet exchanges?"
"List all IXPs where Google has a presence."
"Is the network for 1.1.1.0/24 currently healthy — any ROA issues or BGP anomalies?"
"Monitor AS13335 for changes since last baseline."
```

**Phase 5 — DNS intelligence:**
```
"What DNS records does cloudflare.com have?"
"Is the DNSSEC chain valid for google.com?"
"Check if 1.2.3.4 is on any spam blocklist."
"Audit the email security posture of example.com."
"Has my DNS change for api.example.com propagated globally yet?"
```

**Phase 6 — TLS, certificates & threat intel:**
```
"When does the TLS certificate for cloudflare.com expire?"
"Show me all certificates ever issued for *.example.com."
"Is 198.51.100.1 flagged as malicious — what ports and CVEs does Shodan see?"
"What hostnames has the IP 1.2.3.4 served historically?"
```

---

## All 42 MCP Tools

### Phase 1 — Registry Queries

| Tool | Description | Cache TTL |
|------|-------------|-----------|
| `rir_query_ip` | Query all 5 RIRs for an IP address (parallel) | 1 hour |
| `rir_query_asn` | Query all 5 RIRs for an ASN (parallel) | 1 hour |
| `rir_get_abuse_contact` | Find abuse contact for any IP globally | 1 hour |
| `rir_server_status` | Health check all 5 RDAP servers | live |
| `rir_cache_stats` | View query cache state and TTLs | live |

### Phase 2 — Routing Intelligence

| Tool | Description | Cache TTL |
|------|-------------|-----------|
| `rir_check_rpki` | Validate RPKI/ROA status for prefix + ASN | 15 min |
| `rir_check_bgp_status` | Check BGP visibility for a prefix or ASN | 5 min |
| `rir_get_announced_prefixes` | List all BGP-announced prefixes for an ASN | 5 min |
| `rir_audit_org` | Audit all IP/ASN resources for an organization | 6 hours |

### Phase 3 — Historical Intelligence

| Tool | Description | Cache TTL |
|------|-------------|-----------|
| `rir_prefix_history` | Full ownership timeline for any prefix or ASN | 12 hours |
| `rir_detect_transfers` | Detect cross-org / cross-RIR resource transfers | 12 hours |
| `rir_ipv4_stats` | Global IPv4/IPv6/ASN dashboard + optional delegated IPv4 block listing (`include_blocks`, filters, pagination) | 24 hours |
| `rir_prefix_overview` | Prefix hierarchy: parent, children, BGP status | 1 hour |

### Phase 4 — Peering, IXPs, Health & Monitoring

| Tool | Description | Cache TTL |
|------|-------------|-----------|
| `rir_peering_info` | PeeringDB peering data + BGP neighbours for an ASN | 1 hour |
| `rir_ixp_lookup` | Search Internet Exchange Points globally | 6 hours |
| `rir_network_health` | RPKI + BGP + RDAP health composite check | 5 min |
| `rir_change_monitor` | Detect changes since last baseline (delta report) | live |

### Phase 5 — DNS Intelligence

| Tool | Description | Cache TTL |
|------|-------------|-----------|
| `peerglass_dns_resolve` | DNS resolution with RDAP IP correlation (A/AAAA/PTR/MX/TXT/NS…) | 5 min |
| `peerglass_dns_enumerate` | Full DNS record enumeration — all types in one call + SPF/DMARC extraction | 5 min |
| `peerglass_dns_dnssec` | DNSSEC chain-of-trust validation (SECURE / INSECURE / BOGUS / INDETERMINATE) | 5 min |
| `peerglass_dns_dnsbl` | DNS blocklist check against 30 RBLs in parallel (Spamhaus, Barracuda, SORBS…) | 15 min |
| `peerglass_dns_email_security` | Email security audit: SPF, DMARC, DKIM, MX, BIMI + risk score | 15 min |
| `peerglass_dns_propagation` | DNS propagation check across 10 global resolvers simultaneously | live |

### Phase 6 — TLS, Certificates & Threat Intelligence

| Tool | Description | Cache TTL |
|------|-------------|-----------|
| `peerglass_tls_inspect` | TLS certificate inspection: subject, SANs, expiry, cipher suite, HSTS | 1 hour |
| `peerglass_ct_logs` | Certificate Transparency log search via crt.sh — discover all certs ever issued | 6 hours |
| `peerglass_threat_intel` | Threat intelligence: Shodan InternetDB (open ports, CVEs) + GreyNoise (classification, risk score) | 15 min |
| `peerglass_passive_dns` | Passive DNS history via RIPE Stat — what IPs/hostnames were associated over time | 12 hours |

### Phase 7 — BGP Depth

| Tool | Description | Cache TTL |
|------|-------------|-----------|
| `rir_check_irr` | IRR route object validation via IRRExplorer — checks RIPE/RADB/ARIN/APNIC/LACNIC consistency | 1 hour |
| `rir_detect_route_leak` | BGP route leak detection — identifies valley-free violations and multi-origin anomalies | 5 min |
| `rir_looking_glass` | BGP looking glass via RIPE RIS — real AS paths from global vantage points | 5 min |
| `rir_route_stability` | Route flap and stability analysis — state changes, uptime %, stability score | 15 min |

### Phase 8 — Humanitarian & Crisis Intelligence

| Tool | Description | Cache TTL |
|------|-------------|-----------|
| `peerglass_shutdown_detect` | Country BGP shutdown detection — compares current prefix counts vs baseline | 5 min |
| `peerglass_monitor_register` | Register webhook alerts for shutdown/change events | live |
| `peerglass_shutdown_timeline` | Historical BGP shutdown timeline with SHA-256 integrity hash (for UN reports) | 1 hour |
| `peerglass_dns_censorship` | DNS censorship fingerprinting — detects NXDOMAIN injection, IP poisoning, DPI blocking | 10 min |
| `peerglass_satellite_connectivity` | Satellite internet tracking — Starlink, Viasat, OneWeb BGP presence | 15 min |
| `peerglass_country_chokepoints` | Country internet chokepoint mapping — critical transit providers, resilience score | 6 hours |
| `peerglass_ooni_report` | OONI censorship measurements — blocked domains, Tor accessibility, circumvention tools | 30 min |
| `peerglass_country_health` | Composite country internet health dashboard — 0–100 score from BGP + DNS + OONI + satellite | 5 min |

### Phase 9 — Advanced Platform

| Tool | Description | Cache TTL |
|------|-------------|-----------|
| `rir_as_relationships` | AS relationship classification (provider/customer/peer) via CAIDA AS-Rank API | 7 days |
| `peerglass_geo_lookup` | GeoIP enrichment via MaxMind GeoLite2-City (requires `PEERGLASS_GEOIP_DB` env var) | 24 hours |
| `peerglass_atlas_trace` | RIPE Atlas distributed traceroute from global vantage points (requires `PEERGLASS_RIPE_ATLAS_KEY`) | 5 min |

---

## REST API — 41 Endpoints

PeerGlass exposes every tool as a REST endpoint, allowing integration with
dashboards, scripts, and CI/CD pipelines — no Claude required.

**Registry & Routing**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/ip/{ip}` | RDAP lookup for an IP address |
| GET | `/v1/asn/{asn}` | RDAP lookup for an ASN |
| GET | `/v1/abuse/{ip}` | Abuse contact for any IP |
| GET | `/v1/rpki?prefix=...&asn=...` | RPKI validation |
| GET | `/v1/bgp/{resource}` | BGP visibility status |
| GET | `/v1/announced/{asn}` | Announced prefixes for an ASN |
| GET | `/v1/org?name=...` | Audit all resources for an org name |
| GET | `/v1/history/{resource}` | Prefix/ASN ownership history |
| GET | `/v1/transfers/{resource}` | Transfer detection |
| GET | `/v1/stats/ipv4` | Global IPv4/IPv6/ASN stats |
| GET | `/v1/overview/{prefix}` | Prefix hierarchy overview |
| GET | `/v1/peering/{asn}` | Peering info from PeeringDB |
| GET | `/v1/ixp` | IXP search and listing |
| GET | `/v1/health/{resource}` | Composite network health check |
| GET | `/v1/monitor/{resource}` | Change monitoring (delta) |

**DNS Intelligence**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/dns/resolve/{target}` | DNS resolution + RDAP IP correlation |
| GET | `/v1/dns/enumerate/{domain}` | Full DNS record enumeration (all types) |
| GET | `/v1/dns/dnssec/{domain}` | DNSSEC chain-of-trust validation |
| GET | `/v1/dns/dnsbl/{ip}` | DNS blocklist check (30 RBLs in parallel) |
| GET | `/v1/dns/email/{domain}` | Email security audit (SPF/DMARC/DKIM/BIMI) |
| GET | `/v1/dns/propagation/{domain}` | DNS propagation across 10 global resolvers |

**TLS, Certificates & Threat Intel**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/tls/{hostname}` | TLS certificate inspection |
| GET | `/v1/ct/{domain}` | Certificate Transparency log search |
| GET | `/v1/threat/{ip}` | Threat intelligence (Shodan + GreyNoise) |
| GET | `/v1/pdns/{resource}` | Passive DNS history (RIPE Stat) |

**BGP Depth**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/irr?prefix=...&asn=...` | IRR route object validation |
| GET | `/v1/route-leak/{prefix}` | BGP route leak detection |
| GET | `/v1/looking-glass/{prefix}` | BGP looking glass (RIPE RIS) |
| GET | `/v1/stability/{prefix}` | Route flap stability analysis |

**Humanitarian & Crisis**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/shutdown/{country_code}` | Country BGP shutdown detection |
| POST | `/v1/shutdown/monitor` | Register shutdown webhook alert |
| GET | `/v1/shutdown/timeline/{resource}` | Historical shutdown timeline |
| GET | `/v1/censorship/{domain}` | DNS censorship fingerprinting |
| GET | `/v1/satellite/{country_code}` | Satellite connectivity status |
| GET | `/v1/chokepoints/{country_code}` | Country internet chokepoints |
| GET | `/v1/ooni/{country_code}` | OONI censorship measurements |
| GET | `/v1/health/country/{country_code}` | Composite country internet health |

**Advanced Platform**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/as-relationships/{asn}` | AS relationship classification (CAIDA) |
| GET | `/v1/geo/{ip}` | GeoIP enrichment (MaxMind GeoLite2) |
| GET | `/v1/atlas/{target}` | RIPE Atlas distributed traceroute |
| POST | `/v1/bulk` | Bulk query up to 50 resources in one call |

**Quick example:**

```bash
# Look up who owns 1.1.1.1
curl http://localhost:8000/v1/ip/1.1.1.1

# Validate RPKI for Cloudflare's prefix
curl "http://localhost:8000/v1/rpki?prefix=1.1.1.0/24&asn=AS13335"

# Get BGP peers for Google
curl http://localhost:8000/v1/peering/AS15169

# List AFRINIC delegated IPv4 blocks (allocated + Ghana), paginated
curl "http://localhost:8000/v1/stats/ipv4?rir=AFRINIC&include_blocks=true&status=allocated&country=GH&limit=5&offset=0&format=json"

# DNS — enumerate all record types for a domain
curl http://localhost:8000/v1/dns/enumerate/cloudflare.com

# DNS — check email security (SPF/DMARC/DKIM)
curl http://localhost:8000/v1/dns/email/cloudflare.com

# DNS — check if an IP is on any blocklist
curl http://localhost:8000/v1/dns/dnsbl/1.2.3.4

# DNS — check propagation across 10 global resolvers
curl "http://localhost:8000/v1/dns/propagation/cloudflare.com?record_type=A"

# TLS — inspect certificate for a hostname
curl http://localhost:8000/v1/tls/cloudflare.com

# Certificates — find all certs ever issued for a domain
curl http://localhost:8000/v1/ct/cloudflare.com

# Threat intel — open ports, CVEs, risk score for an IP
curl http://localhost:8000/v1/threat/1.2.3.4

# Passive DNS — what hostnames has this IP served?
curl http://localhost:8000/v1/pdns/1.1.1.1
```

Interactive docs (Swagger UI): http://localhost:8000/docs

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    PEERGLASS                            │
│                                                         │
│   Claude (LLM)              REST Clients                │
│       │ MCP / stdio              │ HTTP                 │
│       ▼                          ▼                      │
│   server.py (42 tools)      api.py (41 endpoints)       │
│       │                          │                      │
│       └──────────┬───────────────┘                      │
│                  ▼                                       │
│           rir_client.py  ── All async HTTP calls         │
│                  │                                       │
│       ┌──────────┼──────────────────┐                   │
│       ▼          ▼                  ▼                   │
│  normalizer.py  formatters.py    cache.py               │
│  (unify RDAP)   (markdown/JSON)  (TTL tiers)            │
│       │                                                  │
│       ▼                                                  │
│    models.py  (Pydantic v2 data models)                  │
└─────────────────────────────────────────────────────────┘

External APIs called at runtime:
  ├── RDAP:    rdap.afrinic.net / rdap.apnic.net / rdap.arin.net
  │            rdap.lacnic.net  / rdap.db.ripe.net
  ├── RPKI:    rpki.cloudflare.com
  ├── BGP:     stat.ripe.net (bgp-state, announced-prefixes,
  │            routing-status, asn-neighbours, historical-whois)
  ├── IXP:     peeringdb.com/api/net, /api/ix, /api/netixlan
  ├── Stats:   NRO Extended Delegation Stats (all 5 RIRs)
  └── Routing: data.iana.org/rdap/ (IANA bootstrap)
```

### How Parallel Queries Work

```
asyncio.gather() fires all 5 RIR queries at exactly the same time:

  AFRINIC ──── responds in 1.1s ──── 404 Not Found
  APNIC   ──── responds in 0.9s ──── ✅ 200 OK  ← authoritative
  ARIN    ──── responds in 1.2s ──── 404 Not Found
  LACNIC  ──── responds in 1.4s ──── 404 Not Found
  RIPE    ──── responds in 0.8s ──── 404 Not Found

Total wall-clock time: ~1–2s (parallel) vs ~6–8s (sequential)
```

---

## Web UI (Sprint 7)

PeerGlass includes a search-first, dark terminal-themed web frontend built with **React 18 + Vite 5 + TypeScript + Tailwind CSS**.

### Features

- **Auto-detection**: Paste any IP, ASN, prefix, domain, or 2-letter country code — the UI auto-detects the type and runs the right tool
- **7 tool categories**: Registry · Routing · DNS · TLS · Threat · Crisis · Peering
- **Dark terminal theme**: Dark background, monospace font (JetBrains Mono), cyan/green accent palette
- **Markdown rendering**: All API results rendered as formatted markdown with syntax highlighting
- **Crisis dashboard**: One-click country health check for Syria, Myanmar, Ukraine, Belarus, Iran, Russia and more
- **41 tools accessible**: Every REST endpoint is exposed via the UI

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `http://localhost:8000` | PeerGlass API base URL |

### Directory structure

```
ui/
├── src/
│   ├── App.tsx                  # Main layout + tab state
│   ├── components/
│   │   ├── SearchBar.tsx        # Search input with auto-type detection
│   │   ├── ResultPanel.tsx      # Markdown result renderer
│   │   ├── TabBar.tsx           # Category + tool tab navigation
│   │   ├── StatusBadge.tsx      # RPKI/BGP/shutdown status indicators
│   │   └── CountryDashboard.tsx # Crisis country quick-access grid
│   ├── hooks/
│   │   └── usePeerGlass.ts      # Query state management hook
│   └── api/
│       └── client.ts            # Typed wrappers for all 41 endpoints
└── dist/                        # Production build output
```

---

## Testing

PeerGlass has **two separate test suites** serving different purposes.
You should run both — they catch different categories of problems.

```
┌─────────────────────────────────────────────────────────────┐
│                   TESTING PYRAMID                           │
│                                                             │
│      🔺 INTEGRATION TESTS  (test_integration.py)            │
│      /\   Real internet. Real APIs. Real data.              │
│     /  \  Proves the product actually works end-to-end.     │
│    /────\  Run this on your machine or a GCP VM.            │
│                                                             │
│   🔺 UNIT / STATIC TESTS  (test_peerglass.py)              │
│   /\   In-memory. No network. Instant.                      │
│  /  \  Proves code structure, branding, and wiring.         │
│ /────\  Runs anywhere including CI/CD.                      │
└─────────────────────────────────────────────────────────────┘
```

---

### Test 1 — Static / Unit Tests (`test_peerglass.py`)

**What it checks:**

| # | Test | What It Verifies |
|---|------|-----------------|
| 1 | Compile check | All 7 `.py` files parse without syntax errors |
| 2 | Branding audit | No stale legacy product/server identity strings |
| 3 | RDAP endpoints | All 5 RIR RDAP URLs are present and correct |
| 4 | Protocol header | `Accept: application/rdap+json` is set |
| 5 | User-Agent | Updated to `peerglass/1.0.0` |
| 6 | MCP server name | `"peerglass"` |
| 7 | Tool count | Exactly 42 `@mcp.tool()` decorators in `server.py` |
| 8 | REST endpoints | All 41 routes present in `api.py` |
| 9 | FastAPI runtime | TestClient hits 3 endpoints in-memory, validates responses |
| 10 | README | PeerGlass branding, 42 tools, RDAP note all present |

**How to run:**

```bash
cd peerglass
python test_peerglass.py
```

**Expected output:**

```
============================================================
PEERGLASS — COMPLETE TEST SUITE
============================================================
1. COMPILE CHECK
   ✅ server.py  ✅ rir_client.py  ✅ formatters.py
   ✅ models.py  ✅ cache.py  ✅ normalizer.py  ✅ api.py

2. BRANDING AUDIT — no stale WHOIS identity strings
   ✅ server.py  ✅ rir_client.py  ✅ README.md  ...

...

✅ ALL TESTS PASSED — 0 errors
  Python files: 7  |  MCP tools: 42  |  REST endpoints: 41
  Protocol: RDAP throughout (RFC 7480-7484)
  Branding: PeerGlass throughout
============================================================
```

**When to run:** Before every commit. Runs in under 3 seconds. No internet required.

---

### Test 2 — Integration Tests (`test_integration.py`)

**What it checks:**

Real HTTP calls to external internet registries/data providers using
well-known, stable test fixtures
(Cloudflare AS13335, Google AS15169, 1.1.1.0/24). Every test asserts on
actual response data — not just that the server responded.

| # | Test | API Called | Fixture | Assertion |
|---|------|-----------|---------|-----------|
| 1 | RDAP reachability | All 5 RIRs | `1.1.1.1` | HTTP 200 or 404 (both mean server is up) |
| 2 | RDAP IP lookup | APNIC | `1.1.1.1` | `objectClassName=ip network`, `startAddress=1.1.1.0` |
| 3 | RDAP ASN lookup | ARIN | `AS13335` | `objectClassName=autnum`, name contains `CLOUDFLARE` |
| 4 | RPKI validation | RIPE Stat | `1.1.1.0/24 AS13335` | `status=ok`, validation status is `valid` |
| 5 | BGP status | RIPE Stat | `1.1.1.0/24` | Prefix visible to RIS peers, origin ASN present |
| 6 | Announced prefixes | RIPE Stat | `AS13335` | >= 5 prefixes, mix of IPv4 + IPv6 |
| 7 | Historical data | RIPE Stat | `AS15169` | `status=ok`, historical object versions returned |
| 8 | PeeringDB network | PeeringDB | `AS13335` | Network record found, peering policy present |
| 9 | IANA Bootstrap | IANA | `AS13335` | Mapped to correct RDAP service URL |
| 10 | AFRINIC RDAP | AFRINIC | `102.176.0.0` | `objectClassName=ip network`, African country code |
| 11 | ASN neighbours | RIPE Stat | `AS13335` | Upstream / peer ASN list returned |
| 12 | PeeringDB IXPs | PeeringDB | global | IXP list with name and country |
| 13 | IANA consistency | IANA/ICANN | IPv4 + IPv6 + ASN bootstrap files | All 5 RIR service URLs present |

**How to run:**

```bash
# On your local machine or a GCP VM (requires internet access)
cd peerglass
python test_integration.py
```

**Expected output (passing):**

```
============================================================
  PEERGLASS — LIVE INTEGRATION TEST SUITE
  Real HTTP calls. No mocks. No fakes.
============================================================
  Time: 2026-02-20 14:00:00 UTC
  APIs: RIPE · ARIN · APNIC · LACNIC · AFRINIC · RIPE Stat · PeeringDB · IANA

────────────────────────────────────────────
  TEST 1 — RDAP Server Reachability (all 5 RIRs)
────────────────────────────────────────────
   ✅ PASS  RIPE RDAP reachable      HTTP 404
   ✅ PASS  ARIN RDAP reachable      HTTP 404
   ✅ PASS  APNIC RDAP reachable     HTTP 200
   ✅ PASS  LACNIC RDAP reachable    HTTP 404
   ✅ PASS  AFRINIC RDAP reachable   HTTP 404

...

============================================================
  SUMMARY
  Checks run   : 48
  ✅ Passed    : 47
  ❌ Failed    : 0
  ⚠️  Skipped  : 1
  Duration     : ~20-40s

  🎉 ALL TESTS PASSED — PeerGlass live APIs confirmed working!
============================================================
```

**When to run:**
- Before a release
- After any change to `rir_client.py` (the HTTP layer)
- After any change to the external API URLs or parameters
- On a schedule (e.g. daily cron on a GCP VM) to detect API changes upstream

**Why this cannot run in CI/CD without configuration:**
The integration tests require outbound internet access to external APIs
(RIPE, ARIN, APNIC, LACNIC, AFRINIC, RIPE Stat, PeeringDB, IANA). Standard CI runners (GitHub Actions
free tier) have internet access, so these tests can run there. Restricted
sandboxes (Anthropic Claude environment, some corporate proxies) will block
the outbound calls and every test will fail with `403 Forbidden` — this is
expected behaviour of the sandbox, not a bug in PeerGlass.

---

### Understanding Test Results

#### Why does RDAP return 404 and still pass?

```
APNIC owns 1.1.1.0/24 (Cloudflare's block). If you ask RIPE for 1.1.1.1:

  You:  GET https://rdap.db.ripe.net/ip/1.1.1.1
  RIPE: HTTP 404

This 404 is RIPE saying "I know about this IP but it's not mine."
The server is alive and working correctly. 404 = server reachable.
200 = server reachable AND it's the authoritative RIR for that IP.
Both are valid success states for the reachability test.
```

#### Why does Test 7 sometimes SKIP?

RIPE Stat's `historical-whois` endpoint has variable coverage. For some
ASNs it returns rich history; for others the `objects` array is empty.
An empty array is a valid API response — the skip is logged to distinguish
"no data" from "API broken".

---

### Running Both Suites Together

```bash
cd peerglass

# Step 1: Always run static tests first (fast, catches code errors)
python test_peerglass.py
echo "Exit code: $?"

# Step 2: Only run integration tests if static tests pass
if [ $? -eq 0 ]; then
    python test_integration.py
fi
```

---

### Verification — Source-Pinned Retrieval vs Model Recall

If you want to verify that PeerGlass is deterministic and source-pinned
(real API retrieval) rather than model recall, run this quick check.

1. Ask ChatGPT to fetch all 5 RIR RDAP endpoints for `1.1.1.1` and return raw JSON only.
2. Repeat the exact same prompt multiple times.
3. Compare ChatGPT output against direct endpoint results below.

Use this prompt in ChatGPT:

```text
For IP 1.1.1.1, query these exact RDAP endpoints and return ONLY JSON:

- AFRINIC: https://rdap.afrinic.net/rdap/ip/1.1.1.1
- APNIC: https://rdap.apnic.net/ip/1.1.1.1
- ARIN: https://rdap.arin.net/registry/ip/1.1.1.1
- LACNIC: https://rdap.lacnic.net/rdap/ip/1.1.1.1
- RIPE: https://rdap.db.ripe.net/ip/1.1.1.1

Output schema per RIR:
{
  "rir": "...",
  "url": "...",
  "http_status": ...,
  "objectClassName": "... or null",
  "handle": "... or null",
  "error": "... or null"
}

Do not summarize. Do not infer.
```

Ground-truth script (direct endpoint calls):

```bash
python - <<'PY'
import asyncio
import json
import httpx

ENDPOINTS = {
    "AFRINIC": "https://rdap.afrinic.net/rdap/ip/1.1.1.1",
    "APNIC": "https://rdap.apnic.net/ip/1.1.1.1",
    "ARIN": "https://rdap.arin.net/registry/ip/1.1.1.1",
    "LACNIC": "https://rdap.lacnic.net/rdap/ip/1.1.1.1",
    "RIPE": "https://rdap.db.ripe.net/ip/1.1.1.1",
}

async def query_one(client, rir, url):
    try:
        r = await client.get(url, timeout=20)
        content_type = r.headers.get("content-type", "")
        data = r.json() if "json" in content_type else {}
        return {
            "rir": rir,
            "url": url,
            "http_status": r.status_code,
            "objectClassName": data.get("objectClassName"),
            "handle": data.get("handle"),
            "error": None,
        }
    except Exception as exc:
        return {
            "rir": rir,
            "url": url,
            "http_status": None,
            "objectClassName": None,
            "handle": None,
            "error": str(exc),
        }

async def main():
    headers = {
        "Accept": "application/rdap+json",
        "User-Agent": "peerglass/verification",
    }
    async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
        results = await asyncio.gather(*[
            query_one(client, rir, url) for rir, url in ENDPOINTS.items()
        ])
    print(json.dumps(results, indent=2))

asyncio.run(main())
PY
```

If ChatGPT outputs are inconsistent or fail to fetch while direct calls are stable,
that difference is exactly why PeerGlass uses deterministic source-pinned retrieval.

---

### Adding Your Own Integration Tests

The `test_integration.py` script is designed to be extended. Each test follows
this pattern:

```python
async def test_your_thing():
    section("TEST N — Short description")
    print("  What API, what fixture, what you expect")

    url = "https://example-api.com/endpoint"
    params = {"resource": "your-fixture", "sourceapp": "peerglass-test"}
    headers = {"Accept": "application/json", "User-Agent": "peerglass/1.0.0 (integration-test)"}

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            fail("API returned 200", f"HTTP {resp.status_code}"); return

        data = resp.json()
        value = data.get("some", {}).get("field", "")

        ok("Field is what I expected", f"value='{value}'") if value == "expected" else fail("Field check", f"Got '{value}'")

    except Exception:
        fail("API call failed", traceback.format_exc()[-120:])
```

Then add it to the `main()` coroutine:

```python
async def main():
    ...
    await test_your_thing()   # ← add here
    ...
```

---

## External APIs Used

| API | Purpose | Cache TTL |
|-----|---------|-----------|
| All 5 RIR RDAP endpoints | IP/ASN registration data (RDAP JSON) | 1 hr |
| `data.iana.org/rdap/` | Bootstrap: which RIR owns which IP/ASN range | permanent |
| `rpki.cloudflare.com` | RPKI/ROA validation (Validated ROA Payloads) | 15 min |
| `stat.ripe.net/data/bgp-state` | BGP routing table visibility | 5 min |
| `stat.ripe.net/data/announced-prefixes` | Prefixes announced by an ASN | 5 min |
| `stat.ripe.net/data/asn-neighbours` | BGP peer/upstream/downstream ASNs | 1 hr |
| `stat.ripe.net/data/historical-whois` | RDAP object change history (RIPE's naming) | 12 hr |
| `stat.ripe.net/data/allocation-history` | Allocation lifecycle events | 12 hr |
| `stat.ripe.net/data/prefix-overview` | Prefix hierarchy metadata | 1 hr |
| `stat.ripe.net/data/routing-status` | Routing status and visibility | 5 min |
| `peeringdb.com/api/net` | Network peering policies | 1 hr |
| `peeringdb.com/api/ix` | Internet Exchange Point directory | 6 hr |
| `peeringdb.com/api/netixlan` | Network-to-IXP membership records | 1 hr |
| NRO Extended Delegation Stats | Authoritative IPv4/IPv6/ASN allocation counts (all 5 RIRs) | 24 hr |

---

## Phase 3 Data Sources Explained

### RIPE Stat historical-whois
Records every change ever made to an RDAP object: when the org field changed,
when the status changed, when a new maintainer was added. Used by
`rir_prefix_history` and `rir_detect_transfers`. The name *"historical-whois"*
is RIPE Stat's own endpoint naming — PeerGlass uses RDAP protocol throughout.

**Coverage:** Best for RIPE NCC resources. Partial for other RIRs.

### RIPE Stat allocation-history
Logs the full allocation lifecycle: when a block was first allocated from the
RIR pool, when it was sub-allocated to an ISP, when it was returned.

### NRO Extended Delegation Stats
Published daily by each RIR as a pipe-delimited text file. Contains every
single IP and ASN record ever created, with current status. Authoritative
source for `rir_ipv4_stats`.

### RIPE Stat prefix-overview / less-specifics / more-specifics
Three APIs queried in parallel to build the prefix hierarchy tree for
`rir_prefix_overview`.

---

## Use Case Workflows

### BGP Hijack Investigation
```
1. rir_query_ip(suspicious_ip)         → Who registered this IP?
2. rir_check_bgp_status(prefix)        → Which ASN is announcing it right now?
3. rir_check_rpki(prefix, asn)         → Is the announcement RPKI-valid?
4. rir_prefix_overview(prefix)         → Any unexpected more-specifics?
5. rir_detect_transfers(prefix)        → Did this block recently change hands?
```

### M&A Due Diligence
```
1. rir_audit_org(company_name)         → What IP blocks does this company own?
2. rir_prefix_history(each_prefix)     → When were they acquired?
3. rir_detect_transfers(each_prefix)   → Were any transferred recently?
4. rir_get_announced_prefixes(asn)     → What are they actively routing?
```

### Peering & IXP Analysis
```
1. rir_get_peering_info(asn)           → Where does this network peer?
2. rir_lookup_ixps(city or ixp_name)  → Find IXPs in a region
3. rir_network_health(asn)             → Is the network healthy?
4. rir_change_monitor(asn)             → Any changes since last check?
```

### Policy Research / ISOC Report
```
1. rir_ipv4_stats()                    → Full global IPv4/IPv6/ASN dashboard
2. rir_ipv4_stats(rir_filter="AFRINIC")→ Africa-specific detail
3. Compare ipv6_total_prefixes across  → IPv6 adoption rates by region
```

---

## IPv4 Exhaustion Context

| RIR | IPv4 Free Pool Exhausted |
|-----|--------------------------|
| APNIC | 15 April 2011 |
| RIPE NCC | 14 September 2012 |
| ARIN | 24 September 2015 |
| LACNIC | June 2020 |
| AFRINIC | 2020–2021 |

All RIRs now operate under transfer policies. IPv4 addresses trade on the
secondary market. `rir_ipv4_stats` tracks remaining pools in real time.

---

## License

MIT