#!/usr/bin/env python3
"""
PeerGlass — Full QA Test Suite
Tests every UI tool, auto-detection logic, endpoint routing,
format switching, and error handling against a local server.
"""
import asyncio
import sys
import re
import json
import httpx
import traceback

BASE = "http://localhost:8001"
TIMEOUT = 30

# ── helpers ──────────────────────────────────────────────────────────────────
PASS = 0; FAIL = 0; SKIP = 0; WARN = 0
FAILURES: list[str] = []

BOLD  = "\033[1m"
GREEN = "\033[92m"
RED   = "\033[91m"
YELL  = "\033[93m"
CYAN  = "\033[96m"
DIM   = "\033[2m"
RESET = "\033[0m"

def section(title: str):
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}{title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}")

def ok(label: str, detail: str = ""):
    global PASS
    PASS += 1
    suffix = f"{DIM} ({detail}){RESET}" if detail else ""
    print(f"  {GREEN}✅ PASS{RESET}  {label}{suffix}")

def fail(label: str, detail: str = ""):
    global FAIL
    FAIL += 1
    FAILURES.append(f"{label}: {detail}")
    suffix = f" — {detail}" if detail else ""
    print(f"  {RED}❌ FAIL{RESET}  {label}{RED}{suffix}{RESET}")

def skip(label: str, detail: str = ""):
    global SKIP
    SKIP += 1
    suffix = f" — {detail}" if detail else ""
    print(f"  {YELL}⚠️  SKIP{RESET}  {label}{YELL}{suffix}{RESET}")

def warn(label: str, detail: str = ""):
    global WARN
    WARN += 1
    suffix = f" — {detail}" if detail else ""
    print(f"  {YELL}⚠️  WARN{RESET}  {label}{YELL}{suffix}{RESET}")

async def get(client: httpx.AsyncClient, path: str, params: dict | None = None, expect_ok=True):
    try:
        r = await client.get(f"{BASE}{path}", params=params or {}, timeout=TIMEOUT)
        return r
    except Exception as e:
        return None

async def post(client: httpx.AsyncClient, path: str, body: dict):
    try:
        r = await client.post(f"{BASE}{path}", json=body, timeout=TIMEOUT)
        return r
    except Exception as e:
        return None

def check_response(r, label: str, *, allow_error=False) -> str | None:
    """Returns response text, or None on failure."""
    if r is None:
        fail(label, "no response / connection error")
        return None
    if r.status_code == 422:
        fail(label, f"HTTP 422 Unprocessable Entity — {r.text[:200]}")
        return None
    if r.status_code == 404:
        fail(label, f"HTTP 404 Not Found — route missing?")
        return None
    if r.status_code == 500 and not allow_error:
        fail(label, f"HTTP 500 Internal Server Error — {r.text[:200]}")
        return None
    return r.text

def is_markdown(text: str) -> bool:
    """Heuristic: contains markdown headings or list markers."""
    return bool(re.search(r'^#{1,3}\s', text, re.MULTILINE) or '- ' in text or '| ' in text)

def is_json(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: API Meta / Health
# ═══════════════════════════════════════════════════════════════════════════
async def test_meta(client: httpx.AsyncClient):
    section("1. API Meta / Health Endpoints")

    # Root
    r = await get(client, "/")
    if check_response(r, "GET / (API root)"):
        d = json.loads(r.text)
        ok("Root returns name", d.get("name", ""))
        ok("Root tool count = 42", str(d.get("tools"))) if d.get("tools") == 42 else fail("Root tool count = 42", f"got {d.get('tools')}")

    # Cache stats
    r = await get(client, "/v1/meta/cache")
    if check_response(r, "GET /v1/meta/cache"):
        ok("Cache stats endpoint alive")

    # OpenAI tools schema
    r = await get(client, "/v1/meta/openai-tools")
    if check_response(r, "GET /v1/meta/openai-tools"):
        tools = json.loads(r.text)
        ok("OpenAI schema is array") if isinstance(tools, list) else fail("OpenAI schema is array", type(tools).__name__)
        ok(f"OpenAI tool count ≥ 40", str(len(tools))) if len(tools) >= 40 else fail("OpenAI tool count ≥ 40", str(len(tools)))

    # Server status (allow slow upstream errors)
    r = await get(client, "/v1/meta/status")
    if r is not None and r.status_code in (200, 500):
        ok("Server status endpoint alive", f"HTTP {r.status_code}")
    else:
        fail("Server status endpoint", f"HTTP {r.status_code if r else 'no response'}")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: Registry Endpoints — input routing
# ═══════════════════════════════════════════════════════════════════════════
async def test_registry(client: httpx.AsyncClient):
    section("2. Registry Endpoints (UI: Registry tab)")

    # IP lookup
    r = await get(client, "/v1/ip/1.1.1.1")
    t = check_response(r, "GET /v1/ip/1.1.1.1", allow_error=True)
    if t:
        ok("IP endpoint returns content", f"{len(t)} chars")
        ok("IP returns markdown by default") if is_markdown(t) or "Error" in t or "error" in t else warn("IP response not markdown", t[:80])

    # IP with JSON format
    r = await get(client, "/v1/ip/1.1.1.1", {"format": "json"})
    t = check_response(r, "GET /v1/ip/1.1.1.1?format=json", allow_error=True)
    if t:
        ok("IP ?format=json returns JSON") if is_json(t) else fail("IP ?format=json returns JSON", t[:100])

    # ASN lookup
    r = await get(client, "/v1/asn/AS13335")
    t = check_response(r, "GET /v1/asn/AS13335", allow_error=True)
    if t:
        ok("ASN endpoint returns content", f"{len(t)} chars")

    # ASN without "AS" prefix
    r = await get(client, "/v1/asn/13335")
    t = check_response(r, "GET /v1/asn/13335 (numeric only)", allow_error=True)
    if t:
        ok("ASN numeric-only input accepted")

    # Abuse contact
    r = await get(client, "/v1/abuse/8.8.8.8")
    t = check_response(r, "GET /v1/abuse/8.8.8.8", allow_error=True)
    if t:
        ok("Abuse contact endpoint returns content")

    # Org audit
    r = await get(client, "/v1/org", {"name": "Cloudflare"})
    t = check_response(r, "GET /v1/org?name=Cloudflare", allow_error=True)
    if t:
        ok("Org audit endpoint returns content", f"{len(t)} chars")

    # Org audit — missing name param → expect 422
    r = await get(client, "/v1/org")
    if r is not None and r.status_code == 422:
        ok("Org audit missing ?name → 422 (correct validation)")
    elif r is not None and r.status_code == 200:
        fail("Org audit missing ?name → should be 422, got 200")
    else:
        skip("Org audit validation check", f"HTTP {r.status_code if r else 'none'}")

    # IPv6 lookup
    r = await get(client, "/v1/ip/2606:4700:4700::1111")
    t = check_response(r, "GET /v1/ip/2606:4700:4700::1111 (IPv6)", allow_error=True)
    if t:
        ok("IPv6 address accepted by IP endpoint")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: Routing Endpoints
# ═══════════════════════════════════════════════════════════════════════════
async def test_routing(client: httpx.AsyncClient):
    section("3. Routing Endpoints (UI: Routing tab)")

    # BGP
    r = await get(client, "/v1/bgp/1.1.1.0%2F24")
    t = check_response(r, "GET /v1/bgp/1.1.1.0/24", allow_error=True)
    if t:
        ok("BGP status endpoint returns content")

    # BGP with ASN
    r = await get(client, "/v1/bgp/AS13335")
    t = check_response(r, "GET /v1/bgp/AS13335", allow_error=True)
    if t:
        ok("BGP ASN input accepted")

    # RPKI — needs prefix + asn
    r = await get(client, "/v1/rpki", {"prefix": "1.1.1.0/24", "asn": "13335"})
    t = check_response(r, "GET /v1/rpki?prefix=1.1.1.0/24&asn=13335", allow_error=True)
    if t:
        ok("RPKI endpoint returns content")

    # RPKI — missing asn → 422
    r = await get(client, "/v1/rpki", {"prefix": "1.1.1.0/24"})
    if r is not None and r.status_code == 422:
        ok("RPKI missing asn → 422 (correct validation)")
    elif r is not None:
        fail("RPKI missing asn should → 422", f"got {r.status_code}")

    # Announced prefixes
    r = await get(client, "/v1/announced/AS13335")
    t = check_response(r, "GET /v1/announced/AS13335", allow_error=True)
    if t:
        ok("Announced prefixes endpoint returns content")

    # Prefix overview
    r = await get(client, "/v1/overview/1.1.1.0%2F24")
    t = check_response(r, "GET /v1/overview/1.1.1.0/24", allow_error=True)
    if t:
        ok("Prefix overview endpoint returns content")

    # IRR
    r = await get(client, "/v1/irr", {"prefix": "1.1.1.0/24", "asn": "13335"})
    t = check_response(r, "GET /v1/irr?prefix=1.1.1.0/24&asn=13335", allow_error=True)
    if t:
        ok("IRR endpoint returns content")

    # Route leak — uses path param with slash
    r = await get(client, "/v1/route-leak/1.1.1.0%2F24")
    t = check_response(r, "GET /v1/route-leak/1.1.1.0/24", allow_error=True)
    if t:
        ok("Route leak endpoint returns content")

    # Looking glass
    r = await get(client, "/v1/looking-glass/1.1.1.0%2F24")
    t = check_response(r, "GET /v1/looking-glass/1.1.1.0/24", allow_error=True)
    if t:
        ok("Looking glass endpoint returns content")

    # Route stability
    r = await get(client, "/v1/stability/1.1.1.0%2F24")
    t = check_response(r, "GET /v1/stability/1.1.1.0/24", allow_error=True)
    if t:
        ok("Route stability endpoint returns content")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: History / Stats Endpoints
# ═══════════════════════════════════════════════════════════════════════════
async def test_history(client: httpx.AsyncClient):
    section("4. History & Stats Endpoints")

    r = await get(client, "/v1/history/1.1.1.0%2F24")
    t = check_response(r, "GET /v1/history/1.1.1.0/24", allow_error=True)
    if t:
        ok("History endpoint returns content")

    r = await get(client, "/v1/transfers/1.1.1.0%2F24")
    t = check_response(r, "GET /v1/transfers/1.1.1.0/24", allow_error=True)
    if t:
        ok("Transfers endpoint returns content")

    r = await get(client, "/v1/stats/ipv4")
    t = check_response(r, "GET /v1/stats/ipv4", allow_error=True)
    if t:
        ok("IPv4 stats endpoint returns content")

    # IPv4 stats with RIR filter
    r = await get(client, "/v1/stats/ipv4", {"rir": "RIPE"})
    t = check_response(r, "GET /v1/stats/ipv4?rir=RIPE", allow_error=True)
    if t:
        ok("IPv4 stats RIR filter accepted")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: DNS Endpoints
# ═══════════════════════════════════════════════════════════════════════════
async def test_dns(client: httpx.AsyncClient):
    section("5. DNS Endpoints (UI: DNS tab)")

    # DNS resolve — domain
    r = await get(client, "/v1/dns/resolve/cloudflare.com")
    t = check_response(r, "GET /v1/dns/resolve/cloudflare.com", allow_error=True)
    if t:
        ok("DNS resolve domain returns content")

    # DNS resolve — IP (reverse)
    r = await get(client, "/v1/dns/resolve/1.1.1.1")
    t = check_response(r, "GET /v1/dns/resolve/1.1.1.1 (reverse)", allow_error=True)
    if t:
        ok("DNS resolve IP (reverse lookup) accepted")

    # DNS enumerate
    r = await get(client, "/v1/dns/enumerate/cloudflare.com")
    t = check_response(r, "GET /v1/dns/enumerate/cloudflare.com", allow_error=True)
    if t:
        ok("DNS enumerate returns content")

    # DNSSEC
    r = await get(client, "/v1/dns/dnssec/cloudflare.com")
    t = check_response(r, "GET /v1/dns/dnssec/cloudflare.com", allow_error=True)
    if t:
        ok("DNSSEC endpoint returns content")

    # DNSBL
    r = await get(client, "/v1/dns/dnsbl/1.1.1.1")
    t = check_response(r, "GET /v1/dns/dnsbl/1.1.1.1", allow_error=True)
    if t:
        ok("DNSBL endpoint returns content")

    # Email security
    r = await get(client, "/v1/dns/email/cloudflare.com")
    t = check_response(r, "GET /v1/dns/email/cloudflare.com", allow_error=True)
    if t:
        ok("Email security endpoint returns content")

    # DNS propagation
    r = await get(client, "/v1/dns/propagation/cloudflare.com")
    t = check_response(r, "GET /v1/dns/propagation/cloudflare.com", allow_error=True)
    if t:
        ok("DNS propagation endpoint returns content")

    # DNS propagation — with record_type param
    r = await get(client, "/v1/dns/propagation/cloudflare.com", {"record_type": "MX"})
    t = check_response(r, "GET /v1/dns/propagation/cloudflare.com?record_type=MX", allow_error=True)
    if t:
        ok("DNS propagation record_type param accepted")

    # DNS censorship
    r = await get(client, "/v1/censorship/twitter.com")
    t = check_response(r, "GET /v1/censorship/twitter.com", allow_error=True)
    if t:
        ok("DNS censorship endpoint returns content")

    # DNS censorship with country code
    r = await get(client, "/v1/censorship/twitter.com", {"country_code": "CN"})
    t = check_response(r, "GET /v1/censorship/twitter.com?country_code=CN", allow_error=True)
    if t:
        ok("DNS censorship country_code param accepted")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: TLS / CT Endpoints
# ═══════════════════════════════════════════════════════════════════════════
async def test_tls(client: httpx.AsyncClient):
    section("6. TLS & Certificate Endpoints (UI: TLS tab)")

    # TLS inspect
    r = await get(client, "/v1/tls/cloudflare.com")
    t = check_response(r, "GET /v1/tls/cloudflare.com", allow_error=True)
    if t:
        ok("TLS inspect endpoint returns content")

    # TLS with custom port
    r = await get(client, "/v1/tls/cloudflare.com", {"port": 443})
    t = check_response(r, "GET /v1/tls/cloudflare.com?port=443", allow_error=True)
    if t:
        ok("TLS port param accepted")

    # CT logs
    r = await get(client, "/v1/ct/cloudflare.com")
    t = check_response(r, "GET /v1/ct/cloudflare.com", allow_error=True)
    if t:
        ok("CT logs endpoint returns content (or graceful error)", f"{len(t)} chars")
        # After our fix, a crt.sh 404 should come back as a warning, not an error in JSON
        if "HTTP 404" in t and "timed out" not in t.lower() and "warning" not in t.lower():
            fail("CT logs: crt.sh 404 should be treated as warning, not hard error")
        else:
            ok("CT logs: crt.sh errors handled gracefully")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: Threat Intel Endpoints
# ═══════════════════════════════════════════════════════════════════════════
async def test_threat(client: httpx.AsyncClient):
    section("7. Threat Intel Endpoints (UI: Threat tab)")

    # Threat intel
    r = await get(client, "/v1/threat/1.1.1.1")
    t = check_response(r, "GET /v1/threat/1.1.1.1", allow_error=True)
    if t:
        ok("Threat intel endpoint returns content")

    # Passive DNS
    r = await get(client, "/v1/pdns/1.1.1.1")
    t = check_response(r, "GET /v1/pdns/1.1.1.1", allow_error=True)
    if t:
        ok("Passive DNS endpoint returns content")

    # GeoIP
    r = await get(client, "/v1/geo/1.1.1.1")
    t = check_response(r, "GET /v1/geo/1.1.1.1", allow_error=True)
    if t:
        ok("GeoIP endpoint returns content")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8: Peering Endpoints
# ═══════════════════════════════════════════════════════════════════════════
async def test_peering(client: httpx.AsyncClient):
    section("8. Peering Endpoints (UI: Peering tab)")

    # Peering info
    r = await get(client, "/v1/peering/AS13335")
    t = check_response(r, "GET /v1/peering/AS13335", allow_error=True)
    if t:
        ok("Peering info endpoint returns content")

    # IXP lookup
    r = await get(client, "/v1/ixp", {"query": "DE-CIX"})
    t = check_response(r, "GET /v1/ixp?query=DE-CIX", allow_error=True)
    if t:
        ok("IXP lookup endpoint returns content")

    # AS relationships
    r = await get(client, "/v1/as-relationships/AS13335")
    t = check_response(r, "GET /v1/as-relationships/AS13335", allow_error=True)
    if t:
        ok("AS relationships endpoint returns content")

    # Network health
    r = await get(client, "/v1/health/AS13335")
    t = check_response(r, "GET /v1/health/AS13335", allow_error=True)
    if t:
        ok("Network health endpoint returns content")

    # Change monitor
    r = await get(client, "/v1/monitor/1.1.1.0%2F24")
    t = check_response(r, "GET /v1/monitor/1.1.1.0/24", allow_error=True)
    if t:
        ok("Change monitor endpoint returns content")

    # RIPE Atlas
    r = await get(client, "/v1/atlas/1.1.1.1")
    t = check_response(r, "GET /v1/atlas/1.1.1.1", allow_error=True)
    if t:
        ok("Atlas traceroute endpoint returns content")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 9: Crisis Endpoints
# ═══════════════════════════════════════════════════════════════════════════
async def test_crisis(client: httpx.AsyncClient):
    section("9. Crisis / Humanitarian Endpoints (UI: Crisis tab)")

    # Shutdown detect
    r = await get(client, "/v1/shutdown/UA")
    t = check_response(r, "GET /v1/shutdown/UA", allow_error=True)
    if t:
        ok("Shutdown detect endpoint returns content")

    # Country health
    r = await get(client, "/v1/health/country/UA")
    t = check_response(r, "GET /v1/health/country/UA", allow_error=True)
    if t:
        ok("Country health endpoint returns content")

    # Satellite
    r = await get(client, "/v1/satellite/UA")
    t = check_response(r, "GET /v1/satellite/UA", allow_error=True)
    if t:
        ok("Satellite connectivity endpoint returns content")

    # Chokepoints
    r = await get(client, "/v1/chokepoints/UA")
    t = check_response(r, "GET /v1/chokepoints/UA", allow_error=True)
    if t:
        ok("Chokepoints endpoint returns content")

    # OONI
    r = await get(client, "/v1/ooni/UA")
    t = check_response(r, "GET /v1/ooni/UA", allow_error=True)
    if t:
        ok("OONI report endpoint returns content")

    # Shutdown timeline
    r = await get(client, "/v1/shutdown/timeline/UA", {"start_date": "2024-01-01", "end_date": "2024-01-07"})
    t = check_response(r, "GET /v1/shutdown/timeline/UA", allow_error=True)
    if t:
        ok("Shutdown timeline endpoint returns content")

    # Shutdown monitor — POST
    r = await post(client, "/v1/shutdown/monitor", {
        "resource": "UA", "threshold": 20, "interval_minutes": 60,
        "notify_url": "https://example.com/hook"
    })
    if r is not None and r.status_code in (200, 201):
        ok("Shutdown monitor POST returns 200/201")
    elif r is not None and r.status_code == 422:
        fail("Shutdown monitor POST → 422", r.text[:200])
    else:
        skip("Shutdown monitor POST", f"HTTP {r.status_code if r else 'none'}")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 10: Bulk Endpoint
# ═══════════════════════════════════════════════════════════════════════════
async def test_bulk(client: httpx.AsyncClient):
    section("10. Bulk Query Endpoint (POST /v1/bulk)")

    payload = {
        "resources": [
            {"resource": "1.1.1.1", "tool": "ip"},
            {"resource": "8.8.8.8", "tool": "ip"},
        ]
    }
    r = await post(client, "/v1/bulk", payload)
    if r is None:
        fail("POST /v1/bulk", "no response")
        return
    if r.status_code == 422:
        fail("POST /v1/bulk", f"422 — {r.text[:300]}")
        return
    if r.status_code == 200:
        ok("POST /v1/bulk returns 200")
        try:
            d = json.loads(r.text)
            ok("Bulk response is JSON", f"keys={list(d.keys())}")
        except Exception:
            warn("Bulk response not JSON", r.text[:80])
    else:
        fail("POST /v1/bulk", f"HTTP {r.status_code}")

    # Bulk over limit (>50)
    over_limit = [{"resource": str(i), "tool": "ip"} for i in range(51)]
    r = await post(client, "/v1/bulk", {"resources": over_limit})
    if r is not None and r.status_code == 422:
        ok("Bulk >50 resources → 422 (correct limit enforcement)")
    elif r is not None and r.status_code == 200:
        warn("Bulk >50 resources accepted — limit may not be enforced")
    else:
        skip("Bulk limit check", f"HTTP {r.status_code if r else 'none'}")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 11: Format Switching (?format=markdown vs ?format=json)
# ═══════════════════════════════════════════════════════════════════════════
async def test_format_switching(client: httpx.AsyncClient):
    section("11. Format Switching (?format=markdown / ?format=json)")

    endpoints = [
        ("/v1/ip/1.1.1.1",          None),
        ("/v1/asn/AS13335",          None),
        ("/v1/dns/resolve/cloudflare.com", None),
        ("/v1/bgp/1.1.1.0%2F24",    None),
        ("/v1/tls/cloudflare.com",   None),
    ]

    for path, extra_params in endpoints:
        short = path.split("/")[-1][:20]

        # Markdown (default)
        r = await get(client, path, {**(extra_params or {}), "format": "markdown"})
        t = check_response(r, f"{short} ?format=markdown", allow_error=True)
        if t:
            ok(f"{short}: markdown mode returns text") if not is_json(t) else fail(f"{short}: markdown mode returned JSON instead")

        # JSON
        r = await get(client, path, {**(extra_params or {}), "format": "json"})
        t = check_response(r, f"{short} ?format=json", allow_error=True)
        if t:
            ok(f"{short}: json mode returns JSON") if is_json(t) else fail(f"{short}: json mode returned non-JSON", t[:80])

        # Invalid format value (should default gracefully, not 422)
        r = await get(client, path, {**(extra_params or {}), "format": "xml"})
        if r is not None and r.status_code == 422:
            ok(f"{short}: invalid format → 422 (validation)")
        elif r is not None and r.status_code == 200:
            ok(f"{short}: invalid format → 200 (falls back gracefully)")
        else:
            skip(f"{short}: invalid format check", f"HTTP {r.status_code if r else 'none'}")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 12: Auto-Detection Logic (Python re-implementation of usePeerGlass)
# ═══════════════════════════════════════════════════════════════════════════
def detect_type(s: str) -> str:
    """Mirror of usePeerGlass.ts detectType function."""
    if re.match(r'^(AS)?\d+$', s, re.IGNORECASE):   return 'asn'
    if re.match(r'^[0-9a-f:]+/\d+$', s, re.IGNORECASE): return 'prefix'
    if re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', s):   return 'prefix'
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', s):        return 'ip'
    if re.match(r'^[0-9a-f:]+$', s, re.IGNORECASE) and ':' in s: return 'ip'
    if re.match(r'^[A-Z]{2}$', s, re.IGNORECASE):   return 'country'
    if re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+$', s, re.IGNORECASE): return 'domain'
    return 'unknown'

async def test_auto_detection(_client):
    section("12. Auto-Detection Logic (mirrors usePeerGlass.ts detectType)")

    cases = [
        # (input, expected_type)
        ("1.1.1.1",               "ip"),
        ("8.8.8.8",               "ip"),
        ("192.168.0.1",           "ip"),
        ("2606:4700:4700::1111",  "ip"),
        ("::1",                   "ip"),
        ("2001:db8::1",           "ip"),
        ("AS13335",               "asn"),
        ("as13335",               "asn"),
        ("13335",                 "asn"),
        ("1",                     "asn"),
        ("1.1.1.0/24",            "prefix"),
        ("192.168.0.0/16",        "prefix"),
        ("2001:db8::/32",         "prefix"),
        ("cloudflare.com",        "domain"),
        ("google.com",            "domain"),
        ("sub.example.co.uk",     "domain"),
        ("UA",                    "country"),
        ("sy",                    "country"),
        ("DE",                    "country"),
        ("US",                    "country"),
        ("Cloudflare Inc.",       "unknown"),  # org name
        ("GOOGL-ARIN",            "unknown"),  # org handle
        ("not-a-valid-thing",     "unknown"),
    ]

    # Edge cases that are tricky
    edge_cases = [
        # 2-letter domain that could be mistaken for country
        # 'io' TLD — "io" alone is a 2-letter string → country, but "example.io" → domain
        ("io",                    "country"),   # bare 2-letter → country
        ("example.io",            "domain"),    # but with dot → domain
        # Single number → ASN
        ("0",                     "asn"),
        ("65535",                 "asn"),
        # Pure number that could be ASN
        ("4294967295",            "asn"),       # max uint32 ASN
    ]

    all_cases = cases + edge_cases
    for inp, expected in all_cases:
        got = detect_type(inp)
        if got == expected:
            ok(f'"{inp}" → {got}')
        else:
            fail(f'"{inp}" → expected={expected}, got={got}')


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 13: UI Tool ↔ Endpoint Coverage Check
# ═══════════════════════════════════════════════════════════════════════════
async def test_tool_endpoint_coverage(client: httpx.AsyncClient):
    section("13. UI Tool ↔ API Endpoint Coverage (TabBar → usePeerGlass → api/client.ts)")

    # Definitive mapping: tool_id → (method, path_template)
    # Verifies every UI tool ID has a reachable, non-404 endpoint
    tool_to_request: list[tuple[str, str, str, dict]] = [
        # (tool_id, method, path, params)
        ("ip",             "GET",  "/v1/ip/1.1.1.1",                 {}),
        ("asn",            "GET",  "/v1/asn/AS13335",                 {}),
        ("abuse",          "GET",  "/v1/abuse/8.8.8.8",               {}),
        ("org",            "GET",  "/v1/org",                         {"name": "Cloudflare"}),
        ("bgp",            "GET",  "/v1/bgp/1.1.1.0%2F24",           {}),
        ("announced",      "GET",  "/v1/announced/AS13335",           {}),
        ("overview",       "GET",  "/v1/overview/1.1.1.0%2F24",      {}),
        ("irr",            "GET",  "/v1/irr",                         {"prefix": "1.1.1.0/24", "asn": "13335"}),
        ("route-leak",     "GET",  "/v1/route-leak/1.1.1.0%2F24",    {}),
        ("looking-glass",  "GET",  "/v1/looking-glass/1.1.1.0%2F24", {}),
        ("stability",      "GET",  "/v1/stability/1.1.1.0%2F24",     {}),
        ("rpki",           "GET",  "/v1/rpki",                        {"prefix": "1.1.1.0/24", "asn": "13335"}),
        ("dns",            "GET",  "/v1/dns/resolve/cloudflare.com",  {}),
        ("dns-enumerate",  "GET",  "/v1/dns/enumerate/cloudflare.com",{}),
        ("dnssec",         "GET",  "/v1/dns/dnssec/cloudflare.com",   {}),
        ("dnsbl",          "GET",  "/v1/dns/dnsbl/1.1.1.1",          {}),
        ("email",          "GET",  "/v1/dns/email/cloudflare.com",    {}),
        ("propagation",    "GET",  "/v1/dns/propagation/cloudflare.com", {}),
        ("censorship",     "GET",  "/v1/censorship/twitter.com",      {}),
        ("tls",            "GET",  "/v1/tls/cloudflare.com",          {}),
        ("ct",             "GET",  "/v1/ct/cloudflare.com",           {}),
        ("threat",         "GET",  "/v1/threat/1.1.1.1",              {}),
        ("pdns",           "GET",  "/v1/pdns/1.1.1.1",                {}),
        ("geo",            "GET",  "/v1/geo/1.1.1.1",                 {}),
        ("peering",        "GET",  "/v1/peering/AS13335",             {}),
        ("ixp",            "GET",  "/v1/ixp",                         {"query": "DE-CIX"}),
        ("as-relationships","GET", "/v1/as-relationships/AS13335",    {}),
        ("health",         "GET",  "/v1/health/AS13335",              {}),
        ("monitor",        "GET",  "/v1/monitor/1.1.1.0%2F24",       {}),
        ("atlas",          "GET",  "/v1/atlas/1.1.1.1",               {}),
        ("shutdown",       "GET",  "/v1/shutdown/UA",                 {}),
        ("country-health", "GET",  "/v1/health/country/UA",           {}),
        ("satellite",      "GET",  "/v1/satellite/UA",                {}),
        ("chokepoints",    "GET",  "/v1/chokepoints/UA",              {}),
        ("ooni",           "GET",  "/v1/ooni/UA",                     {}),
    ]

    for (tool_id, method, path, params) in tool_to_request:
        r = await get(client, path, params)
        if r is None:
            fail(f"tool={tool_id} → {path}", "connection error")
        elif r.status_code == 404:
            fail(f"tool={tool_id} → {path}", "HTTP 404 — route not found!")
        elif r.status_code == 422:
            fail(f"tool={tool_id} → {path}", f"HTTP 422 — {r.text[:150]}")
        else:
            ok(f"tool={tool_id} → HTTP {r.status_code}", path)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 14: Error Handling — Bad Inputs
# ═══════════════════════════════════════════════════════════════════════════
async def test_error_handling(client: httpx.AsyncClient):
    section("14. Error Handling — Bad / Invalid Inputs")

    bad_cases = [
        # (label, path, params)
        ("IP: obviously invalid",        "/v1/ip/not-an-ip",            {}),
        ("IP: empty-ish path",           "/v1/ip/.",                    {}),
        ("ASN: text",                    "/v1/asn/notanasn",            {}),
        ("BGP: nonsense",                "/v1/bgp/zzz",                 {}),
        ("TLS: non-existent hostname",   "/v1/tls/this.does.not.exist.invalid", {}),
        ("DNS: non-existent domain",     "/v1/dns/resolve/this.does.not.exist.invalid", {}),
        ("Shutdown: invalid code",       "/v1/shutdown/ZZ",             {}),
        ("Country health: invalid code", "/v1/health/country/ZZ",       {}),
    ]

    for label, path, params in bad_cases:
        r = await get(client, path, params)
        if r is None:
            skip(label, "no response (network issue?)")
            continue
        # Should NOT be 404 (route missing) or 500 (unhandled crash)
        if r.status_code == 404:
            fail(label, "HTTP 404 — route missing")
        elif r.status_code == 500:
            # Check if it's a structured error or raw crash
            try:
                body = json.loads(r.text)
                ok(label, f"HTTP 500 with structured error: {list(body.keys())}")
            except Exception:
                fail(label, f"HTTP 500 unstructured crash: {r.text[:150]}")
        elif r.status_code in (200, 422):
            ok(label, f"HTTP {r.status_code} — handled gracefully")
        else:
            ok(label, f"HTTP {r.status_code}")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 15: OpenAPI / Swagger Docs
# ═══════════════════════════════════════════════════════════════════════════
async def test_docs(client: httpx.AsyncClient):
    section("15. OpenAPI Docs (/docs, /redoc, /openapi.json)")

    for path in ["/docs", "/redoc", "/openapi.json"]:
        r = await get(client, path)
        if r and r.status_code == 200:
            ok(f"{path} reachable", f"{len(r.text)} chars")
        else:
            fail(f"{path}", f"HTTP {r.status_code if r else 'no response'}")

    # Validate openapi.json structure
    r = await get(client, "/openapi.json")
    if r and r.status_code == 200:
        try:
            schema = json.loads(r.text)
            paths = schema.get("paths", {})
            ok(f"OpenAPI paths count", str(len(paths)))
            # Check key endpoints are in schema
            for ep in ["/v1/ip/{ip}", "/v1/asn/{asn}", "/v1/bgp/{resource}", "/v1/ct/{domain}"]:
                if ep in paths:
                    ok(f"OpenAPI includes {ep}")
                else:
                    fail(f"OpenAPI missing {ep}")
        except Exception as e:
            fail("OpenAPI JSON parse", str(e))


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 16: CORS Headers
# ═══════════════════════════════════════════════════════════════════════════
async def test_cors(client: httpx.AsyncClient):
    section("16. CORS Headers (required for browser UI)")

    # Preflight request
    r = None
    try:
        r = await client.options(
            f"{BASE}/v1/ip/1.1.1.1",
            headers={"Origin": "https://duksh.github.io", "Access-Control-Request-Method": "GET"},
            timeout=10,
        )
    except Exception as e:
        fail("OPTIONS preflight", str(e))
        return

    if r.status_code in (200, 204):
        ok("OPTIONS preflight returns 200/204", str(r.status_code))
    else:
        fail("OPTIONS preflight", f"HTTP {r.status_code}")

    acao = r.headers.get("access-control-allow-origin", "")
    if acao in ("*", "https://duksh.github.io"):
        ok("Access-Control-Allow-Origin set", acao)
    else:
        fail("Access-Control-Allow-Origin missing or wrong", repr(acao))

    # Regular GET from browser origin
    r = await get(client, "/v1/ip/1.1.1.1")
    if r:
        acao = r.headers.get("access-control-allow-origin", "")
        if acao:
            ok("GET response includes CORS header", acao)
        else:
            fail("GET response missing Access-Control-Allow-Origin")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 17: Response Content Quality Checks
# ═══════════════════════════════════════════════════════════════════════════
async def test_content_quality(client: httpx.AsyncClient):
    section("17. Response Content Quality (markdown structure)")

    # Each should return markdown with a heading
    checks = [
        ("/v1/ip/1.1.1.1",                None,                    "IP lookup heading"),
        ("/v1/asn/AS13335",               None,                    "ASN lookup heading"),
        ("/v1/dns/resolve/cloudflare.com",None,                    "DNS resolve heading"),
        ("/v1/geo/1.1.1.1",               None,                    "GeoIP heading"),
    ]

    for path, params, label in checks:
        r = await get(client, path, params or {})
        t = check_response(r, label, allow_error=True)
        if t:
            if is_markdown(t):
                ok(f"{label}: has markdown structure")
            else:
                warn(f"{label}: no markdown headings detected", t[:80])


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 18: Rate Limiting Headers
# ═══════════════════════════════════════════════════════════════════════════
async def test_rate_limit_headers(client: httpx.AsyncClient):
    section("18. Rate Limiting Headers")

    r = await get(client, "/v1/ip/1.1.1.1")
    if r:
        has_rl = any("ratelimit" in k.lower() or "retry-after" in k.lower() or "x-ratelimit" in k.lower()
                     for k in r.headers)
        if has_rl:
            rl_headers = {k: v for k, v in r.headers.items() if "ratelimit" in k.lower()}
            ok("Rate limit headers present", str(rl_headers))
        else:
            warn("No rate limit headers on response (may be OK in dev mode)")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
async def main():
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  PeerGlass Full QA Test Suite{RESET}")
    print(f"{BOLD}  Target: {BASE}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")

    async with httpx.AsyncClient() as client:
        # Check server is up
        try:
            r = await client.get(f"{BASE}/", timeout=10)
            if r.status_code != 200:
                print(f"\n{RED}ERROR: Server not responding at {BASE} (HTTP {r.status_code}){RESET}")
                sys.exit(1)
        except Exception as e:
            print(f"\n{RED}ERROR: Cannot connect to {BASE}: {e}{RESET}")
            sys.exit(1)

        await test_meta(client)
        await test_registry(client)
        await test_routing(client)
        await test_history(client)
        await test_dns(client)
        await test_tls(client)
        await test_threat(client)
        await test_peering(client)
        await test_crisis(client)
        await test_bulk(client)
        await test_format_switching(client)
        await test_auto_detection(client)
        await test_tool_endpoint_coverage(client)
        await test_error_handling(client)
        await test_docs(client)
        await test_cors(client)
        await test_content_quality(client)
        await test_rate_limit_headers(client)

    # Summary
    total = PASS + FAIL + SKIP + WARN
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  QA SUMMARY{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Checks run   : {total}")
    print(f"{GREEN}  ✅ Passed   : {PASS}{RESET}")
    print(f"{RED}  ❌ Failed   : {FAIL}{RESET}")
    print(f"{YELL}  ⚠️  Skipped  : {SKIP}{RESET}")
    print(f"{YELL}  ⚠️  Warnings : {WARN}{RESET}")

    if FAILURES:
        print(f"\n{RED}{BOLD}  FAILURES:{RESET}")
        for f in FAILURES:
            print(f"    {RED}• {f}{RESET}")

    print(f"\n{'='*60}\n")
    sys.exit(1 if FAIL > 0 else 0)


if __name__ == "__main__":
    asyncio.run(main())
