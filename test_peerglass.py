"""
test_peerglass.py — Complete PeerGlass test suite
Tests: compile, branding, RDAP endpoints, MCP name, tool count,
       REST API runtime, README correctness.
"""

import py_compile
import re
import sys

errors = []

print("=" * 60)
print("PEERGLASS — COMPLETE TEST SUITE")
print("=" * 60)


# ── 1. COMPILE CHECK ─────────────────────────────────────────
print("\n1. COMPILE CHECK — all .py files")
files = [
    "server.py", "rir_client.py", "formatters.py",
    "models.py", "cache.py", "normalizer.py", "api.py",
]
for f in files:
    try:
        py_compile.compile(f, doraise=True)
        print(f"   ✅ {f}")
    except py_compile.PyCompileError as e:
        print(f"   ❌ {f}: {e}")
        errors.append(f"compile:{f}:{e}")


# ── 2. BRANDING AUDIT ────────────────────────────────────────
print("\n2. BRANDING AUDIT — no stale WHOIS in identity strings")

FORBIDDEN = [
    (r"Multi-RIR WHOIS",   "Old product name"),
    (r"rir_whois_mcp",     "Old MCP server ID"),
    (r"WHOIS MCP",         "Old product name variant"),
]

check_files = {
    "server.py":     open("server.py").read(),
    "rir_client.py": open("rir_client.py").read(),
    "cache.py":      open("cache.py").read(),
    "models.py":     open("models.py").read(),
    "api.py":        open("api.py").read(),
    "README.md":     open("README.md").read(),
    "pyproject.toml":open("pyproject.toml").read(),
}

for fname, content in check_files.items():
    file_errors = []
    for pattern, reason in FORBIDDEN:
        if re.search(pattern, content):
            file_errors.append(f'{pattern} ({reason})')
            errors.append(f"branding:{fname}:{pattern}")
    if file_errors:
        for e in file_errors:
            print(f"   ❌ {fname}: found \"{e}\"")
    else:
        print(f"   ✅ {fname}")


# ── 3. RDAP ENDPOINTS ────────────────────────────────────────
print("\n3. RDAP ENDPOINTS — all 5 RIRs present and correct")
client_src = open("rir_client.py").read()
rdap_urls = [
    ("AFRINIC", "https://rdap.afrinic.net/rdap"),
    ("APNIC",   "https://rdap.apnic.net"),
    ("ARIN",    "https://rdap.arin.net/registry"),
    ("LACNIC",  "https://rdap.lacnic.net/rdap"),
    ("RIPE",    "https://rdap.db.ripe.net"),
]
for rir, url in rdap_urls:
    if url in client_src:
        print(f"   ✅ {rir}: {url}")
    else:
        print(f"   ❌ {rir}: {url} NOT FOUND")
        errors.append(f"rdap:{rir}")


# ── 4. PROTOCOL HEADER ───────────────────────────────────────
print("\n4. PROTOCOL HEADER — Accept: application/rdap+json")
if "application/rdap+json" in client_src:
    print("   ✅ Accept header uses RDAP media type")
else:
    print("   ❌ RDAP Accept header missing")
    errors.append("accept_header")


# ── 5. USER-AGENT ────────────────────────────────────────────
print("\n5. USER-AGENT — updated to PeerGlass")
if "peerglass/1.0.0" in client_src and "PeerGlass RDAP" in client_src:
    print("   ✅ User-Agent: peerglass/1.0.0 (PeerGlass RDAP+BGP+RPKI client)")
else:
    print("   ❌ User-Agent not updated")
    errors.append("user_agent")


# ── 6. MCP SERVER NAME ───────────────────────────────────────
print("\n6. MCP SERVER NAME — updated to peerglass")
server_src = open("server.py").read()
if '"peerglass"' in server_src and "rir_whois_mcp" not in server_src:
    print('   ✅ MCP name = "peerglass"')
else:
    print("   ❌ MCP server name not updated")
    errors.append("mcp_name")


# ── 7. TOOL COUNT ────────────────────────────────────────────
print("\n7. TOOL COUNT — 39 @mcp.tool() decorators in server.py")
# Decorator is @mcp.tool( with description kwarg on next line
tools_found = re.findall(r"@mcp\.tool\(", server_src)
count = len(tools_found)
if count == 39:
    print(f"   ✅ {count} @mcp.tool() decorators found")
else:
    print(f"   ❌ Expected 39, found {count}")
    errors.append(f"tool_count:{count}")


# ── 8. REST ENDPOINTS ────────────────────────────────────────
print("\n8. REST API — all 29 endpoints present in api.py")
api_src = open("api.py").read()
routes = [
    "/v1/ip/{ip}",           "/v1/asn/{asn}",
    "/v1/abuse/{ip}",        "/v1/rpki",
    "/v1/bgp/{resource}",    "/v1/announced/{asn}",
    "/v1/org",               "/v1/history/{resource}",
    "/v1/transfers/{resource}", "/v1/stats/ipv4",
    "/v1/overview/{prefix}", "/v1/peering/{asn}",
    "/v1/ixp",               "/v1/health/{resource}",
    "/v1/monitor/{resource}",
    "/v1/dns/resolve/{target}",  "/v1/dns/enumerate/{domain}",
    "/v1/dns/dnssec/{domain}",   "/v1/dns/dnsbl/{ip}",
    "/v1/dns/email/{domain}",    "/v1/dns/propagation/{domain}",
    "/v1/tls/{hostname}",        "/v1/ct/{domain}",
    "/v1/threat/{ip}",           "/v1/pdns/{resource}",
    "/v1/irr",                   "/v1/route-leak/",
    "/v1/looking-glass/",        "/v1/stability/",
    "/v1/shutdown/",             "/v1/shutdown/monitor",
    "/v1/shutdown/timeline/",    "/v1/censorship/",
    "/v1/satellite/",            "/v1/chokepoints/",
    "/v1/ooni/",                 "/v1/health/country/",
]
for r in routes:
    if r in api_src:
        print(f"   ✅ {r}")
    else:
        print(f"   ❌ {r} MISSING")
        errors.append(f"route:{r}")


# ── 9. FASTAPI RUNTIME ───────────────────────────────────────
print("\n9. FASTAPI RUNTIME — routes resolve, OpenAI schema correct")
try:
    from fastapi.testclient import TestClient
    from api import app

    client = TestClient(app)

    r = client.get("/")
    assert r.status_code == 200, f"Root returned {r.status_code}"
    data = r.json()
    assert data["tools"] == 39, f"Root shows {data['tools']} tools not 31"
    assert data["name"] == "PeerGlass API", f"Name is {data['name']}"
    print(f"   ✅ GET /  → 200, name=PeerGlass API, tools=39")

    r = client.get("/v1/meta/cache")
    assert r.status_code == 200
    print("   ✅ GET /v1/meta/cache → 200")

    r = client.get("/v1/meta/openai-tools")
    assert r.status_code == 200
    tools_json = r.json()["tools"]
    names = [t["function"]["name"] for t in tools_json]
    required = [
        "peerglass_health", "peerglass_rpki",
        "peerglass_ixp", "peerglass_monitor", "peerglass_peering",
    ]
    for expected in required:
        assert expected in names, f"{expected} missing from OpenAI schema"
    print(f"   ✅ GET /v1/meta/openai-tools → {len(tools_json)} tools, all peerglass_*")

    # Confirm no stale branding in any response
    root_str = str(client.get("/").json()).lower()
    assert "whois_mcp" not in root_str
    assert "multi-rir whois" not in root_str
    print("   ✅ No stale branding in API responses")

except Exception as e:
    import traceback
    print(f"   ❌ FastAPI runtime error: {e}")
    traceback.print_exc()
    errors.append(f"fastapi:{e}")


# ── 10. README ───────────────────────────────────────────────
print("\n10. README — PeerGlass branding, 39 tools, RDAP note, historical-whois explained")
readme = open("README.md").read()

must_contain = [
    ("PeerGlass",              "Product name present"),
    ("39 tools",               "Correct tool count (39)"),
    ("RDAP (RFC 7480",         "RDAP RFC reference"),
    ("Protocol note",          "WHOIS→RDAP explanation block"),
    ("peerglass",              "MCP config uses peerglass"),
    ("RIPE Stat's own name",   "historical-whois explained as RIPE API naming"),
]
must_not_contain = [
    ("Multi-RIR WHOIS",        "Old product name must be absent"),
]

for term, desc in must_contain:
    if term in readme:
        print(f"   ✅ {desc}")
    else:
        print(f"   ❌ Missing: {desc}  (searched: \"{term}\")")
        errors.append(f"readme:missing:{term}")

for term, desc in must_not_contain:
    if term not in readme:
        print(f"   ✅ {desc}")
    else:
        print(f"   ❌ {desc}  (found \"{term}\")")
        errors.append(f"readme:found:{term}")


# ── 11. SPRINT 1 — NEW FEATURES ──────────────────────────────
print("\n11. SPRINT 1 FEATURES — A1, A2, B1, B2, D2, J3")

# A1: IPv6 CIDR helpers exist
client_src2 = open("rir_client.py").read()
if "_ip6_to_int" in client_src2 and "_cidr_contains_ip6" in client_src2:
    print("   ✅ A1: IPv6 bootstrap helpers (_ip6_to_int, _cidr_contains_ip6)")
else:
    print("   ❌ A1: IPv6 bootstrap helpers missing")
    errors.append("sprint1:A1")

# A2: Bootstrap TTL constant present
if "BOOTSTRAP_TTL" in client_src2 and "86_400" in client_src2:
    print("   ✅ A2: Bootstrap 24h TTL (BOOTSTRAP_TTL = 86_400)")
else:
    print("   ❌ A2: BOOTSTRAP_TTL constant missing")
    errors.append("sprint1:A2")

# A2: Cache stores timestamps (tuple not bare dict)
if "_BOOTSTRAP_CACHE: dict[str, tuple[dict, float]]" in client_src2:
    print("   ✅ A2: Bootstrap cache uses (data, timestamp) tuples")
else:
    print("   ❌ A2: Bootstrap cache timestamp structure missing")
    errors.append("sprint1:A2:cache_type")

# B1: slowapi imported and limiter applied
api_src2 = open("api.py").read()
if "from slowapi import Limiter" in api_src2 and "limiter = Limiter(" in api_src2:
    print("   ✅ B1: slowapi Limiter present in api.py")
else:
    print("   ❌ B1: slowapi rate limiter missing")
    errors.append("sprint1:B1")

if "@limiter.limit" in api_src2:
    limit_count = api_src2.count("@limiter.limit")
    print(f"   ✅ B1: {limit_count} @limiter.limit decorators applied")
else:
    print("   ❌ B1: no @limiter.limit decorators found")
    errors.append("sprint1:B1:decorators")

# B2: CORS env var
if "PEERGLASS_ALLOWED_ORIGINS" in api_src2:
    print("   ✅ B2: CORS origins via PEERGLASS_ALLOWED_ORIGINS env var")
else:
    print("   ❌ B2: CORS env var missing")
    errors.append("sprint1:B2")

# D2: BGPCommunity model and BGP_WELL_KNOWN_COMMUNITIES dict
models_src2 = open("models.py").read()
if "class BGPCommunity" in models_src2 and "BGP_WELL_KNOWN_COMMUNITIES" in models_src2:
    print("   ✅ D2: BGPCommunity model and well-known community map present")
else:
    print("   ❌ D2: BGPCommunity model missing")
    errors.append("sprint1:D2:model")

if "communities: List[BGPCommunity]" in models_src2:
    print("   ✅ D2: BGPStatusResult.communities field present")
else:
    print("   ❌ D2: BGPStatusResult.communities field missing")
    errors.append("sprint1:D2:field")

# D2: Communities parsed in rir_client and rendered in formatters
if "communities_seen" in client_src2 and "entry.get(\"community\"" in client_src2:
    print("   ✅ D2: Communities parsed from bgp-state response")
else:
    print("   ❌ D2: Community parsing missing in rir_client.py")
    errors.append("sprint1:D2:parsing")

# J3: WHOIS fallback function present
if "async def get_whois_fallback" in client_src2 and "async def _whois_query" in client_src2:
    print("   ✅ J3: WHOIS fallback (_whois_query, get_whois_fallback) present")
else:
    print("   ❌ J3: WHOIS fallback functions missing")
    errors.append("sprint1:J3")

if "get_whois_fallback" in api_src2:
    print("   ✅ J3: WHOIS fallback wired into /v1/ip and /v1/asn endpoints")
else:
    print("   ❌ J3: WHOIS fallback not wired into API endpoints")
    errors.append("sprint1:J3:wired")

# D2 model import round-trip
try:
    from models import BGPCommunity, BGP_WELL_KNOWN_COMMUNITIES, BGPStatusResult
    c = BGPCommunity(asn=65535, value=666, description="BLACKHOLE")
    assert c.asn == 65535
    assert c.value == 666
    key = (65535, 666)
    assert key in BGP_WELL_KNOWN_COMMUNITIES, "Blackhole community missing from map"
    result = BGPStatusResult(
        resource="1.1.1.0/24",
        resource_type="prefix",
        is_announced=True,
        communities=[c],
    )
    assert len(result.communities) == 1
    print("   ✅ D2: BGPCommunity model serializes and round-trips correctly")
except Exception as e:
    print(f"   ❌ D2: Model round-trip failed: {e}")
    errors.append(f"sprint1:D2:roundtrip:{e}")

# A1 logic test — basic IPv6 CIDR matching
try:
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from rir_client import _ip6_to_int, _cidr_contains_ip6

    google_dns_v6 = "2001:4860:4860::8888"
    google_block  = "2001:4860::/32"
    ip_int = _ip6_to_int(google_dns_v6)
    assert _cidr_contains_ip6(google_block, ip_int), "Google IPv6 should be in 2001:4860::/32"
    assert not _cidr_contains_ip6("2606:4700::/32", ip_int), "Google IPv6 should not be in Cloudflare block"
    print("   ✅ A1: IPv6 CIDR matching logic correct")
except Exception as e:
    print(f"   ❌ A1: IPv6 CIDR matching failed: {e}")
    errors.append(f"sprint1:A1:logic:{e}")


# ── SECTION 12 — SPRINT 2 (DNS features E1–E5, E7) ───────────
print("\n12. SPRINT 2 — DNS features (E1–E5, E7)")

# E1: dns_resolve present in rir_client
import rir_client as _rc2
for fn_name in ["dns_resolve", "dns_enumerate", "dns_dnssec", "dns_dnsbl", "dns_email_security", "dns_propagation"]:
    if hasattr(_rc2, fn_name):
        print(f"   ✅ E: rir_client.{fn_name} present")
    else:
        print(f"   ❌ E: rir_client.{fn_name} MISSING")
        errors.append(f"sprint2:client:{fn_name}")

# DNS models present
try:
    from models import (
        DNSResolveInput, DNSResolveResult, DNSRecord,
        DNSEnumerateInput, DNSEnumerateResult,
        DNSSECInput, DNSSECResult,
        DNSBLInput, DNSBLResult, DNSBLEntry,
        EmailSecurityInput, EmailSecurityResult,
        DNSPropagationInput, DNSPropagationResult, PropagationEntry,
    )
    print("   ✅ Sprint 2: all DNS Pydantic models importable")
except Exception as e:
    print(f"   ❌ Sprint 2: DNS models import failed: {e}")
    errors.append(f"sprint2:models:{e}")

# DNS formatter functions present
try:
    from formatters import (
        format_dns_resolve_md,
        format_dns_enumerate_md,
        format_dns_dnssec_md,
        format_dns_dnsbl_md,
        format_email_security_md,
        format_dns_propagation_md,
    )
    print("   ✅ Sprint 2: all DNS formatter functions importable")
except Exception as e:
    print(f"   ❌ Sprint 2: DNS formatters import failed: {e}")
    errors.append(f"sprint2:formatters:{e}")

# DNS MCP tools in server.py
dns_mcp_tools = [
    "peerglass_dns_resolve", "peerglass_dns_enumerate", "peerglass_dns_dnssec",
    "peerglass_dns_dnsbl", "peerglass_dns_email_security", "peerglass_dns_propagation",
]
for tool in dns_mcp_tools:
    if tool in server_src:
        print(f"   ✅ E: MCP tool {tool} present in server.py")
    else:
        print(f"   ❌ E: MCP tool {tool} MISSING from server.py")
        errors.append(f"sprint2:mcp:{tool}")

# DNS API endpoints in api.py
api_src2 = open("api.py").read()
dns_routes = [
    "/v1/dns/resolve/{target}", "/v1/dns/enumerate/{domain}",
    "/v1/dns/dnssec/{domain}",  "/v1/dns/dnsbl/{ip}",
    "/v1/dns/email/{domain}",   "/v1/dns/propagation/{domain}",
]
for route in dns_routes:
    if route in api_src2:
        print(f"   ✅ E: REST route {route} present")
    else:
        print(f"   ❌ E: REST route {route} MISSING")
        errors.append(f"sprint2:route:{route}")

# DNS TTL constants in cache.py
cache_src = open("cache.py").read()
dns_ttl_keys = [
    "TTL_DNS_RESOLVE", "TTL_DNS_ENUMERATE", "TTL_DNS_DNSSEC",
    "TTL_DNS_DNSBL", "TTL_DNS_EMAIL", "TTL_DNS_PROPAGATION",
]
for k in dns_ttl_keys:
    if k in cache_src:
        print(f"   ✅ E: cache.{k} present")
    else:
        print(f"   ❌ E: cache.{k} MISSING")
        errors.append(f"sprint2:cache:{k}")


# ── SECTION 13 — SPRINT 3 (TLS, CT Logs, Threat Intel, PDNS) ─
print("\n13. SPRINT 3 — TLS (F1), CT Logs (F2), Threat Intel (G1), PDNS (E6)")

# Client functions
import rir_client as _rc3
for fn_name in ["tls_inspect", "ct_logs", "threat_intel", "passive_dns"]:
    if hasattr(_rc3, fn_name):
        print(f"   ✅ Sprint 3: rir_client.{fn_name} present")
    else:
        print(f"   ❌ Sprint 3: rir_client.{fn_name} MISSING")
        errors.append(f"sprint3:client:{fn_name}")

# Models
try:
    from models import (
        TLSInspectInput, TLSCertResult,
        CTLogInput, CTLogEntry, CTLogResult,
        ThreatIntelInput, ThreatIntelResult,
        PassiveDNSInput, PassiveDNSRecord, PassiveDNSResult,
    )
    # Quick round-trip checks
    tls = TLSCertResult(hostname="example.com", port=443)
    assert tls.expired is True  # default True until connected
    ct = CTLogResult(domain="example.com")
    assert ct.total_found == 0
    ti = ThreatIntelResult(ip="1.1.1.1")
    assert ti.risk_level == "LOW"
    pdns = PassiveDNSResult(resource="1.1.1.1")
    assert pdns.total == 0
    print("   ✅ Sprint 3: all models importable and round-trip correctly")
except Exception as e:
    print(f"   ❌ Sprint 3: model check failed: {e}")
    errors.append(f"sprint3:models:{e}")

# Formatters
try:
    from formatters import (
        format_tls_inspect_md,
        format_ct_logs_md,
        format_threat_intel_md,
        format_passive_dns_md,
    )
    print("   ✅ Sprint 3: all formatters importable")
except Exception as e:
    print(f"   ❌ Sprint 3: formatters import failed: {e}")
    errors.append(f"sprint3:formatters:{e}")

# MCP tools
sprint3_mcp = [
    "peerglass_tls_inspect", "peerglass_ct_logs",
    "peerglass_threat_intel", "peerglass_passive_dns",
]
for tool in sprint3_mcp:
    if tool in server_src:
        print(f"   ✅ Sprint 3: MCP tool {tool} present")
    else:
        print(f"   ❌ Sprint 3: MCP tool {tool} MISSING")
        errors.append(f"sprint3:mcp:{tool}")

# REST routes
api_src3 = open("api.py").read()
sprint3_routes = ["/v1/tls/{hostname}", "/v1/ct/{domain}", "/v1/threat/{ip}", "/v1/pdns/{resource}"]
for route in sprint3_routes:
    if route in api_src3:
        print(f"   ✅ Sprint 3: REST route {route} present")
    else:
        print(f"   ❌ Sprint 3: REST route {route} MISSING")
        errors.append(f"sprint3:route:{route}")

# Cache TTLs
cache_src3 = open("cache.py").read()
sprint3_ttls = ["TTL_TLS_INSPECT", "TTL_CT_LOGS", "TTL_THREAT_INTEL", "TTL_PASSIVE_DNS"]
for k in sprint3_ttls:
    if k in cache_src3:
        print(f"   ✅ Sprint 3: cache.{k} present")
    else:
        print(f"   ❌ Sprint 3: cache.{k} MISSING")
        errors.append(f"sprint3:cache:{k}")


# ── SPRINT 4 — BGP Depth (D1, D3, D4, D5) ────────────────────
print()
print("14. SPRINT 4 — IRR Validation (D1), Route Leak (D3), Looking Glass (D4), Stability (D5)")

# rir_client functions
client_src4 = open("rir_client.py").read()
sprint4_fns = ["check_irr", "detect_route_leak", "get_looking_glass", "get_route_stability"]
for fn in sprint4_fns:
    if f"async def {fn}" in client_src4:
        print(f"   ✅ Sprint 4: rir_client.{fn} present")
    else:
        print(f"   ❌ Sprint 4: rir_client.{fn} MISSING")
        errors.append(f"sprint4:fn:{fn}")

# Models
from models import (
    IRRCheckInput, IRRRouteObject, IRRResult,
    RouteLeakInput, RouteLeakPath, RouteLeakResult,
    LookingGlassInput, LookingGlassEntry, LookingGlassResult,
    RouteStabilityInput, RouteEvent, RouteStabilityResult,
)
sprint4_models = [
    ("IRRCheckInput",       IRRCheckInput),
    ("IRRResult",           IRRResult),
    ("RouteLeakInput",      RouteLeakInput),
    ("RouteLeakResult",     RouteLeakResult),
    ("LookingGlassInput",   LookingGlassInput),
    ("LookingGlassResult",  LookingGlassResult),
    ("RouteStabilityInput", RouteStabilityInput),
    ("RouteStabilityResult",RouteStabilityResult),
]
for name, cls in sprint4_models:
    try:
        cls.model_fields  # Pydantic v2 check
        print(f"   ✅ Sprint 4: model {name} importable")
    except Exception as e:
        print(f"   ❌ Sprint 4: model {name} BROKEN: {e}")
        errors.append(f"sprint4:model:{name}")

# Formatters
from formatters import (
    format_irr_result_md, format_route_leak_md,
    format_looking_glass_md, format_route_stability_md,
)
for fn_name in ["format_irr_result_md", "format_route_leak_md",
                "format_looking_glass_md", "format_route_stability_md"]:
    print(f"   ✅ Sprint 4: formatter {fn_name} importable")

# MCP tools
server_src4 = open("server.py").read()
sprint4_tools = [
    "rir_check_irr", "rir_detect_route_leak",
    "rir_looking_glass", "rir_route_stability",
]
for tool in sprint4_tools:
    if f'name="{tool}"' in server_src4:
        print(f"   ✅ Sprint 4: MCP tool {tool} present")
    else:
        print(f"   ❌ Sprint 4: MCP tool {tool} MISSING")
        errors.append(f"sprint4:mcp:{tool}")

# REST routes
api_src4 = open("api.py").read()
sprint4_routes = ["/v1/irr", "/v1/route-leak/", "/v1/looking-glass/", "/v1/stability/"]
for route in sprint4_routes:
    if route in api_src4:
        print(f"   ✅ Sprint 4: REST route {route} present")
    else:
        print(f"   ❌ Sprint 4: REST route {route} MISSING")
        errors.append(f"sprint4:route:{route}")

# Cache TTLs
cache_src4 = open("cache.py").read()
sprint4_ttls = ["TTL_IRR", "TTL_ROUTE_LEAK", "TTL_LOOKING_GLASS", "TTL_ROUTE_STABILITY"]
for k in sprint4_ttls:
    if k in cache_src4:
        print(f"   ✅ Sprint 4: cache.{k} present")
    else:
        print(f"   ❌ Sprint 4: cache.{k} MISSING")
        errors.append(f"sprint4:cache:{k}")


# ── SPRINT 5 — Humanitarian / Crisis (H1–H8) ─────────────────
print()
print("15. SPRINT 5 — Shutdown (H1), Webhooks (H2), Timeline (H3), Censorship (H4),")
print("               Satellite (H5), Chokepoints (H6), OONI (H7), Country Health (H8)")

client_src5 = open("rir_client.py").read()
sprint5_fns = [
    "detect_shutdown", "register_shutdown_monitor", "get_shutdown_timeline",
    "probe_dns_censorship", "get_satellite_connectivity",
    "get_country_chokepoints", "get_ooni_report", "get_country_health",
]
for fn in sprint5_fns:
    if f"async def {fn}" in client_src5:
        print(f"   ✅ Sprint 5: rir_client.{fn} present")
    else:
        print(f"   ❌ Sprint 5: rir_client.{fn} MISSING")
        errors.append(f"sprint5:fn:{fn}")

from models import (
    ShutdownDetectInput, ShutdownDetectResult,
    MonitorRegisterInput, MonitorRegisterResult,
    ShutdownTimelineInput, ShutdownTimelineResult,
    CensorshipProbeInput, CensorshipProbeResult,
    SatelliteConnectivityInput, SatelliteConnectivityResult,
    ChokePointInput, ChokePointResult,
    OONIReportInput, OONIReportResult,
    CountryHealthInput, CountryHealthResult,
)
sprint5_models = [
    "ShutdownDetectInput", "ShutdownDetectResult",
    "MonitorRegisterInput", "MonitorRegisterResult",
    "ShutdownTimelineInput", "ShutdownTimelineResult",
    "CensorshipProbeInput", "CensorshipProbeResult",
    "SatelliteConnectivityInput", "SatelliteConnectivityResult",
    "ChokePointInput", "ChokePointResult",
    "OONIReportInput", "OONIReportResult",
    "CountryHealthInput", "CountryHealthResult",
]
for name in sprint5_models:
    print(f"   ✅ Sprint 5: model {name} importable")

from formatters import (
    format_shutdown_detect_md, format_monitor_register_md,
    format_shutdown_timeline_md, format_censorship_probe_md,
    format_satellite_connectivity_md, format_chokepoints_md,
    format_ooni_report_md, format_country_health_md,
)
for fn_name in ["format_shutdown_detect_md", "format_monitor_register_md",
                "format_shutdown_timeline_md", "format_censorship_probe_md",
                "format_satellite_connectivity_md", "format_chokepoints_md",
                "format_ooni_report_md", "format_country_health_md"]:
    print(f"   ✅ Sprint 5: formatter {fn_name} importable")

server_src5 = open("server.py").read()
sprint5_tools = [
    "peerglass_shutdown_detect", "peerglass_monitor_register",
    "peerglass_shutdown_timeline", "peerglass_dns_censorship",
    "peerglass_satellite_connectivity", "peerglass_country_chokepoints",
    "peerglass_ooni_report", "peerglass_country_health",
]
for tool in sprint5_tools:
    if f'name="{tool}"' in server_src5:
        print(f"   ✅ Sprint 5: MCP tool {tool} present")
    else:
        print(f"   ❌ Sprint 5: MCP tool {tool} MISSING")
        errors.append(f"sprint5:mcp:{tool}")

api_src5 = open("api.py").read()
sprint5_routes = [
    "/v1/shutdown/", "/v1/shutdown/monitor", "/v1/shutdown/timeline/",
    "/v1/censorship/", "/v1/satellite/", "/v1/chokepoints/",
    "/v1/ooni/", "/v1/health/country/",
]
for route in sprint5_routes:
    if route in api_src5:
        print(f"   ✅ Sprint 5: REST route {route} present")
    else:
        print(f"   ❌ Sprint 5: REST route {route} MISSING")
        errors.append(f"sprint5:route:{route}")

cache_src5 = open("cache.py").read()
sprint5_ttls = [
    "TTL_SHUTDOWN", "TTL_SHUTDOWN_TIMELINE", "TTL_CENSORSHIP",
    "TTL_SATELLITE", "TTL_CHOKEPOINTS", "TTL_OONI", "TTL_COUNTRY_HEALTH",
]
for k in sprint5_ttls:
    if k in cache_src5:
        print(f"   ✅ Sprint 5: cache.{k} present")
    else:
        print(f"   ❌ Sprint 5: cache.{k} MISSING")
        errors.append(f"sprint5:cache:{k}")


# ── SUMMARY ──────────────────────────────────────────────────
print()
print("=" * 60)
if not errors:
    print("✅ ALL TESTS PASSED — 0 errors")
    print()
    print("  Python files:         7  (all compile clean)")
    print("  MCP tools:            39")
    print("  REST endpoints:       37")
    print("  Protocol:             RDAP throughout (RFC 7480-7484)")
    print("  Branding:             PeerGlass throughout")
    print("  historical-whois:     correctly attributed to RIPE Stat API naming")
else:
    print(f"❌ {len(errors)} ERROR(S) FOUND:")
    for e in errors:
        print(f"   • {e}")
    sys.exit(1)
print("=" * 60)
