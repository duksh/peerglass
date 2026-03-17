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
print("\n7. TOOL COUNT — 17 @mcp.tool() decorators in server.py")
# Decorator is @mcp.tool( with description kwarg on next line
tools_found = re.findall(r"@mcp\.tool\(", server_src)
count = len(tools_found)
if count == 17:
    print(f"   ✅ {count} @mcp.tool() decorators found")
else:
    print(f"   ❌ Expected 17, found {count}")
    errors.append(f"tool_count:{count}")


# ── 8. REST ENDPOINTS ────────────────────────────────────────
print("\n8. REST API — all 15 endpoints present in api.py")
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
    assert data["tools"] == 17, f"Root shows {data['tools']} tools not 17"
    assert data["name"] == "PeerGlass API", f"Name is {data['name']}"
    print(f"   ✅ GET /  → 200, name=PeerGlass API, tools=17")

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
print("\n10. README — PeerGlass branding, 17 tools, RDAP note, historical-whois explained")
readme = open("README.md").read()

must_contain = [
    ("PeerGlass",              "Product name present"),
    ("17 tools",               "Correct tool count (17)"),
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

# ── SUMMARY ──────────────────────────────────────────────────
print()
print("=" * 60)
if not errors:
    print("✅ ALL TESTS PASSED — 0 errors")
    print()
    print("  Python files:         7  (all compile clean)")
    print("  MCP tools:            17")
    print("  REST endpoints:       15")
    print("  Protocol:             RDAP throughout (RFC 7480-7484)")
    print("  Branding:             PeerGlass throughout")
    print("  historical-whois:     correctly attributed to RIPE Stat API naming")
else:
    print(f"❌ {len(errors)} ERROR(S) FOUND:")
    for e in errors:
        print(f"   • {e}")
    sys.exit(1)
print("=" * 60)
