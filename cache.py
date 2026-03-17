"""
cache.py — In-memory TTL cache for PeerGlass.

Each RIR has rate limits (typically 5–15 req/min). Caching protects
both the RIR infrastructure and our query latency.

Think of it like a sticky-note pad: if you already looked up who owns
1.1.1.1 thirty minutes ago, there is no need to ask again — just read
the note. The note expires after the TTL and a fresh query is made.

Cache TTLs (Time To Live):
  IP lookups    → 1 hour   (IP ownership is very stable)
  ASN lookups   → 1 hour
  Org lookups   → 6 hours  (org records change rarely)
  Abuse contact → 1 hour
  BGP status    → 5 minutes (routing tables change frequently)
  RPKI status   → 15 minutes (ROAs can be created/revoked)
  Stats         → 24 hours
"""

import time
import hashlib
import json
from typing import Any, Optional

# ── TTL constants (seconds) ─────────────────────────────────
TTL_IP    = 3_600       # 1 hour
TTL_ASN   = 3_600       # 1 hour
TTL_ORG   = 21_600      # 6 hours
TTL_ABUSE = 3_600       # 1 hour
TTL_BGP   = 300         # 5 minutes
TTL_RPKI  = 900         # 15 minutes
TTL_STATS = 86_400      # 24 hours
TTL_HISTORY  = 43_200   # 12 hours  — historical records don't change often
TTL_TRANSFER = 43_200   # 12 hours  — transfers are infrequent
TTL_IPV4STAT = 86_400   # 24 hours  — NRO stats are published daily
TTL_OVERVIEW = 3_600    # 1 hour    — prefix overview (BGP part can shift)
TTL_PEERING  = 21_600   # 6 hours   — PeeringDB records are fairly stable
TTL_IXP      = 43_200   # 12 hours  — IXP list changes slowly
TTL_HEALTH   = 300      # 5 minutes — combined health check has live BGP data

# DNS TTLs
TTL_DNS_RESOLVE    = 300       # 5 minutes  — DNS can change quickly
TTL_DNS_ENUMERATE  = 300       # 5 minutes
TTL_DNS_DNSSEC     = 3_600     # 1 hour     — DNSSEC chains are stable
TTL_DNS_DNSBL      = 3_600     # 1 hour     — blocklist status is semi-static
TTL_DNS_EMAIL      = 3_600     # 1 hour     — SPF/DMARC/DKIM change rarely
TTL_DNS_PROPAGATION = 120      # 2 minutes  — propagation is time-sensitive

# Sprint 3 — TLS, CT logs, Threat Intel, Passive DNS
TTL_TLS_INSPECT  = 3_600     # 1 hour     — certs change infrequently
TTL_CT_LOGS      = 86_400    # 24 hours   — CT log history is append-only
TTL_THREAT_INTEL = 3_600     # 1 hour     — Shodan/GreyNoise refreshes hourly
TTL_PASSIVE_DNS  = 86_400    # 24 hours   — PDNS history rarely changes

# Sprint 4 — BGP depth
TTL_IRR              = 3_600   # 1 hour     — IRR route objects are fairly stable
TTL_ROUTE_LEAK       = 300     # 5 minutes  — BGP state can shift quickly
TTL_LOOKING_GLASS    = 300     # 5 minutes  — live routing table snapshots
TTL_ROUTE_STABILITY  = 900     # 15 minutes — stability window is time-sensitive

# Sprint 5 — Humanitarian / crisis
TTL_SHUTDOWN          = 300      # 5 minutes  — shutdown changes fast
TTL_SHUTDOWN_TIMELINE = 3_600    # 1 hour     — historical evidence
TTL_CENSORSHIP        = 600      # 10 minutes — DNS censorship can change
TTL_SATELLITE         = 900      # 15 minutes — satellite BGP changes slowly
TTL_CHOKEPOINTS       = 21_600   # 6 hours    — transit topology is stable
TTL_OONI              = 1_800    # 30 minutes — OONI updates continuously
TTL_COUNTRY_HEALTH    = 300      # 5 minutes  — composite live score

# ── In-memory store ─────────────────────────────────────────
_STORE: dict[str, tuple[Any, float]] = {}


def _make_key(*args: Any) -> str:
    """Create a stable, collision-resistant cache key from any arguments."""
    raw = json.dumps(args, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def get(cache_key: str) -> Optional[Any]:
    """Return cached value if not expired. Returns None on miss or expiry."""
    if cache_key not in _STORE:
        return None
    value, expiry = _STORE[cache_key]
    if time.time() > expiry:
        del _STORE[cache_key]
        return None
    return value


def set(cache_key: str, value: Any, ttl: int) -> None:
    """Store a value with a TTL in seconds."""
    _STORE[cache_key] = (value, time.time() + ttl)


# ── Key builders ────────────────────────────────────────────

def make_ip_key(ip: str) -> str:
    return _make_key("ip", ip.lower().strip())

def make_asn_key(asn: str) -> str:
    return _make_key("asn", asn.upper().lstrip("AS"))

def make_org_key(org: str) -> str:
    return _make_key("org", org.lower().strip())

def make_abuse_key(ip: str) -> str:
    return _make_key("abuse", ip.lower().strip())

def make_bgp_key(resource: str) -> str:
    return _make_key("bgp", resource.lower().strip())

def make_rpki_key(prefix: str, asn: str) -> str:
    return _make_key("rpki", prefix.lower().strip(), asn.strip())

def make_history_key(resource: str) -> str:
    return _make_key("history", resource.lower().strip())

def make_transfer_key(resource: str) -> str:
    return _make_key("transfer", resource.lower().strip())

def make_ipv4stat_key(
    rir_filter: str = "all",
    include_blocks: bool = False,
    status_filter: Optional[str] = None,
    country_filter: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> str:
    return _make_key(
        "ipv4stat",
        rir_filter.lower(),
        bool(include_blocks),
        (status_filter or "").lower(),
        (country_filter or "").upper(),
        int(limit),
        int(offset),
    )

def make_overview_key(prefix: str) -> str:
    return _make_key("overview", prefix.lower().strip())

def make_peering_key(asn: str) -> str:
    return _make_key("peering", asn.upper().lstrip("AS"))

def make_ixp_key(query: str) -> str:
    return _make_key("ixp", query.lower().strip())

def make_health_key(resource: str) -> str:
    return _make_key("health", resource.lower().strip())

def make_dns_resolve_key(target: str) -> str:
    return _make_key("dns_resolve", target.lower().strip())

def make_dns_enumerate_key(domain: str) -> str:
    return _make_key("dns_enumerate", domain.lower().strip())

def make_dns_dnssec_key(domain: str) -> str:
    return _make_key("dns_dnssec", domain.lower().strip())

def make_dns_dnsbl_key(ip: str) -> str:
    return _make_key("dns_dnsbl", ip.strip())

def make_dns_email_key(domain: str) -> str:
    return _make_key("dns_email", domain.lower().strip())

def make_dns_propagation_key(domain: str, record_type: str) -> str:
    return _make_key("dns_propagation", domain.lower().strip(), record_type.upper())

def make_tls_key(hostname: str, port: int) -> str:
    return _make_key("tls", hostname.lower().strip(), int(port))

def make_ct_key(domain: str) -> str:
    return _make_key("ct_logs", domain.lower().strip())

def make_threat_intel_key(ip: str) -> str:
    return _make_key("threat_intel", ip.strip())

def make_passive_dns_key(resource: str) -> str:
    return _make_key("passive_dns", resource.lower().strip())

# Sprint 4 — BGP depth
def make_irr_key(prefix: str, asn: str) -> str:
    return _make_key("irr", prefix.strip(), asn.upper().lstrip("AS"))

def make_route_leak_key(prefix: str) -> str:
    return _make_key("route_leak", prefix.strip())

def make_looking_glass_key(prefix: str, vantage_points: int) -> str:
    return _make_key("looking_glass", prefix.strip(), int(vantage_points))

def make_route_stability_key(prefix: str, hours: int) -> str:
    return _make_key("route_stability", prefix.strip(), int(hours))

# Sprint 5 — Humanitarian / crisis
def make_shutdown_key(country_code: str) -> str:
    return _make_key("shutdown", country_code.upper().strip())

def make_shutdown_timeline_key(resource: str, start: str, end: str) -> str:
    return _make_key("shutdown_timeline", resource.upper().strip(), start, end)

def make_censorship_key(domain: str, country_code: str = "") -> str:
    return _make_key("censorship", domain.lower().strip(), country_code.upper().strip())

def make_satellite_key(country_code: str) -> str:
    return _make_key("satellite", country_code.upper().strip())

def make_chokepoints_key(country_code: str) -> str:
    return _make_key("chokepoints", country_code.upper().strip())

def make_ooni_key(country_code: str, domain: str = "") -> str:
    return _make_key("ooni", country_code.upper().strip(), domain.lower().strip())

def make_country_health_key(country_code: str) -> str:
    return _make_key("country_health", country_code.upper().strip())


# ── Monitor Store — persistent baselines for change detection ──
# Separate from the TTL cache: baselines never expire automatically.
# Key = make_monitor_key(resource), Value = snapshot dict.
_MONITOR_STORE: dict[str, dict] = {}

def make_monitor_key(resource: str) -> str:
    return _make_key("monitor", resource.lower().strip())

def get_baseline(resource: str) -> dict | None:
    """Retrieve a stored monitoring baseline, or None if not set."""
    return _MONITOR_STORE.get(make_monitor_key(resource))

def set_baseline(resource: str, snapshot: dict) -> None:
    """Store a monitoring baseline snapshot."""
    _MONITOR_STORE[make_monitor_key(resource)] = snapshot

def clear_baseline(resource: str) -> bool:
    """Delete a monitoring baseline. Returns True if it existed."""
    key = make_monitor_key(resource)
    if key in _MONITOR_STORE:
        del _MONITOR_STORE[key]
        return True
    return False

def list_monitored() -> list[str]:
    """Return list of resources currently being monitored."""
    return list(_MONITOR_STORE.keys())


# ── Diagnostics ─────────────────────────────────────────────

def stats() -> dict[str, int]:
    """Return cache health statistics."""
    now = time.time()
    alive   = sum(1 for _, (_, exp) in _STORE.items() if exp > now)
    expired = len(_STORE) - alive
    return {"total_entries": len(_STORE), "alive": alive, "expired": expired}


def clear() -> int:
    """Clear all cache entries. Returns count cleared."""
    count = len(_STORE)
    _STORE.clear()
    return count
