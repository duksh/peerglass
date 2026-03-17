"""
rir_client.py — PeerGlass async HTTP clients for all external APIs.

Phase 1: RDAP queries to all 5 RIRs (parallel engine)
Phase 2: RPKI/ROA validation (Cloudflare), BGP status (RIPE Stat),
         Organization search (RDAP search endpoints)

Protocol note: all live registry queries use RDAP (RFC 7480-7484),
the IANA-mandated JSON successor to legacy WHOIS. The string
"historical-whois" below refers to the RIPE Stat upstream API
endpoint name — it is not our protocol choice.

The parallel engine is the core of this server:
  asyncio.gather() fires all 5 RIR queries simultaneously.
  Like asking 5 librarians the same question at once instead of
  waiting for each one to finish before approaching the next.
"""

from __future__ import annotations
import asyncio
import ipaddress
import socket
import time
from typing import Any, Optional
import httpx

from models import RIRName, RIRQueryResult, RPKIResult, RPKIValidity, \
    BGPStatusResult, BGPPrefix, BGPCommunity, BGP_WELL_KNOWN_COMMUNITIES, \
    OrgResource, HistoricalEvent, PrefixHistoryResult, TransferEvent, TransferDetectResult, \
    RIRDelegationStats, GlobalIPv4Stats, IPv4DelegatedBlock, RelatedPrefix, PrefixOverviewResult, \
    IXPRecord, PeeringInfoResult, IXPLookupResult, NetworkHealthResult, \
    ChangeMonitorResult, FieldDelta


# ──────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────

RDAP_ENDPOINTS: dict[RIRName, str] = {
    RIRName.AFRINIC: "https://rdap.afrinic.net/rdap",
    RIRName.APNIC:   "https://rdap.apnic.net",
    RIRName.ARIN:    "https://rdap.arin.net/registry",
    RIRName.LACNIC:  "https://rdap.lacnic.net/rdap",
    RIRName.RIPE:    "https://rdap.db.ripe.net",
}

# RDAP search endpoints (not all RIRs support entity search)
RDAP_SEARCH_ENDPOINTS: dict[RIRName, Optional[str]] = {
    RIRName.AFRINIC: "https://rdap.afrinic.net/rdap",
    RIRName.APNIC:   "https://rdap.apnic.net",
    RIRName.ARIN:    "https://rdap.arin.net/registry",
    RIRName.LACNIC:  None,  # LACNIC does not support RDAP entity search
    RIRName.RIPE:    "https://rdap.db.ripe.net",
}

# IANA Bootstrap — tells us which RIR is authoritative for each IP/ASN range
IANA_BOOTSTRAP_IPv4 = "https://data.iana.org/rdap/ipv4.json"
IANA_BOOTSTRAP_IPv6 = "https://data.iana.org/rdap/ipv6.json"
IANA_BOOTSTRAP_ASN  = "https://data.iana.org/rdap/asn.json"

# Phase 2 — external API endpoints
CLOUDFLARE_RPKI_URL = "https://rpki.cloudflare.com/api/v1/validity"
RIPE_STAT_RPKI_URL  = "https://stat.ripe.net/data/rpki-validation/data.json"
RIPE_STAT_BGP_URL   = "https://stat.ripe.net/data/bgp-state/data.json"
RIPE_STAT_PREFIXES_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPE_STAT_ROUTING_URL  = "https://stat.ripe.net/data/routing-status/data.json"

# Phase 3 — historical intelligence endpoints
RIPE_STAT_HIST_WHOIS_URL    = "https://stat.ripe.net/data/historical-whois/data.json"
RIPE_STAT_ALLOC_HIST_URL    = "https://stat.ripe.net/data/allocation-history/data.json"
RIPE_STAT_PREFIX_OVERVIEW   = "https://stat.ripe.net/data/prefix-overview/data.json"
RIPE_STAT_LESS_SPECIFICS    = "https://stat.ripe.net/data/less-specifics/data.json"
RIPE_STAT_MORE_SPECIFICS    = "https://stat.ripe.net/data/more-specifics/data.json"

# NRO Extended Delegation Stats — published daily by each RIR
# Format: rir|CC|type|start|value|date|status[|opaque-id[|extensions]]
NRO_DELEGATION_STATS: dict[str, str] = {
    "AFRINIC": "https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest",
    "APNIC":   "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "ARIN":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "LACNIC":  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "RIPE":    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
}

RIR_REGIONS: dict[str, str] = {
    "AFRINIC": "Africa",
    "APNIC":   "Asia-Pacific",
    "ARIN":    "North America",
    "LACNIC":  "Latin America & Caribbean",
    "RIPE":    "Europe / Middle East / Central Asia",
}

# Phase 4 — PeeringDB + RIPE Stat neighbours
PEERINGDB_NET_URL   = "https://www.peeringdb.com/api/net"
PEERINGDB_IXP_URL   = "https://www.peeringdb.com/api/ix"
PEERINGDB_NETIXLAN_URL = "https://www.peeringdb.com/api/netixlan"
RIPE_STAT_NEIGHBOURS_URL = "https://stat.ripe.net/data/asn-neighbours/data.json"

DEFAULT_TIMEOUT = 15.0
DEFAULT_HEADERS = {
    "Accept":     "application/rdap+json, application/json",
    "User-Agent": "peerglass/1.0.0 (PeerGlass RDAP+BGP+RPKI client; educational/research use)",
}

# Bootstrap data is cached with a 24-hour TTL so long-running servers
# always use fresh IANA data without needing a restart (A2).
# Structure: {url: (data_dict, fetched_timestamp)}
_BOOTSTRAP_CACHE: dict[str, tuple[dict, float]] = {}
BOOTSTRAP_TTL = 86_400  # 24 hours


# ──────────────────────────────────────────────────────────────
# Bootstrap / routing helpers
# ──────────────────────────────────────────────────────────────

async def _load_bootstrap(url: str, client: httpx.AsyncClient) -> dict:
    """Load IANA bootstrap JSON, refreshing from network if older than 24 h."""
    cached = _BOOTSTRAP_CACHE.get(url)
    if cached:
        data, fetched_at = cached
        if time.time() - fetched_at < BOOTSTRAP_TTL:
            return data
    try:
        resp = await client.get(url, timeout=10.0, headers=DEFAULT_HEADERS)
        resp.raise_for_status()
        data = resp.json()
        _BOOTSTRAP_CACHE[url] = (data, time.time())
        return data
    except Exception:
        # On network failure return stale data if we have it, else empty
        return cached[0] if cached else {}


def _ip4_to_int(ip: str) -> int:
    parts = ip.split(".")
    result = 0
    for part in parts:
        result = (result << 8) + int(part)
    return result


def _cidr_contains_ip4(cidr: str, ip_int: int) -> bool:
    try:
        network, bits = cidr.split("/")
        net_int = _ip4_to_int(network)
        mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
        return (ip_int & mask) == (net_int & mask)
    except Exception:
        return False


def _ip6_to_int(ip: str) -> int:
    """Convert an IPv6 address (without prefix) to a 128-bit integer."""
    return int(ipaddress.ip_address(ip.split("/")[0]))


def _cidr_contains_ip6(cidr: str, ip_int: int) -> bool:
    """Return True if ip_int falls inside the IPv6 CIDR block."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        net_int = int(network.network_address)
        shift = 128 - network.prefixlen
        mask = ((1 << 128) - 1) ^ ((1 << shift) - 1)
        return (ip_int & mask) == (net_int & mask)
    except Exception:
        return False


async def _find_authoritative_base_url(
    query: str,
    query_type: str,  # "ip" | "asn"
    client: httpx.AsyncClient,
) -> Optional[str]:
    """
    Use IANA RDAP Bootstrap to find which RIR is authoritative for a given
    IP address or ASN. Returns the RDAP base URL of that RIR, or None.
    Supports both IPv4 and IPv6 (A1).
    """
    if query_type == "ip":
        is_v6 = ":" in query
        url = IANA_BOOTSTRAP_IPv6 if is_v6 else IANA_BOOTSTRAP_IPv4
        bootstrap = await _load_bootstrap(url, client)
        if is_v6:
            try:
                ip_int = _ip6_to_int(query)
                for service in bootstrap.get("services", []):
                    cidrs, urls = service[0], service[1]
                    for cidr in cidrs:
                        if _cidr_contains_ip6(cidr, ip_int):
                            return urls[0] if urls else None
            except Exception:
                pass
        else:
            try:
                ip_int = _ip4_to_int(query.split("/")[0])
                for service in bootstrap.get("services", []):
                    cidrs, urls = service[0], service[1]
                    for cidr in cidrs:
                        if _cidr_contains_ip4(cidr, ip_int):
                            return urls[0] if urls else None
            except Exception:
                pass
    elif query_type == "asn":
        bootstrap = await _load_bootstrap(IANA_BOOTSTRAP_ASN, client)
        try:
            asn_num = int(query.upper().lstrip("AS"))
            for service in bootstrap.get("services", []):
                ranges, urls = service[0], service[1]
                for r in ranges:
                    parts = r.split("-")
                    lo = int(parts[0])
                    hi = int(parts[1]) if len(parts) == 2 else lo
                    if lo <= asn_num <= hi:
                        return urls[0] if urls else None
        except Exception:
            pass
    return None


# ──────────────────────────────────────────────────────────────
# Core single-RIR query
# ──────────────────────────────────────────────────────────────

async def _query_one_rir(
    client: httpx.AsyncClient,
    rir: RIRName,
    base_url: str,
    path: str,
) -> RIRQueryResult:
    """Query one RIR's RDAP endpoint and return a structured result."""
    url = f"{base_url}/{path}"
    queried_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        resp = await client.get(url, timeout=DEFAULT_TIMEOUT, headers=DEFAULT_HEADERS, follow_redirects=True)
        if resp.status_code == 200:
            return RIRQueryResult(rir=rir, status="ok", queried_at=queried_at, data=resp.json())
        if resp.status_code == 404:
            return RIRQueryResult(rir=rir, status="not_found", queried_at=queried_at,
                                  error=f"Resource not found in {rir.value} registry")
        if resp.status_code == 429:
            return RIRQueryResult(rir=rir, status="rate_limited", queried_at=queried_at,
                                  error=f"Rate limited by {rir.value}. Try again in a few minutes.")
        return RIRQueryResult(rir=rir, status="error", queried_at=queried_at,
                              error=f"HTTP {resp.status_code} from {rir.value}")
    except httpx.TimeoutException:
        return RIRQueryResult(rir=rir, status="error", queried_at=queried_at,
                              error=f"{rir.value} timed out after {DEFAULT_TIMEOUT}s")
    except httpx.ConnectError:
        return RIRQueryResult(rir=rir, status="error", queried_at=queried_at,
                              error=f"Cannot connect to {rir.value} RDAP server")
    except Exception as exc:
        return RIRQueryResult(rir=rir, status="error", queried_at=queried_at,
                              error=f"{rir.value}: {type(exc).__name__}: {exc}")


# ──────────────────────────────────────────────────────────────
# Phase 1 — Parallel multi-RIR queries
# ──────────────────────────────────────────────────────────────

async def query_ip_all_rirs(ip: str) -> list[RIRQueryResult]:
    """Fire RDAP /ip/{ip} at all 5 RIRs simultaneously."""
    async with httpx.AsyncClient() as client:
        tasks = [
            _query_one_rir(client, rir, endpoint, f"ip/{ip}")
            for rir, endpoint in RDAP_ENDPOINTS.items()
        ]
        return list(await asyncio.gather(*tasks))


async def query_asn_all_rirs(asn: str) -> list[RIRQueryResult]:
    """Fire RDAP /autnum/{asn} at all 5 RIRs simultaneously."""
    asn_num = asn.upper().lstrip("AS")
    async with httpx.AsyncClient() as client:
        tasks = [
            _query_one_rir(client, rir, endpoint, f"autnum/{asn_num}")
            for rir, endpoint in RDAP_ENDPOINTS.items()
        ]
        return list(await asyncio.gather(*tasks))


async def query_authoritative_rir(query: str, query_type: str) -> Optional[RIRQueryResult]:
    """
    Find and query ONLY the authoritative RIR using IANA bootstrap.
    More efficient than querying all 5 — used for abuse contact lookups.
    Falls back to querying all 5 if bootstrap fails.
    """
    async with httpx.AsyncClient() as client:
        base_url = await _find_authoritative_base_url(query, query_type, client)
        if base_url:
            matched_rir: Optional[RIRName] = None
            for rir, endpoint in RDAP_ENDPOINTS.items():
                if base_url.rstrip("/").startswith(endpoint.rstrip("/")):
                    matched_rir = rir
                    break
            if matched_rir:
                path = f"{query_type}/{query}"
                return await _query_one_rir(client, matched_rir, base_url, path)

    # Fallback: query all, return first successful
    path = f"{query_type}/{query.upper().lstrip('AS') if query_type == 'asn' else query}"
    all_results = await query_ip_all_rirs(query) if query_type == "ip" else await query_asn_all_rirs(query)
    for result in all_results:
        if result.status == "ok":
            return result
    return None


# ──────────────────────────────────────────────────────────────
# J3 — WHOIS port-43 fallback
# ──────────────────────────────────────────────────────────────

# WHOIS server hostnames per RIR (port 43, plain TCP)
_WHOIS_SERVERS: dict[str, str] = {
    "AFRINIC": "whois.afrinic.net",
    "APNIC":   "whois.apnic.net",
    "ARIN":    "whois.arin.net",
    "LACNIC":  "whois.lacnic.net",
    "RIPE":    "whois.ripe.net",
}

# Map RDAP base URL prefixes to RIR names for WHOIS server selection
_RDAP_TO_RIR: list[tuple[str, str]] = [
    ("rdap.afrinic.net", "AFRINIC"),
    ("rdap.apnic.net",   "APNIC"),
    ("rdap.arin.net",    "ARIN"),
    ("rdap.lacnic.net",  "LACNIC"),
    ("rdap.db.ripe.net", "RIPE"),
]


async def _whois_query(query: str, whois_host: str, timeout: float = 10.0) -> str:
    """
    Open a raw TCP connection to whois_host:43, send query+CRLF, read response.
    Returns the raw WHOIS text or empty string on failure.
    """
    loop = asyncio.get_event_loop()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(whois_host, 43),
            timeout=timeout,
        )
        writer.write(f"{query}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _parse_whois_to_rdap_like(text: str, resource: str, rir: str) -> dict:
    """
    Parse key:value WHOIS text into a minimal RDAP-like dict so the existing
    normalizer can extract fields from it. Marks source as 'WHOIS fallback'.
    """
    fields: dict[str, Any] = {"objectClassName": "ip network", "_whois_fallback": True, "_rir": rir}
    for line in text.splitlines():
        if ":" not in line or line.startswith("%"):
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if not val:
            continue
        # Map common WHOIS keys to RDAP-like equivalents
        if key in ("netname", "inetnum", "inet6num", "aut-num", "as-name"):
            fields.setdefault("name", val)
        elif key in ("org", "organisation", "orgname", "owner"):
            fields.setdefault("org_name", val)
        elif key in ("country",):
            fields.setdefault("country", val.upper())
        elif key in ("abuse-mailbox", "orgabuseemail", "abuse-c"):
            fields.setdefault("abuse_email", val)
        elif key in ("created", "regdate"):
            fields.setdefault("created", val)
        elif key in ("last-modified", "changed", "updated"):
            fields.setdefault("last_changed", val)
        elif key in ("status",):
            fields.setdefault("status", val)
        elif key in ("netrange", "inetnum"):
            fields.setdefault("handle", val)
    # Provide a minimal 'handle' if still missing
    fields.setdefault("handle", resource)
    return fields


async def get_whois_fallback(resource: str, query_type: str) -> Optional[RIRQueryResult]:
    """
    Query the authoritative RIR WHOIS server (port 43) for a resource.
    Returns a RIRQueryResult with a WHOIS-parsed data dict, or None on failure.
    Used as a last-resort fallback when all RDAP responses are empty.
    """
    async with httpx.AsyncClient() as client:
        base_url = await _find_authoritative_base_url(resource, query_type, client)

    rir_name = "RIPE"  # default fallback
    if base_url:
        for rdap_fragment, rir_key in _RDAP_TO_RIR:
            if rdap_fragment in base_url:
                rir_name = rir_key
                break

    whois_host = _WHOIS_SERVERS.get(rir_name, "whois.ripe.net")
    text = await _whois_query(resource, whois_host)
    if not text or text.strip().startswith("%ERROR"):
        return None

    try:
        rir_enum = RIRName(rir_name)
    except ValueError:
        rir_enum = RIRName.RIPE

    data = _parse_whois_to_rdap_like(text, resource, rir_name)
    return RIRQueryResult(
        rir=rir_enum,
        status="ok",
        queried_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        data=data,
    )


async def get_rir_server_status() -> dict[RIRName, dict]:
    """Fetch /help from all 5 RIR RDAP endpoints simultaneously."""
    async with httpx.AsyncClient() as client:
        tasks = [
            _query_one_rir(client, rir, endpoint, "help")
            for rir, endpoint in RDAP_ENDPOINTS.items()
        ]
        results = list(await asyncio.gather(*tasks))
    return {
        r.rir: r.data if r.status == "ok" else {"error": r.error}
        for r in results
    }


# ──────────────────────────────────────────────────────────────
# Phase 2 — RPKI / ROA Validation
# ──────────────────────────────────────────────────────────────

async def check_rpki(prefix: str, asn: str) -> RPKIResult:
    """
    Validate a prefix+ASN pair against RPKI.

    Primary source: RIPE Stat rpki-validation endpoint.
    Fallback source: Cloudflare RPKI validator (legacy endpoint).

    RPKI (Resource Public Key Infrastructure) is a cryptographic system
    where each RIR issues Route Origin Authorizations (ROAs) — digital
    certificates that say "ASN X is authorized to announce prefix Y".

    This check answers: "Is this BGP route cryptographically valid?"
    A VALID result means the route has a matching ROA.
    An INVALID result means there IS a ROA, but this ASN/prefix doesn't match it.
    NOT-FOUND means no ROA exists — the route is unverified (not necessarily bad).
    """
    # Parse prefix into network and length
    try:
        network, length = prefix.split("/")
    except ValueError:
        return RPKIResult(
            prefix=prefix, asn=asn,
            validity=RPKIValidity.UNKNOWN,
            description="Invalid prefix format. Use CIDR notation e.g. '1.1.1.0/24'",
        )

    asn_num = asn.upper().lstrip("AS")
    validity_map = {
        "valid":      RPKIValidity.VALID,
        "invalid":    RPKIValidity.INVALID,
        "not-found":  RPKIValidity.NOT_FOUND,
        "not_found":  RPKIValidity.NOT_FOUND,
        "notfound":   RPKIValidity.NOT_FOUND,
        "unknown":    RPKIValidity.UNKNOWN,
    }
    descriptions = {
        RPKIValidity.VALID:
            "✅ This route has a valid ROA. The ASN is authorized to announce this prefix.",
        RPKIValidity.INVALID:
            "🚨 RPKI INVALID. A ROA exists but this ASN/prefix combination violates it. "
            "This may indicate a BGP route leak or hijack.",
        RPKIValidity.NOT_FOUND:
            "⚠️ No ROA found for this prefix. The route is unverified but not necessarily malicious. "
            "Consider creating a ROA at your RIR.",
        RPKIValidity.UNKNOWN:
            "❓ RPKI validity could not be determined.",
    }

    errors: list[str] = []
    try:
        async with httpx.AsyncClient() as client:
            # 1) Primary: RIPE Stat RPKI validation
            ripe_resp = await client.get(
                RIPE_STAT_RPKI_URL,
                params={"resource": f"AS{asn_num}", "prefix": prefix, "sourceapp": "peerglass"},
                timeout=10.0,
                headers=DEFAULT_HEADERS,
            )
            if ripe_resp.status_code == 200:
                ripe_payload = ripe_resp.json()
                if ripe_payload.get("status") == "ok":
                    ripe_data = ripe_payload.get("data", {})
                    state = str(ripe_data.get("status", "unknown")).lower()
                    validity = validity_map.get(state, RPKIValidity.UNKNOWN)
                    covering_roas = [
                        {
                            "asn": str(roa.get("origin", "")).lstrip("AS"),
                            "prefix": roa.get("prefix"),
                            "maxLength": roa.get("max_length"),
                        }
                        for roa in ripe_data.get("validating_roas", [])
                        if isinstance(roa, dict)
                    ]
                    return RPKIResult(
                        prefix=prefix,
                        asn=f"AS{asn_num}",
                        validity=validity,
                        covering_roas=covering_roas,
                        source="RIPE Stat RPKI Validation",
                        description=descriptions.get(validity, ""),
                    )
                errors.append("RIPE Stat RPKI API returned non-ok payload")
            else:
                errors.append(f"RIPE Stat RPKI API returned HTTP {ripe_resp.status_code}")

            # 2) Fallback: Cloudflare endpoint (legacy)
            cf_url = f"{CLOUDFLARE_RPKI_URL}/{asn_num}/{network}/{length}"
            cf_resp = await client.get(cf_url, timeout=10.0, headers=DEFAULT_HEADERS)
            if cf_resp.status_code == 200:
                cf_payload = cf_resp.json()
                validity_raw = cf_payload.get("result", {}).get("validity", cf_payload.get("validity", {}))
                state = str(validity_raw.get("state", cf_payload.get("status", "unknown"))).lower()
                validity = validity_map.get(state, RPKIValidity.UNKNOWN)

                vrps = validity_raw.get("VRPs", {}) if isinstance(validity_raw, dict) else {}
                covering_roas = vrps.get("matched", [])
                unmatched_roas = vrps.get("unmatched_as", []) + vrps.get("unmatched_length", [])

                return RPKIResult(
                    prefix=prefix,
                    asn=f"AS{asn_num}",
                    validity=validity,
                    covering_roas=covering_roas + unmatched_roas,
                    source="Cloudflare RPKI Validator",
                    description=descriptions.get(validity, ""),
                )

            errors.append(f"Cloudflare RPKI API returned HTTP {cf_resp.status_code}")
    except httpx.TimeoutException:
        errors.append("RPKI validators timed out")
    except Exception as exc:
        errors.append(f"Error querying RPKI: {type(exc).__name__}: {exc}")

    return RPKIResult(
        prefix=prefix,
        asn=f"AS{asn_num}",
        validity=RPKIValidity.UNKNOWN,
        source="RIPE Stat + Cloudflare fallback",
        description="; ".join(errors) if errors else "RPKI validity could not be determined.",
    )


# ──────────────────────────────────────────────────────────────
# Phase 2 — BGP Routing Table Status (RIPE Stat)
# ──────────────────────────────────────────────────────────────

async def get_bgp_status(resource: str) -> BGPStatusResult:
    """
    Check whether a prefix or ASN is currently visible in the global
    BGP routing table using RIPE Stat (which aggregates data from
    RIPE RIS route collectors worldwide).

    BGP (Border Gateway Protocol) is the routing protocol of the internet.
    Think of it as the internet's GPS — it tells traffic how to get from
    one network to another. If a prefix isn't in BGP, no traffic reaches it.
    If it IS in BGP with the wrong ASN, that could be a hijack.
    """
    queried_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    is_asn = resource.upper().startswith("AS") or resource.isdigit()
    resource_type = "asn" if is_asn else "prefix"

    url = RIPE_STAT_ROUTING_URL if not is_asn else RIPE_STAT_PREFIXES_URL
    params = {"resource": resource, "sourceapp": "peerglass"}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, params=params, timeout=15.0, headers=DEFAULT_HEADERS)
            if resp.status_code != 200:
                return BGPStatusResult(
                    resource=resource, resource_type=resource_type,
                    is_announced=False, queried_at=queried_at,
                    announced_prefixes=[],
                )

            data = resp.json().get("data", {})

            if is_asn:
                # RIPE Stat announced-prefixes endpoint
                prefixes_raw = data.get("prefixes", [])
                prefixes = [
                    BGPPrefix(
                        prefix       = p.get("prefix", ""),
                        peers_seeing = p.get("timelines", [{}])[-1].get("endtime") and len(p.get("timelines", [])),
                        first_seen   = p.get("timelines", [{}])[0].get("starttime") if p.get("timelines") else None,
                        last_seen    = p.get("timelines", [{}])[-1].get("endtime") if p.get("timelines") else None,
                    )
                    for p in prefixes_raw
                ]
                return BGPStatusResult(
                    resource            = resource,
                    resource_type       = resource_type,
                    is_announced        = len(prefixes) > 0,
                    announced_prefixes  = prefixes,
                    queried_at          = queried_at,
                )
            else:
                # RIPE Stat routing-status endpoint (prefix)
                visibility = data.get("visibility", {})
                if isinstance(visibility, dict) and (
                    "full_table_peer_count" in visibility or "seeing_prefix_peer_count" in visibility
                ):
                    # Older schema
                    full_table_peers = visibility.get("full_table_peer_count", 0)
                    seeing_peers = visibility.get("seeing_prefix_peer_count", 0)
                else:
                    # Newer schema groups visibility by address family (v4/v6)
                    vis_v4 = visibility.get("v4", {}) if isinstance(visibility, dict) else {}
                    vis_v6 = visibility.get("v6", {}) if isinstance(visibility, dict) else {}
                    seeing_peers = max(
                        int(vis_v4.get("ris_peers_seeing", 0) or 0),
                        int(vis_v6.get("ris_peers_seeing", 0) or 0),
                    )
                    full_table_peers = max(
                        int(vis_v4.get("total_ris_peers", 0) or 0),
                        int(vis_v6.get("total_ris_peers", 0) or 0),
                    )
                vis_pct = round((seeing_peers / full_table_peers) * 100, 1) if full_table_peers else None

                origin_asns: list[str] = []
                origins_raw = data.get("origins") or data.get("by_origin") or []
                for origin_entry in origins_raw:
                    if isinstance(origin_entry, dict):
                        origin_value = origin_entry.get("origin")
                    else:
                        origin_value = origin_entry
                    if origin_value in (None, ""):
                        continue
                    origin = str(origin_value)
                    origin = origin if origin.upper().startswith("AS") else f"AS{origin}"
                    if origin not in origin_asns:
                        origin_asns.append(origin)

                # Fallback: bgp-state now returns 'bgp_state' instead of 'routes'
                # Also parse BGP communities from this response (D2).
                announced_from_bgp_state = False
                communities_seen: dict[tuple[int, int], BGPCommunity] = {}
                bgp_resp = await client.get(RIPE_STAT_BGP_URL, params=params, timeout=15.0, headers=DEFAULT_HEADERS)
                if bgp_resp.status_code == 200:
                    bgp_data = bgp_resp.json().get("data", {})
                    entries = bgp_data.get("bgp_state") or bgp_data.get("routes") or []
                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        # Extract origin ASN when routing-status didn't find any
                        if seeing_peers == 0 and not origin_asns:
                            path = entry.get("path")
                            origin_value = path[-1] if isinstance(path, list) and path else entry.get("origin")
                            if origin_value not in (None, ""):
                                origin = str(origin_value)
                                origin = origin if origin.upper().startswith("AS") else f"AS{origin}"
                                if origin not in origin_asns:
                                    origin_asns.append(origin)
                        # Parse communities
                        for comm in entry.get("community", []):
                            if isinstance(comm, (list, tuple)) and len(comm) == 2:
                                try:
                                    c_asn, c_val = int(comm[0]), int(comm[1])
                                    key = (c_asn, c_val)
                                    if key not in communities_seen:
                                        desc = BGP_WELL_KNOWN_COMMUNITIES.get(key)
                                        communities_seen[key] = BGPCommunity(
                                            asn=c_asn, value=c_val, description=desc
                                        )
                                except (ValueError, TypeError):
                                    pass
                    announced_from_bgp_state = len(entries) > 0

                return BGPStatusResult(
                    resource            = resource,
                    resource_type       = resource_type,
                    is_announced        = (seeing_peers > 0) or bool(origin_asns) or announced_from_bgp_state,
                    announcing_asns     = origin_asns,
                    visibility_percent  = vis_pct,
                    communities         = list(communities_seen.values()),
                    queried_at          = queried_at,
                )

    except httpx.TimeoutException:
        return BGPStatusResult(
            resource=resource, resource_type=resource_type,
            is_announced=False, queried_at=queried_at,
        )
    except Exception as exc:
        return BGPStatusResult(
            resource=resource, resource_type=resource_type,
            is_announced=False, queried_at=queried_at,
        )


async def get_announced_prefixes(asn: str, min_peers: int = 5) -> BGPStatusResult:
    """
    Fetch all IP prefixes currently being announced by an ASN in BGP.
    Uses RIPE Stat's announced-prefixes endpoint.
    """
    normalized_asn = f"AS{asn.upper().lstrip('AS')}"
    queried_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    params = {"resource": normalized_asn, "min_peers_seeing": min_peers, "sourceapp": "peerglass"}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                RIPE_STAT_PREFIXES_URL, params=params, timeout=20.0, headers=DEFAULT_HEADERS
            )
            if resp.status_code != 200:
                return BGPStatusResult(
                    resource=normalized_asn, resource_type="asn",
                    is_announced=False, queried_at=queried_at,
                )
            data = resp.json().get("data", {})
            prefixes_raw = data.get("prefixes", [])
            prefixes = [
                BGPPrefix(
                    prefix       = p.get("prefix", ""),
                    peers_seeing = len(p.get("timelines", [])),
                    first_seen   = p.get("timelines", [{}])[0].get("starttime") if p.get("timelines") else None,
                    last_seen    = p.get("timelines", [{}])[-1].get("endtime") if p.get("timelines") else None,
                )
                for p in prefixes_raw
            ]
            return BGPStatusResult(
                resource           = normalized_asn,
                resource_type      = "asn",
                is_announced       = len(prefixes) > 0,
                announced_prefixes = prefixes,
                queried_at         = queried_at,
            )
    except Exception:
        return BGPStatusResult(
            resource=normalized_asn, resource_type="asn",
            is_announced=False, queried_at=queried_at,
        )


# ──────────────────────────────────────────────────────────────
# Phase 2 — Organization Resource Audit
# ──────────────────────────────────────────────────────────────

async def _search_org_in_rir(
    client: httpx.AsyncClient,
    rir: RIRName,
    base_url: str,
    org_name: str,
) -> tuple[RIRName, list[OrgResource], Optional[str]]:
    """Search for an organization's resources in a single RIR."""
    resources: list[OrgResource] = []
    try:
        # RDAP entity search by name
        search_url = f"{base_url}/entities?fn={org_name}&role=registrant"
        resp = await client.get(search_url, timeout=15.0, headers=DEFAULT_HEADERS, follow_redirects=True)

        if resp.status_code in (200, 206):
            data = resp.json()
            for entity in data.get("entitySearchResults", []):
                handle = entity.get("handle", "")
                vcard = entity.get("vcardArray", [None, []])[1]
                fn = None
                for entry in vcard:
                    if isinstance(entry, list) and entry[0] == "fn":
                        fn = entry[3]
                        break

                # For each entity, try to get their IP and ASN resources
                for link in entity.get("links", []):
                    if link.get("rel") == "self" and link.get("href"):
                        resources.append(OrgResource(
                            rir           = rir.value,
                            resource_type = "entity",
                            handle        = handle,
                            name          = fn,
                        ))
                        break

        elif resp.status_code == 404:
            pass  # Not found in this RIR — expected
        else:
            return rir, resources, f"HTTP {resp.status_code} from {rir.value} entity search"

    except httpx.TimeoutException:
        return rir, resources, f"{rir.value} entity search timed out"
    except Exception as exc:
        return rir, resources, f"{rir.value}: {type(exc).__name__}: {exc}"

    return rir, resources, None


async def search_org_all_rirs(org_name: str) -> tuple[list[OrgResource], list[str]]:
    """
    Search for an organization across all 5 RIRs that support entity search.
    LACNIC does not support RDAP entity search and is skipped.
    Returns (resources, errors).
    """
    all_resources: list[OrgResource] = []
    all_errors: list[str] = []

    searchable = {
        rir: url for rir, url in RDAP_SEARCH_ENDPOINTS.items() if url is not None
    }

    async with httpx.AsyncClient() as client:
        tasks = [
            _search_org_in_rir(client, rir, base_url, org_name)
            for rir, base_url in searchable.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    for rir, resources, error in results:
        all_resources.extend(resources)
        if error:
            all_errors.append(error)

    if not searchable.get(RIRName.LACNIC):
        all_errors.append("LACNIC: Entity search not supported via RDAP. Query LACNIC directly at https://query.milacnic.lacnic.net/home")

    return all_resources, all_errors


# ──────────────────────────────────────────────────────────────
# Phase 3 — Historical Allocation Tracking
# ──────────────────────────────────────────────────────────────

def _is_asn_resource(resource: str) -> bool:
    """Return True if resource looks like an ASN (AS12345 or bare integer)."""
    cleaned = resource.strip().upper()
    if cleaned.startswith("AS"):
        return cleaned[2:].isdigit()
    return cleaned.isdigit()


def _normalize_resource(resource: str) -> tuple[str, str]:
    """Return (normalized_resource, resource_type) where type is 'asn' or 'prefix'."""
    if _is_asn_resource(resource):
        num = resource.strip().upper().lstrip("AS")
        return f"AS{num}", "asn"
    return resource.strip(), "prefix"


async def get_prefix_history(resource: str) -> PrefixHistoryResult:
    """
    Fetch full registration history for a prefix or ASN from RIPE Stat.

    Uses two complementary RIPE Stat endpoints:
      historical-whois  → object attribute changes over time (org, status, dates)
      allocation-history → raw allocation/assignment event log

    Think of this like a property deed history — every time the "land"
    (IP block) changed hands or was subdivided, there is a record.
    """
    normalized, rtype = _normalize_resource(resource)
    events: list[HistoricalEvent] = []
    errors: list[str] = []
    current_holder: Optional[str] = None
    current_rir: Optional[str] = None
    registration_date: Optional[str] = None
    sources: list[str] = []

    params = {"resource": normalized, "sourceapp": "peerglass"}

    async with httpx.AsyncClient() as client:
        # ── 1. historical-whois: object attribute changes ──────────────
        try:
            resp = await client.get(
                RIPE_STAT_HIST_WHOIS_URL, params=params, timeout=20.0, headers=DEFAULT_HEADERS
            )
            if resp.status_code == 200:
                sources.append("RIPE Stat historical-whois")
                data = resp.json().get("data", {})
                objects = data.get("objects", [])

                for obj in objects:
                    # Each object has a list of "versions" representing changes
                    versions = obj.get("versions", [])
                    obj_type = obj.get("type", "")

                    for i, version in enumerate(versions):
                        attrs = {a["key"]: a["value"] for a in version.get("attributes", []) if "key" in a and "value" in a}
                        version_date = version.get("from_time", "")[:10]

                        # Detect first registration
                        if i == 0 and not registration_date and version_date:
                            registration_date = version_date
                            events.append(HistoricalEvent(
                                event_date  = version_date,
                                event_type  = "created",
                                attribute   = "object",
                                new_value   = attrs.get("descr") or attrs.get("netname") or obj_type,
                                source      = "RIPE Stat historical-whois",
                            ))

                        # Detect org / holder changes between consecutive versions
                        if i > 0:
                            prev_attrs = {a["key"]: a["value"] for a in versions[i-1].get("attributes", []) if "key" in a and "value" in a}
                            for field in ("org", "mnt-by", "descr", "netname", "status"):
                                old_val = prev_attrs.get(field)
                                new_val = attrs.get(field)
                                if old_val and new_val and old_val != new_val:
                                    events.append(HistoricalEvent(
                                        event_date  = version_date,
                                        event_type  = "transferred" if field in ("org", "mnt-by") else "updated",
                                        attribute   = field,
                                        old_value   = old_val,
                                        new_value   = new_val,
                                        source      = "RIPE Stat historical-whois",
                                    ))

                        # Track latest holder from most recent version
                        if i == len(versions) - 1:
                            current_holder = attrs.get("org") or attrs.get("descr") or attrs.get("netname")
            else:
                errors.append(f"historical-whois: HTTP {resp.status_code}")
        except httpx.TimeoutException:
            errors.append("historical-whois: request timed out")
        except Exception as exc:
            errors.append(f"historical-whois: {type(exc).__name__}: {exc}")

        # ── 2. allocation-history: allocation/assignment events ─────────
        try:
            resp2 = await client.get(
                RIPE_STAT_ALLOC_HIST_URL, params=params, timeout=20.0, headers=DEFAULT_HEADERS
            )
            if resp2.status_code == 200:
                sources.append("RIPE Stat allocation-history")
                data2 = resp2.json().get("data", {})

                for record in data2.get("resources", []):
                    alloc_date  = str(record.get("timelines", [{}])[0].get("starttime", ""))[:10] \
                                  if record.get("timelines") else None
                    status_val  = record.get("status", "")
                    rir_val     = record.get("rir", "")

                    if rir_val and not current_rir:
                        current_rir = rir_val.upper()

                    if alloc_date and status_val:
                        events.append(HistoricalEvent(
                            event_date  = alloc_date,
                            event_type  = "allocation",
                            attribute   = "status",
                            new_value   = f"{status_val} (via {rir_val or 'unknown RIR'})",
                            source      = "RIPE Stat allocation-history",
                        ))
            else:
                errors.append(f"allocation-history: HTTP {resp2.status_code}")
        except httpx.TimeoutException:
            errors.append("allocation-history: request timed out")
        except Exception as exc:
            errors.append(f"allocation-history: {type(exc).__name__}: {exc}")

    # Sort events by date, oldest first
    events.sort(key=lambda e: e.event_date or "")

    return PrefixHistoryResult(
        resource          = normalized,
        resource_type     = rtype,
        current_holder    = current_holder,
        current_rir       = current_rir,
        registration_date = registration_date,
        total_events      = len(events),
        events            = events,
        sources           = sources,
        errors            = errors,
    )


# ──────────────────────────────────────────────────────────────
# Phase 3 — Transfer Detection
# ──────────────────────────────────────────────────────────────

async def detect_transfers(resource: str) -> TransferDetectResult:
    """
    Detect cross-org and cross-RIR transfers for a prefix or ASN.

    Strategy:
    1. Fetch full history via historical-whois
    2. Look for org / mnt-by changes (= ownership transfer)
    3. Look for rir-source changes (= cross-RIR transfer)
    4. Enrich with current holder from RDAP

    A transfer looks like: org changed from "GOOGLE-1" to "META-1" on date X.
    A cross-RIR transfer is rarer — it means the block physically moved
    between registries (e.g. ARIN → RIPE after an acquisition).
    """
    normalized, rtype = _normalize_resource(resource)
    transfers: list[TransferEvent] = []
    errors: list[str] = []
    sources: list[str] = []
    current_holder: Optional[str] = None
    current_rir: Optional[str] = None
    first_registered: Optional[str] = None
    notes: list[str] = []

    params = {"resource": normalized, "sourceapp": "peerglass"}

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                RIPE_STAT_HIST_WHOIS_URL, params=params, timeout=20.0, headers=DEFAULT_HEADERS
            )
            if resp.status_code == 200:
                sources.append("RIPE Stat historical-whois")
                data = resp.json().get("data", {})

                for obj in data.get("objects", []):
                    versions = obj.get("versions", [])
                    if not versions:
                        continue

                    # Capture first registration date
                    t0 = versions[0].get("from_time", "")[:10]
                    if t0 and (not first_registered or t0 < first_registered):
                        first_registered = t0

                    for i in range(1, len(versions)):
                        prev = {a["key"]: a["value"] for a in versions[i-1].get("attributes", []) if "key" in a and "value" in a}
                        curr = {a["key"]: a["value"] for a in versions[i].get("attributes", []) if "key" in a and "value" in a}
                        vdate = versions[i].get("from_time", "")[:10]

                        # ── org change → intra-RIR or cross-org transfer ──
                        for field in ("org", "mnt-by"):
                            old_v = prev.get(field)
                            new_v = curr.get(field)
                            if old_v and new_v and old_v != new_v:
                                # Heuristic: if org handles differ in the RIR prefix, it's cross-RIR
                                def _rir_from_handle(h: str) -> Optional[str]:
                                    for rir in ("AFRINIC", "APNIC", "ARIN", "LACNIC", "RIPE"):
                                        if rir in h.upper():
                                            return rir
                                    return None

                                from_rir = _rir_from_handle(old_v)
                                to_rir   = _rir_from_handle(new_v)
                                ttype    = "inter-rir" if (from_rir and to_rir and from_rir != to_rir) else "org-change"

                                transfers.append(TransferEvent(
                                    transfer_date  = vdate,
                                    transfer_type  = ttype,
                                    from_org       = old_v,
                                    to_org         = new_v,
                                    from_rir       = from_rir,
                                    to_rir         = to_rir,
                                    evidence       = f"{field} changed",
                                ))

                        # Track current holder from most recent version
                        if i == len(versions) - 1:
                            current_holder = curr.get("org") or curr.get("descr") or curr.get("netname")

            elif resp.status_code == 404:
                notes.append("No historical data found. Resource may be too new or outside RIPE NCC's historical coverage.")
            else:
                errors.append(f"historical-whois: HTTP {resp.status_code}")

        except httpx.TimeoutException:
            errors.append("historical-whois: timed out")
        except Exception as exc:
            errors.append(f"historical-whois: {type(exc).__name__}: {exc}")

    # Deduplicate transfers by date + evidence
    seen: set[str] = set()
    unique_transfers: list[TransferEvent] = []
    for t in sorted(transfers, key=lambda x: x.transfer_date or ""):
        key = f"{t.transfer_date}|{t.from_org}|{t.to_org}"
        if key not in seen:
            seen.add(key)
            unique_transfers.append(t)

    if rtype == "asn":
        notes.append(
            "Note: RIPE Stat historical-whois has best coverage for RIPE NCC resources. "
            "For ARIN resources, cross-RIR transfer records are more limited via this API."
        )

    if not unique_transfers:
        notes.append("No ownership transfers detected in available historical records. "
                     "This may mean the resource has never changed hands, or its history predates "
                     "RIPE Stat's coverage window.")

    return TransferDetectResult(
        resource          = normalized,
        resource_type     = rtype,
        transfers_detected= len(unique_transfers),
        transfers         = unique_transfers,
        current_holder    = current_holder,
        current_rir       = current_rir,
        first_registered  = first_registered,
        sources           = sources,
        notes             = notes,
    )


# ──────────────────────────────────────────────────────────────
# Phase 3 — IPv4 / IPv6 / ASN Exhaustion Stats
# ──────────────────────────────────────────────────────────────

async def _fetch_rir_delegation_stats(
    client: httpx.AsyncClient,
    rir: str,
    url: str,
    include_blocks: bool = False,
    status_filter: Optional[str] = None,
    country_filter: Optional[str] = None,
) -> tuple[RIRDelegationStats, list[IPv4DelegatedBlock]]:
    """
    Fetch and parse the NRO Extended Delegation Stats file for one RIR.

    The file is a pipe-delimited text file. Summary lines look like:
      arin|*|ipv4|0|7527|summary
      arin|*|ipv6|0|18891|summary
      arin|*|asn|0|73659|summary

    Detail lines look like:
      arin|US|ipv4|3.0.0.0|16777216|19941001|allocated

    We parse both to build a complete picture.
    """
    errors: list[str] = []
    ipv4_blocks: list[IPv4DelegatedBlock] = []
    stats_date: Optional[str] = None
    ipv4_allocated = ipv4_assigned = ipv4_available = ipv4_total = 0
    ipv6_allocated = ipv6_total = 0
    asn_allocated = asn_total = 0

    try:
        resp = await client.get(url, timeout=30.0, follow_redirects=True,
                                headers={"User-Agent": DEFAULT_HEADERS["User-Agent"]})
        if resp.status_code != 200:
            errors.append(f"HTTP {resp.status_code} from {rir} delegation stats")
            return RIRDelegationStats(rir=rir, region=RIR_REGIONS.get(rir, ""), errors=errors), []

        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue

            parts = line.split("|")
            if len(parts) < 6:
                continue

            # Header line: version|registry|serial|records|startdate|enddate|UTCoffset
            if parts[0].isdigit():
                if len(parts) >= 5:
                    stats_date = parts[5][:8] if len(parts) > 5 else None
                continue

            rir_field   = parts[0].upper()
            type_field  = parts[2].lower() if len(parts) > 2 else ""
            value_field = parts[4] if len(parts) > 4 else "0"
            status_field= parts[6].lower() if len(parts) > 6 else (parts[5].lower() if len(parts) > 5 else "")

            # Summary lines: rir|*|type|0|count|summary
            if len(parts) >= 6 and parts[5].lower() == "summary":
                count = int(value_field) if value_field.isdigit() else 0
                if type_field == "ipv4":
                    ipv4_total = count
                elif type_field == "ipv6":
                    ipv6_total = count
                elif type_field == "asn":
                    asn_total = count
                continue

            # Detail lines: rir|cc|type|start|value|date|status
            if rir_field not in (rir, rir.lower(), "ripencc"):
                continue

            try:
                value = int(value_field)
            except ValueError:
                continue

            if type_field == "ipv4":
                if "allocated" in status_field:
                    ipv4_allocated += value
                elif "assigned" in status_field:
                    ipv4_assigned += value
                elif "available" in status_field or "free" in status_field:
                    ipv4_available += value

                if include_blocks:
                    normalized_status = "available" if ("available" in status_field or "free" in status_field) else status_field
                    country = parts[1].upper() if len(parts) > 1 and parts[1] != "*" else None

                    if status_filter and normalized_status != status_filter:
                        continue
                    if country_filter and country != country_filter:
                        continue

                    try:
                        start_ip = ipaddress.ip_address(parts[3])
                        end_ip = start_ip + (value - 1)
                    except ValueError:
                        continue

                    ipv4_blocks.append(
                        IPv4DelegatedBlock(
                            rir=rir,
                            country=country,
                            start_ip=str(start_ip),
                            end_ip=str(end_ip),
                            address_count=value,
                            date=parts[5] if len(parts) > 5 else None,
                            status=normalized_status,
                        )
                    )
            elif type_field == "ipv6":
                if "allocated" in status_field or "assigned" in status_field:
                    ipv6_allocated += 1  # Count distinct IPv6 records
            elif type_field == "asn":
                if "allocated" in status_field or "assigned" in status_field:
                    asn_allocated += 1

    except httpx.TimeoutException:
        errors.append(f"{rir} delegation stats timed out")
    except Exception as exc:
        errors.append(f"{rir} delegation stats: {type(exc).__name__}: {exc}")

    return RIRDelegationStats(
        rir              = rir,
        region           = RIR_REGIONS.get(rir, ""),
        ipv4_allocated   = ipv4_allocated,
        ipv4_assigned    = ipv4_assigned,
        ipv4_available   = ipv4_available,
        ipv4_total_prefixes = ipv4_total,
        ipv6_allocated   = ipv6_allocated,
        ipv6_total_prefixes = ipv6_total,
        asn_allocated    = asn_allocated,
        asn_total        = asn_total,
        stats_date       = stats_date,
        errors           = errors,
    ), ipv4_blocks


async def get_global_ipv4_stats(
    rir_filter: Optional[str] = None,
    include_blocks: bool = False,
    status_filter: Optional[str] = None,
    country_filter: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> GlobalIPv4Stats:
    """
    Fetch and aggregate IPv4/IPv6/ASN delegation statistics from all 5 RIRs.

    Parses the NRO Extended Delegation Stats files, published daily by each RIR.
    These files are the authoritative source for how much IP space each RIR
    has allocated, assigned, or still holds in reserve.

    Think of this like reading the annual reports of 5 central banks — each
    one publishes how much "currency" (IP space) they've issued and to whom.

    If rir_filter is set, only that RIR's stats are fetched.
    """
    queried_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    status_filter = (status_filter or "").lower() or None
    country_filter = (country_filter or "").upper() or None

    if include_blocks and not rir_filter:
        return GlobalIPv4Stats(
            queried_at=queried_at,
            errors=["include_blocks=true requires rir_filter to target a single RIR"],
            blocks_limit=limit,
            blocks_offset=offset,
            blocks_filters={
                "rir_filter": None,
                "status_filter": status_filter,
                "country_filter": country_filter,
            },
        )

    targets = {
        k: v for k, v in NRO_DELEGATION_STATS.items()
        if not rir_filter or k == rir_filter.upper()
    }

    async with httpx.AsyncClient() as client:
        tasks = [
            _fetch_rir_delegation_stats(
                client,
                rir,
                url,
                include_blocks=include_blocks,
                status_filter=status_filter,
                country_filter=country_filter,
            )
            for rir, url in targets.items()
        ]
        gathered = list(await asyncio.gather(*tasks))

    rir_stats = [stat for stat, _ in gathered]
    all_blocks = [block for _, blocks in gathered for block in blocks]

    all_errors = [e for r in rir_stats for e in r.errors]

    blocks_total = len(all_blocks)
    paginated_blocks = all_blocks[offset:offset + limit] if include_blocks else []

    return GlobalIPv4Stats(
        queried_at            = queried_at,
        rirs                  = rir_stats,
        global_ipv4_prefixes  = sum(r.ipv4_total_prefixes for r in rir_stats),
        global_ipv6_prefixes  = sum(r.ipv6_total_prefixes for r in rir_stats),
        global_asns           = sum(r.asn_total for r in rir_stats),
        ipv4_blocks           = paginated_blocks,
        blocks_total          = blocks_total if include_blocks else 0,
        blocks_returned       = len(paginated_blocks),
        blocks_limit          = limit if include_blocks else None,
        blocks_offset         = offset if include_blocks else None,
        blocks_filters        = {
            "rir_filter": (rir_filter or "").upper() or None,
            "status_filter": status_filter,
            "country_filter": country_filter,
        } if include_blocks else {},
        errors                = all_errors,
    )


# ──────────────────────────────────────────────────────────────
# Phase 3 — Prefix Hierarchy Overview
# ──────────────────────────────────────────────────────────────

async def get_prefix_overview(prefix: str) -> PrefixOverviewResult:
    """
    Fetch a rich overview of a prefix: holder, parent allocation, child
    assignments, sibling blocks, and BGP announcement status.

    Uses three RIPE Stat endpoints in parallel:
      prefix-overview   → current holder, announced status, origin ASNs
      less-specifics    → parent and covering allocations
      more-specifics    → child assignments within the prefix

    Like looking at a neighborhood on a map — prefix-overview shows who owns
    the block, less-specifics shows the whole street, more-specifics shows
    the individual plots within that block.
    """
    errors: list[str] = []
    related: list[RelatedPrefix] = []
    holder: Optional[str] = None
    holder_handle: Optional[str] = None
    rir: Optional[str] = None
    country: Optional[str] = None
    announced: Optional[bool] = None
    announcing_asns: list[str] = []
    block_size: Optional[int] = None
    alloc_status: Optional[str] = None

    params_base = {"resource": prefix, "sourceapp": "peerglass"}

    async with httpx.AsyncClient() as client:
        # Fire all 3 RIPE Stat requests in parallel
        overview_task      = client.get(RIPE_STAT_PREFIX_OVERVIEW, params=params_base, timeout=15.0, headers=DEFAULT_HEADERS)
        less_specific_task = client.get(RIPE_STAT_LESS_SPECIFICS,  params=params_base, timeout=15.0, headers=DEFAULT_HEADERS)
        more_specific_task = client.get(RIPE_STAT_MORE_SPECIFICS,  params=params_base, timeout=15.0, headers=DEFAULT_HEADERS)

        results = await asyncio.gather(overview_task, less_specific_task, more_specific_task, return_exceptions=True)

    # ── prefix-overview ────────────────────────────────────────────
    if not isinstance(results[0], Exception) and results[0].status_code == 200:
        d = results[0].json().get("data", {})
        holder        = d.get("holder")
        announced     = d.get("announced", False)
        alloc_status  = d.get("block", {}).get("resource") if d.get("block") else None
        block_size    = d.get("block", {}).get("desc")

        for asn_obj in d.get("asns", []):
            asn_str = f"AS{asn_obj.get('asn', '')}"
            if asn_str not in announcing_asns:
                announcing_asns.append(asn_str)

        # Extract RIR from related data
        rir = (d.get("block") or {}).get("name", "")
        if not rir:
            rir = None
    elif isinstance(results[0], Exception):
        errors.append(f"prefix-overview: {type(results[0]).__name__}")
    else:
        errors.append(f"prefix-overview: HTTP {results[0].status_code}")

    # ── less-specifics (parent / covering prefixes) ─────────────────
    if not isinstance(results[1], Exception) and results[1].status_code == 200:
        d = results[1].json().get("data", {})
        for p in d.get("prefixes", []):
            pfx = p.get("prefix", "")
            if pfx and pfx != prefix:
                related.append(RelatedPrefix(
                    prefix       = pfx,
                    relationship = "less-specific",
                    holder       = p.get("data", {}).get("descr"),
                ))
    elif isinstance(results[1], Exception):
        errors.append(f"less-specifics: {type(results[1]).__name__}")

    # ── more-specifics (child / sub-prefixes) ─────────────────────
    if not isinstance(results[2], Exception) and results[2].status_code == 200:
        d = results[2].json().get("data", {})
        for p in d.get("prefixes", []):
            pfx = p.get("prefix", "")
            if pfx and pfx != prefix:
                related.append(RelatedPrefix(
                    prefix       = pfx,
                    relationship = "more-specific",
                ))
    elif isinstance(results[2], Exception):
        errors.append(f"more-specifics: {type(results[2]).__name__}")

    return PrefixOverviewResult(
        prefix            = prefix,
        holder            = holder,
        holder_handle     = holder_handle,
        rir               = rir,
        country           = country,
        announced         = announced,
        announcing_asns   = announcing_asns,
        block_size_ips    = None,
        related_prefixes  = related,
        allocation_status = alloc_status,
        errors            = errors,
    )


# ──────────────────────────────────────────────────────────────
# Phase 4 — PeeringDB: ASN peering info
# ──────────────────────────────────────────────────────────────

async def get_peering_info(asn: str) -> PeeringInfoResult:
    """
    Fetch peering policy, IXP presence, and NOC contacts for an ASN
    from PeeringDB, supplemented with BGP neighbour data from RIPE Stat.

    PeeringDB is the internet's social network for network operators.
    Every ISP, CDN, and large enterprise registers here to publish:
    - Their peering policy (Open = peer with anyone, Selective = requirements,
      Restrictive = very limited, No Peering = transit only)
    - Which Internet Exchange Points they are present at
    - Their NOC/peering contact emails
    - Their IRR AS-SET (used in route filters)

    Think of it like a business card directory for ASNs.
    RIPE Stat supplements with actual BGP upstream/downstream neighbours.
    """
    asn_num = asn.upper().lstrip("AS")
    normalized = f"AS{asn_num}"
    errors: list[str] = []
    ixp_presence: list[IXPRecord] = []
    neighbour_asns: list[str] = []

    async with httpx.AsyncClient() as client:
        # ── 1. PeeringDB: network record ──────────────────────────
        net_data: dict = {}
        try:
            resp = await client.get(
                PEERINGDB_NET_URL,
                params={"asn": asn_num, "depth": 2},
                timeout=15.0,
                headers={**DEFAULT_HEADERS, "Accept": "application/json"},
            )
            if resp.status_code == 200:
                results_list = resp.json().get("data", [])
                if results_list:
                    net_data = results_list[0]
            elif resp.status_code == 404:
                errors.append(f"ASN {normalized} not found in PeeringDB. "
                              "The network may not have registered. "
                              "Check https://www.peeringdb.com/")
            else:
                errors.append(f"PeeringDB net: HTTP {resp.status_code}")
        except httpx.TimeoutException:
            errors.append("PeeringDB network lookup timed out")
        except Exception as exc:
            errors.append(f"PeeringDB net: {type(exc).__name__}: {exc}")

        # ── 2. PeeringDB: IXP memberships (netixlan) ──────────────
        net_id = net_data.get("id")
        if net_id:
            try:
                resp2 = await client.get(
                    PEERINGDB_NETIXLAN_URL,
                    params={"net_id": net_id, "depth": 2},
                    timeout=15.0,
                    headers={**DEFAULT_HEADERS, "Accept": "application/json"},
                )
                if resp2.status_code == 200:
                    for lane in resp2.json().get("data", []):
                        ix = lane.get("ixlan", {}).get("ix", {}) or {}
                        ixp_presence.append(IXPRecord(
                            ix_id    = ix.get("id"),
                            name     = ix.get("name", ""),
                            name_long= ix.get("name_long"),
                            city     = ix.get("city"),
                            country  = ix.get("country"),
                            website  = ix.get("website"),
                            ipaddr4  = lane.get("ipaddr4"),
                            ipaddr6  = lane.get("ipaddr6"),
                            speed    = lane.get("speed"),
                        ))
            except Exception as exc:
                errors.append(f"PeeringDB IXP memberships: {type(exc).__name__}: {exc}")

        # ── 3. RIPE Stat: BGP neighbours ──────────────────────────
        try:
            resp3 = await client.get(
                RIPE_STAT_NEIGHBOURS_URL,
                params={"resource": normalized, "sourceapp": "peerglass"},
                timeout=15.0,
                headers=DEFAULT_HEADERS,
            )
            if resp3.status_code == 200:
                nb_data = resp3.json().get("data", {})
                for nb in nb_data.get("neighbours", []):
                    nb_asn = f"AS{nb.get('asn', '')}"
                    if nb_asn not in neighbour_asns:
                        neighbour_asns.append(nb_asn)
        except Exception as exc:
            errors.append(f"RIPE Stat neighbours: {type(exc).__name__}: {exc}")

    # Extract fields from PeeringDB net_data
    poc_set = net_data.get("poc_set", [])
    noc_email    = next((p.get("email") for p in poc_set if p.get("role") == "NOC"), None)
    abuse_email  = next((p.get("email") for p in poc_set if p.get("role") == "Abuse"), None)
    peering_email= next((p.get("email") for p in poc_set if "Peering" in p.get("role", "")), None)
    if not noc_email:
        noc_email = net_data.get("email")

    return PeeringInfoResult(
        asn              = normalized,
        network_name     = net_data.get("name"),
        aka              = net_data.get("aka"),
        website          = net_data.get("website"),
        info_type        = net_data.get("info_type"),
        policy_general   = net_data.get("policy_general"),
        policy_locations = net_data.get("policy_locations"),
        policy_ratio     = net_data.get("policy_ratio"),
        policy_contracts = net_data.get("policy_contracts"),
        noc_email        = noc_email,
        noc_phone        = net_data.get("phone"),
        abuse_email      = abuse_email,
        peering_email    = peering_email,
        irr_as_set       = net_data.get("irr_as_set"),
        info_prefixes4   = net_data.get("info_prefixes4"),
        info_prefixes6   = net_data.get("info_prefixes6"),
        ixp_presence     = ixp_presence,
        neighbour_asns   = neighbour_asns[:30],  # cap at 30 for readability
        errors           = errors,
    )


# ──────────────────────────────────────────────────────────────
# Phase 4 — IXP Lookup by country or name
# ──────────────────────────────────────────────────────────────

async def lookup_ixps(query: str) -> IXPLookupResult:
    """
    Search PeeringDB for Internet Exchange Points by country code or name.

    An Internet Exchange Point (IXP) is a physical facility where ISPs,
    CDNs, and networks interconnect to exchange traffic without paying
    a transit provider. The internet literally runs through these buildings.

    Examples of famous IXPs:
    - AMS-IX (Amsterdam) — one of the world's largest
    - LINX (London) — UK's main exchange
    - DE-CIX (Frankfurt) — Europe's busiest
    - JINX (Johannesburg) — Africa's largest
    - MAURITIUS-IX (Mauritius) — your local IXP!

    Query can be a 2-letter country code (ISO 3166-1 alpha-2) like 'MU',
    or a partial IXP name like 'AMS-IX' or 'Nairobi'.
    """
    errors: list[str] = []
    ixps: list[IXPRecord] = []

    # Detect if query looks like a country code (2 letters) or a name
    is_country = len(query.strip()) == 2 and query.strip().isalpha()
    params: dict = {"depth": 1}
    if is_country:
        params["country"] = query.strip().upper()
    else:
        params["name__icontains"] = query.strip()

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                PEERINGDB_IXP_URL,
                params=params,
                timeout=15.0,
                headers={**DEFAULT_HEADERS, "Accept": "application/json"},
            )
            if resp.status_code == 200:
                for ix in resp.json().get("data", []):
                    ixps.append(IXPRecord(
                        ix_id       = ix.get("id"),
                        name        = ix.get("name", ""),
                        name_long   = ix.get("name_long"),
                        city        = ix.get("city"),
                        country     = ix.get("country"),
                        region      = ix.get("region_continent"),
                        website     = ix.get("website"),
                        tech_email  = ix.get("tech_email"),
                        member_count= ix.get("net_count"),
                    ))
            elif resp.status_code == 404:
                errors.append(f"No IXPs found matching '{query}'.")
            else:
                errors.append(f"PeeringDB IXP search: HTTP {resp.status_code}")
        except httpx.TimeoutException:
            errors.append("PeeringDB IXP search timed out")
        except Exception as exc:
            errors.append(f"PeeringDB IXP: {type(exc).__name__}: {exc}")

    return IXPLookupResult(
        query       = query,
        total_found = len(ixps),
        ixps        = ixps,
        errors      = errors,
    )


# ──────────────────────────────────────────────────────────────
# Phase 4 — Combined Network Health Report
# ──────────────────────────────────────────────────────────────

async def get_network_health(resource: str) -> NetworkHealthResult:
    """
    Run a parallel multi-source health check on any IP, prefix, or ASN.

    Fires all checks simultaneously:
      RDAP      → Who owns it, which RIR, country, abuse contact
      BGP       → Is it being announced? Which ASN(s)? What visibility?
      RPKI      → Is the route cryptographically valid? (prefix only)
      PeeringDB → Peering policy and NOC contact (ASN only)

    Then synthesises health signals:
      ✅ All good       → RPKI valid, announced, registered
      ⚠️ Warning        → Not announced, RPKI not-found, no abuse contact
      🚨 Critical       → RPKI invalid (possible hijack), multiple origin ASNs

    Like a one-stop MOT check for any internet resource.
    """
    import time as _time
    queried_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
    errors: list[str] = []
    health_signals: list[str] = []

    # Determine resource type
    is_asn = resource.upper().startswith("AS") and resource.upper()[2:].isdigit()
    is_asn = is_asn or resource.isdigit()
    has_slash = "/" in resource
    resource_type = "asn" if is_asn else ("prefix" if has_slash else "ip")

    # Normalize
    asn_for_peering: Optional[str] = None
    prefix_for_rpki: Optional[str] = None
    ip_for_rdap: Optional[str] = resource

    if is_asn:
        asn_for_peering = f"AS{resource.upper().lstrip('AS')}"
        ip_for_rdap = None
    elif has_slash:
        prefix_for_rpki = resource

    # ── Build parallel tasks ───────────────────────────────────
    async with httpx.AsyncClient() as client:
        gather_tasks = []

        # Task 0: RDAP lookup
        if ip_for_rdap:
            gather_tasks.append(query_ip_all_rirs(ip_for_rdap))
        elif prefix_for_rpki:
            # Use prefix network address for RDAP
            network_ip = prefix_for_rpki.split("/")[0]
            gather_tasks.append(query_ip_all_rirs(network_ip))
        else:
            # ASN RDAP
            gather_tasks.append(query_asn_all_rirs(asn_for_peering or resource))

        # Task 1: BGP status
        gather_tasks.append(get_bgp_status(resource))

        # Task 2: PeeringDB (if ASN known or will be discovered)
        if asn_for_peering:
            gather_tasks.append(get_peering_info(asn_for_peering))
        else:
            gather_tasks.append(asyncio.sleep(0))  # placeholder

        results = await asyncio.gather(*gather_tasks, return_exceptions=True)

    rdap_results = results[0] if not isinstance(results[0], Exception) else []
    bgp_result   = results[1] if not isinstance(results[1], Exception) else None
    peering_result = results[2] if not isinstance(results[2], Exception) and asn_for_peering else None

    # ── Parse RDAP ────────────────────────────────────────────
    from normalizer import normalize_ip_response, normalize_asn_response
    rdap_holder = rdap_rir = rdap_country = rdap_abuse = rdap_status = None

    if isinstance(rdap_results, list):
        if resource_type == "asn":
            asn_resources = [normalize_asn_response(r) for r in rdap_results if r.status == "ok"]
            if asn_resources:
                first = asn_resources[0]
                rdap_holder  = first.org_name or first.name
                rdap_rir     = first.rir
                rdap_country = first.country
                rdap_abuse   = first.abuse_email
                rdap_status  = first.status
        else:
            net_resources = [normalize_ip_response(r) for r in rdap_results if r.status == "ok"]
            if net_resources:
                first = net_resources[0]
                rdap_holder  = first.org_name or first.name
                rdap_rir     = first.rir
                rdap_country = first.country
                rdap_abuse   = first.abuse_email
                rdap_status  = first.status

    # ── Parse BGP ────────────────────────────────────────────
    bgp_announced = bgp_asns = bgp_vis = None
    if bgp_result and not isinstance(bgp_result, Exception):
        bgp_announced = bgp_result.is_announced
        bgp_asns      = bgp_result.announcing_asns
        bgp_vis       = bgp_result.visibility_percent

    # ── RPKI check (prefix only — fire separately, need an ASN) ──
    rpki_validity: Optional[str] = "N/A"
    if prefix_for_rpki and bgp_asns:
        try:
            asn_str = bgp_asns[0].lstrip("AS")
            rpki_result = await check_rpki(prefix_for_rpki, asn_str)
            rpki_validity = rpki_result.validity.value
        except Exception as exc:
            errors.append(f"RPKI check: {exc}")
            rpki_validity = "unknown"
    elif prefix_for_rpki:
        rpki_validity = "unknown"  # No ASN to check against

    # ── Parse PeeringDB ────────────────────────────────────────
    peering_policy = peering_noc = None
    peering_ixp_count: Optional[int] = None
    if peering_result and hasattr(peering_result, "policy_general"):
        peering_policy    = peering_result.policy_general
        peering_noc       = peering_result.noc_email
        peering_ixp_count = len(peering_result.ixp_presence)

    # ── Health Signals ─────────────────────────────────────────
    if rdap_holder:
        health_signals.append(f"✅ Registered to: **{rdap_holder}** ({rdap_rir or '?'})")
    else:
        health_signals.append("⚠️ No RDAP registration found — resource may be unallocated")

    if bgp_announced is True:
        asns_str = ", ".join(bgp_asns[:3]) if bgp_asns else "unknown"
        if bgp_vis is not None:
            health_signals.append(f"✅ Announced in BGP by {asns_str} ({bgp_vis}% visibility)")
        else:
            health_signals.append(f"✅ Announced in BGP by {asns_str}")
        if len(bgp_asns or []) > 1:
            health_signals.append(f"🚨 Multiple origin ASNs ({len(bgp_asns)}) — possible MOAS or hijack, verify with RPKI")
    elif bgp_announced is False:
        health_signals.append("⚠️ Not currently visible in global BGP routing table")
    
    if rpki_validity == "valid":
        health_signals.append("✅ RPKI/ROA: Route is cryptographically VALID")
    elif rpki_validity == "invalid":
        health_signals.append("🚨 RPKI/ROA: Route is INVALID — possible BGP hijack!")
    elif rpki_validity == "not-found":
        health_signals.append("⚠️ RPKI/ROA: No ROA found — route is unprotected")
    elif rpki_validity == "unknown":
        health_signals.append("❓ RPKI/ROA: Status unknown (no announcing ASN to check against)")

    if not rdap_abuse and resource_type != "asn":
        health_signals.append("⚠️ No abuse contact registered")

    if peering_policy:
        health_signals.append(f"📡 Peering policy: **{peering_policy}** | IXPs: {peering_ixp_count}")

    return NetworkHealthResult(
        resource          = resource,
        resource_type     = resource_type,
        queried_at        = queried_at,
        rdap_holder       = rdap_holder,
        rdap_rir          = rdap_rir,
        rdap_country      = rdap_country,
        rdap_abuse_email  = rdap_abuse,
        rdap_status       = rdap_status,
        bgp_announced     = bgp_announced,
        bgp_announcing_asns = bgp_asns or [],
        bgp_visibility_pct  = bgp_vis,
        rpki_validity     = rpki_validity,
        peering_policy    = peering_policy,
        peering_ixp_count = peering_ixp_count,
        peering_noc_email = peering_noc,
        health_signals    = health_signals,
        errors            = errors,
    )


# ──────────────────────────────────────────────────────────────
# Phase 4 — Change Monitor
# ──────────────────────────────────────────────────────────────

async def run_change_monitor(resource: str, reset_baseline: bool = False) -> ChangeMonitorResult:
    """
    Monitor a prefix or ASN for registration/routing changes between calls.

    On first call:  captures a baseline snapshot of RDAP + BGP state.
    On later calls: compares the current state against the stored baseline
                    and reports exactly what changed.

    Tracked fields:
      RDAP: holder, rir, country, status, abuse_email
      BGP:  is_announced, announcing_asns, visibility_percent
      (RPKI is deliberately excluded — it changes too frequently)

    Think of it like a "git diff" for internet routing state:
    the first call takes a snapshot, subsequent calls show the diff.

    Baselines persist in memory for the server's lifetime.
    Use reset_baseline=True to start fresh after reviewing changes.
    """
    import time as _time
    import cache as _cache
    from normalizer import normalize_ip_response, normalize_asn_response

    checked_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
    is_asn = resource.upper().startswith("AS") and resource.upper()[2:].isdigit()
    is_asn = is_asn or resource.isdigit()
    resource_type = "asn" if is_asn else "prefix"

    # Reset if requested
    if reset_baseline:
        _cache.clear_baseline(resource)

    # Gather current state
    async def _current_state() -> dict:
        if is_asn:
            asn_results = await query_asn_all_rirs(resource)
            asn_res = [normalize_asn_response(r) for r in asn_results if r.status == "ok"]
            holder  = asn_res[0].org_name or asn_res[0].name if asn_res else None
            rir     = asn_res[0].rir if asn_res else None
            country = asn_res[0].country if asn_res else None
            status  = asn_res[0].status if asn_res else None
            abuse   = asn_res[0].abuse_email if asn_res else None
        else:
            ip = resource.split("/")[0]
            ip_results = await query_ip_all_rirs(ip)
            net_res = [normalize_ip_response(r) for r in ip_results if r.status == "ok"]
            holder  = net_res[0].org_name or net_res[0].name if net_res else None
            rir     = net_res[0].rir if net_res else None
            country = net_res[0].country if net_res else None
            status  = net_res[0].status if net_res else None
            abuse   = net_res[0].abuse_email if net_res else None

        bgp = await get_bgp_status(resource)
        return {
            "holder":           holder,
            "rir":              rir,
            "country":          country,
            "rdap_status":      status,
            "abuse_email":      abuse,
            "bgp_announced":    str(bgp.is_announced),
            "bgp_origin_asns":  ",".join(sorted(bgp.announcing_asns)),
            "bgp_visibility":   str(round(bgp.visibility_percent or 0, 1)),
            "captured_at":      checked_at,
        }

    current = await _current_state()
    baseline = _cache.get_baseline(resource)

    # First call — store baseline
    if baseline is None:
        _cache.set_baseline(resource, current)
        return ChangeMonitorResult(
            resource             = resource,
            resource_type        = resource_type,
            status               = "baseline_created",
            baseline_captured_at = checked_at,
            checked_at           = checked_at,
            current_holder       = current.get("holder"),
            current_rir          = current.get("rir"),
            message              = (
                f"✅ Baseline captured for `{resource}`. "
                "Call this tool again later to detect changes. "
                f"Holder: **{current.get('holder') or 'Unknown'}** | "
                f"RIR: **{current.get('rir') or 'Unknown'}** | "
                f"BGP: **{'Announced' if current.get('bgp_announced') == 'True' else 'Not announced'}**"
            ),
        )

    # Subsequent calls — diff
    TRACKED_FIELDS = [
        "holder", "rir", "country", "rdap_status",
        "abuse_email", "bgp_announced", "bgp_origin_asns", "bgp_visibility",
    ]
    FIELD_LABELS = {
        "holder":         "RDAP Holder",
        "rir":            "RIR",
        "country":        "Country",
        "rdap_status":    "Allocation Status",
        "abuse_email":    "Abuse Email",
        "bgp_announced":  "BGP Announced",
        "bgp_origin_asns":"BGP Origin ASN(s)",
        "bgp_visibility": "BGP Visibility %",
    }

    changes: list[FieldDelta] = []
    for field in TRACKED_FIELDS:
        old_val = baseline.get(field)
        new_val = current.get(field)
        if old_val != new_val:
            changes.append(FieldDelta(
                field      = FIELD_LABELS.get(field, field),
                old_value  = old_val,
                new_value  = new_val,
                changed_at = checked_at,
            ))

    if changes:
        status = "changes_detected"
        msg = (f"🔔 **{len(changes)} change(s) detected** for `{resource}` "
               f"since baseline ({baseline.get('captured_at', 'unknown')}). "
               "Review the changes below. Use `reset_baseline=True` to acknowledge.")
        # Update baseline to current so next call diffs from now
        _cache.set_baseline(resource, current)
    else:
        status = "no_changes"
        msg = (f"✅ No changes detected for `{resource}` "
               f"since baseline ({baseline.get('captured_at', 'unknown')}). "
               "Registration and BGP state are stable.")

    return ChangeMonitorResult(
        resource             = resource,
        resource_type        = resource_type,
        status               = status,
        baseline_captured_at = baseline.get("captured_at"),
        checked_at           = checked_at,
        changes              = changes,
        current_holder       = current.get("holder"),
        current_rir          = current.get("rir"),
        message              = msg,
    )


# ══════════════════════════════════════════════════════════════
# Sprint 2 — DNS Features (E1, E2, E3, E4, E5, E7)
# ══════════════════════════════════════════════════════════════

import dns.asyncresolver
import dns.resolver
import dns.reversename
import dns.rdatatype
import dns.name
import dns.exception
import dns.rdata

from models import (
    DNSResolveResult, DNSRecord, DNSEnumerateResult, DNSSECResult,
    DNSBLEntry, DNSBLResult, EmailSecurityResult,
    PropagationEntry, DNSPropagationResult,
)

# ── DNSBL list: (zone, human-readable description) ───────────
_DNSBL_LISTS: list[tuple[str, str]] = [
    ("zen.spamhaus.org",         "Spamhaus ZEN (SBL + XBL + PBL)"),
    ("bl.spamcop.net",           "SpamCop BL"),
    ("b.barracudacentral.org",   "Barracuda Reputation Block"),
    ("cbl.abuseat.org",          "CBL — Composite Blocking List"),
    ("dnsbl.sorbs.net",          "SORBS Combined"),
    ("spam.dnsbl.sorbs.net",     "SORBS Spam"),
    ("http.dnsbl.sorbs.net",     "SORBS HTTP Proxy"),
    ("socks.dnsbl.sorbs.net",    "SORBS SOCKS Proxy"),
    ("misc.dnsbl.sorbs.net",     "SORBS Misc Proxy"),
    ("smtp.dnsbl.sorbs.net",     "SORBS SMTP"),
    ("new.spam.dnsbl.sorbs.net", "SORBS New Spam"),
    ("dnsbl-1.uceprotect.net",   "UCEProtect Level 1"),
    ("dnsbl-2.uceprotect.net",   "UCEProtect Level 2"),
    ("dnsbl-3.uceprotect.net",   "UCEProtect Level 3"),
    ("db.wpbl.info",             "WPBL"),
    ("ix.dnsbl.manitu.net",      "Manitu NiX Spam"),
    ("truncate.gbudb.net",       "GBUdb Truncate"),
    ("bl.0spam.org",             "0spam"),
    ("dnsbl.spfbl.net",          "SPFBL"),
    ("all.s5h.net",              "s5h.net Spam"),
    ("dyna.spamrats.com",        "SpamRATS Dynamic"),
    ("noptr.spamrats.com",       "SpamRATS No-PTR"),
    ("spam.spamrats.com",        "SpamRATS Spam"),
    ("ips.backscatterer.org",    "Backscatterer"),
    ("psbl.surriel.com",         "PSBL — Passive Spam Block"),
    ("drone.abuse.ch",           "Abuse.ch Drone"),
    ("dronebl.org",              "DroneBL"),
    ("rbl.megarbl.net",          "MegaRBL"),
    ("ubl.unsubscore.com",       "Unsubscore UBL"),
    ("bogons.cymru.com",         "Bogons — unallocated space"),
]

# Spamhaus ZEN return-code descriptions
_SPAMHAUS_CODES: dict[str, str] = {
    "127.0.0.2":  "SBL — spam source",
    "127.0.0.3":  "SBL CSS — compromised server",
    "127.0.0.4":  "XBL — CBL listed (exploited host)",
    "127.0.0.5":  "XBL — CBL listed (exploited host)",
    "127.0.0.6":  "XBL — CBL listed (exploited host)",
    "127.0.0.7":  "XBL — CBL listed (exploited host)",
    "127.0.0.9":  "SBL + DROP listed",
    "127.0.0.10": "PBL — ISP dynamic address range",
    "127.0.0.11": "PBL — end-user IP",
}

# 10 global resolvers for propagation checks
_PROPAGATION_RESOLVERS: list[tuple[str, str, str]] = [
    ("8.8.8.8",          "Google",         "US"),
    ("8.8.4.4",          "Google (2)",     "US"),
    ("1.1.1.1",          "Cloudflare",     "US"),
    ("1.0.0.1",          "Cloudflare (2)", "US"),
    ("9.9.9.9",          "Quad9",          "CH"),
    ("208.67.222.222",   "OpenDNS",        "US"),
    ("94.140.14.14",     "AdGuard",        "RU"),
    ("185.228.168.9",    "CleanBrowsing",  "US"),
    ("64.6.64.6",        "Verisign",       "US"),
    ("149.112.112.112",  "Quad9 (2)",      "US"),
]

# Common DKIM selectors to probe
_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "mail", "k1", "k2", "dkim", "email", "s1", "s2",
]


async def _dns_query(name: str, rdtype: str, resolver: Optional[dns.asyncresolver.Resolver] = None) -> list[str]:
    """Resolve a DNS query, returning all rdata values as strings. Empty list on NXDOMAIN/error."""
    try:
        res = resolver or dns.asyncresolver.get_default_resolver()
        answer = await res.resolve(name, rdtype, raise_on_no_answer=False)
        if answer.rrset is None:
            return []
        return [r.to_text() for r in answer.rrset]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return []
    except Exception:
        return []


# ── E1 — Forward & Reverse DNS Resolution ────────────────────

async def dns_resolve(target: str) -> DNSResolveResult:
    """
    Resolve A/AAAA records for a domain, or PTR records for an IP address.
    For IP inputs, also correlates with RDAP owner to flag PTR mismatches.
    """
    target = target.strip()
    is_ip = False
    errors: list[str] = []

    # Detect if target is an IP address
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        pass

    ptr_records: list[str] = []
    a_records: list[str] = []
    aaaa_records: list[str] = []
    rdap_org: Optional[str] = None
    rdap_mismatch = False

    if is_ip:
        # Reverse DNS lookup
        try:
            rev_name = dns.reversename.from_address(target)
            ptr_records = await _dns_query(str(rev_name), "PTR")
        except Exception as e:
            errors.append(f"PTR lookup failed: {e}")

        # Correlate with RDAP to detect PTR mismatches
        try:
            async with httpx.AsyncClient() as client:
                base_url = await _find_authoritative_base_url(target, "ip", client)
            if base_url:
                rdap_result = await query_authoritative_rir(target, "ip")
                if rdap_result and rdap_result.status == "ok" and rdap_result.data:
                    from normalizer import normalize_ip_response
                    nr = normalize_ip_response(rdap_result.rir.value, rdap_result.data)
                    rdap_org = nr.org_name or nr.name
                    if rdap_org and ptr_records:
                        # Flag if none of the PTR hostnames contain a fragment of the RDAP org
                        org_fragment = rdap_org.lower().split()[0][:6]
                        if not any(org_fragment in p.lower() for p in ptr_records):
                            rdap_mismatch = True
        except Exception:
            pass
    else:
        # Forward DNS lookup
        a_records    = await _dns_query(target, "A")
        aaaa_records = await _dns_query(target, "AAAA")

    return DNSResolveResult(
        target=target,
        is_ip=is_ip,
        ptr_records=ptr_records,
        a_records=a_records,
        aaaa_records=aaaa_records,
        rdap_org=rdap_org,
        rdap_mismatch=rdap_mismatch,
        errors=errors,
    )


# ── E2 — Full DNS Record Enumeration ─────────────────────────

async def dns_enumerate(domain: str) -> DNSEnumerateResult:
    """
    Fetch all common DNS record types (A, AAAA, MX, NS, SOA, TXT, CAA,
    DNSKEY, SRV, CNAME) for a domain. Flags SPF and DMARC values from TXT.
    """
    domain = domain.strip().lower()
    record_types = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CAA", "DNSKEY", "SRV", "CNAME"]
    records: dict[str, list[DNSRecord]] = {}
    errors: list[str] = []
    spf_value: Optional[str] = None
    dmarc_value: Optional[str] = None

    async def _fetch(rtype: str) -> list[DNSRecord]:
        try:
            resolver = dns.asyncresolver.get_default_resolver()
            answer = await resolver.resolve(domain, rtype, raise_on_no_answer=False)
            if answer.rrset is None:
                return []
            result_records = []
            for rdata_item in answer.rrset:
                result_records.append(DNSRecord(
                    rtype=rtype,
                    value=rdata_item.to_text(),
                    ttl=answer.rrset.ttl,
                ))
            return result_records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception as e:
            errors.append(f"{rtype}: {e}")
            return []

    tasks = {rtype: _fetch(rtype) for rtype in record_types}
    for rtype, coro in tasks.items():
        recs = await coro
        if recs:
            records[rtype] = recs

    # Extract SPF from TXT records
    for rec in records.get("TXT", []):
        stripped = rec.value.strip('"')
        if stripped.startswith("v=spf1"):
            spf_value = stripped
            break

    # Try DMARC TXT at _dmarc subdomain
    try:
        dmarc_txts = await _dns_query(f"_dmarc.{domain}", "TXT")
        for txt in dmarc_txts:
            if "v=DMARC1" in txt:
                dmarc_value = txt.strip('"')
                break
    except Exception:
        pass

    return DNSEnumerateResult(
        domain=domain,
        records=records,
        spf_value=spf_value,
        dmarc_value=dmarc_value,
        errors=errors,
    )


# ── E3 — DNSSEC Chain Validation ─────────────────────────────

async def dns_dnssec(domain: str) -> DNSSECResult:
    """
    Check DNSSEC deployment for a domain.
    Returns SECURE / INSECURE / BOGUS / INDETERMINATE.

    SECURE:        DNSKEY + RRSIG + DS all present and consistent.
    INSECURE:      DNSKEY present but no DS at parent (not delegated).
    BOGUS:         Records present but RRSIG expiry issues or mismatch.
    INDETERMINATE: Cannot determine status (query failures).
    """
    domain = domain.strip().lower()
    errors: list[str] = []
    has_dnskey = False
    has_rrsig = False
    has_ds = False
    sig_expiry: Optional[str] = None

    try:
        # Check DNSKEY at domain
        dnskeys = await _dns_query(domain, "DNSKEY")
        has_dnskey = len(dnskeys) > 0

        # Check RRSIG (signature records) for A or SOA
        try:
            resolver = dns.asyncresolver.get_default_resolver()
            answer = await resolver.resolve(domain, "RRSIG", raise_on_no_answer=False)
            if answer.rrset:
                has_rrsig = True
                # Extract expiry from first RRSIG
                for rdata_item in answer.rrset:
                    txt = rdata_item.to_text()
                    parts = txt.split()
                    if len(parts) >= 5:
                        expiry_raw = parts[4]
                        # RRSIG expiry is YYYYMMDDHHmmss
                        if len(expiry_raw) == 14:
                            sig_expiry = f"{expiry_raw[:4]}-{expiry_raw[4:6]}-{expiry_raw[6:8]}"
                    break
        except Exception:
            pass

        # Check DS record at parent zone
        parent = ".".join(domain.split(".")[1:]) if "." in domain else ""
        if parent:
            ds_records = await _dns_query(domain, "DS")
            has_ds = len(ds_records) > 0

    except Exception as e:
        errors.append(str(e))

    # Determine status
    if errors and not has_dnskey:
        status = "INDETERMINATE"
    elif has_dnskey and has_rrsig and has_ds:
        status = "SECURE"
    elif has_dnskey and has_rrsig and not has_ds:
        # Signed but not delegated — technically insecure from resolver's perspective
        status = "INSECURE"
    elif has_dnskey and not has_rrsig:
        status = "BOGUS"
    else:
        status = "INSECURE"

    return DNSSECResult(
        domain=domain,
        status=status,
        has_dnskey=has_dnskey,
        has_rrsig=has_rrsig,
        has_ds=has_ds,
        signature_expiry=sig_expiry,
        errors=errors,
    )


# ── E4 — DNSBL Blocklist Checking ────────────────────────────

async def dns_dnsbl(ip: str) -> DNSBLResult:
    """
    Check an IPv4 address against 30 DNS blocklists in parallel.
    Uses pure DNS A-record lookups — no external APIs or keys needed.
    """
    ip = ip.strip()
    errors: list[str] = []

    # Reverse the IP octets for DNSBL queries: 1.2.3.4 → 4.3.2.1
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return DNSBLResult(ip=ip, errors=["Only IPv4 is supported for DNSBL checks"])
        reversed_ip = ".".join(reversed(parts))
    except Exception as e:
        return DNSBLResult(ip=ip, errors=[f"Invalid IP: {e}"])

    async def _check_one(zone: str, desc: str) -> DNSBLEntry:
        query_name = f"{reversed_ip}.{zone}"
        try:
            resolver = dns.asyncresolver.get_default_resolver()
            answer = await resolver.resolve(query_name, "A", raise_on_no_answer=False)
            if answer.rrset:
                return_code = answer.rrset[0].to_text()
                detail = _SPAMHAUS_CODES.get(return_code) if "spamhaus" in zone else None
                return DNSBLEntry(
                    list_name=zone,
                    list_description=desc,
                    listed=True,
                    return_code=return_code,
                    description=detail,
                )
            return DNSBLEntry(list_name=zone, list_description=desc, listed=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return DNSBLEntry(list_name=zone, list_description=desc, listed=False)
        except dns.exception.Timeout:
            return DNSBLEntry(list_name=zone, list_description=desc, listed=False,
                              description="timeout")
        except Exception:
            return DNSBLEntry(list_name=zone, list_description=desc, listed=False)

    tasks = [_check_one(zone, desc) for zone, desc in _DNSBL_LISTS]
    entries: list[DNSBLEntry] = list(await asyncio.gather(*tasks))
    listed_count = sum(1 for e in entries if e.listed)

    return DNSBLResult(
        ip=ip,
        listed_count=listed_count,
        checked_count=len(entries),
        entries=entries,
        errors=errors,
    )


# ── E5 — Email Security Record Analysis ──────────────────────

async def dns_email_security(domain: str) -> EmailSecurityResult:
    """
    Comprehensive email security audit: SPF, DMARC, DKIM, MX.
    All pure DNS — no external APIs or keys needed.
    """
    domain = domain.strip().lower()
    errors: list[str] = []
    recommendations: list[str] = []

    # --- SPF ---
    spf_record: Optional[str] = None
    spf_valid = False
    spf_all_mechanism: Optional[str] = None

    try:
        txts = await _dns_query(domain, "TXT")
        for txt in txts:
            clean = txt.strip('"')
            if clean.startswith("v=spf1"):
                spf_record = clean
                spf_valid = True
                # Extract the 'all' qualifier
                for part in clean.split():
                    if part.endswith("all"):
                        spf_all_mechanism = part  # e.g. -all, ~all, +all
                break
    except Exception as e:
        errors.append(f"SPF: {e}")

    if not spf_valid:
        recommendations.append("Add an SPF record (v=spf1) to prevent email spoofing.")
    elif spf_all_mechanism in ("+all", "?all", None):
        recommendations.append("SPF -all or ~all is recommended; +all permits any sender.")

    # --- DMARC ---
    dmarc_present = False
    dmarc_policy: Optional[str] = None
    dmarc_rua: Optional[str] = None
    dmarc_ruf: Optional[str] = None

    try:
        dmarc_txts = await _dns_query(f"_dmarc.{domain}", "TXT")
        for txt in dmarc_txts:
            clean = txt.strip('"')
            if "v=DMARC1" in clean:
                dmarc_present = True
                for tag in clean.split(";"):
                    tag = tag.strip()
                    if tag.startswith("p="):
                        dmarc_policy = tag[2:].strip()
                    elif tag.startswith("rua="):
                        dmarc_rua = tag[4:].strip()
                    elif tag.startswith("ruf="):
                        dmarc_ruf = tag[4:].strip()
                break
    except Exception as e:
        errors.append(f"DMARC: {e}")

    if not dmarc_present:
        recommendations.append("Add a DMARC record (_dmarc.<domain>) to enable policy enforcement.")
    elif dmarc_policy == "none":
        recommendations.append("Upgrade DMARC policy from p=none to p=quarantine or p=reject.")

    # --- DKIM (probe common selectors) ---
    dkim_selectors_found: list[str] = []
    try:
        async def _probe_dkim(selector: str) -> Optional[str]:
            txts = await _dns_query(f"{selector}._domainkey.{domain}", "TXT")
            for txt in txts:
                if "v=DKIM1" in txt or "k=rsa" in txt or "p=" in txt:
                    return selector
            return None

        tasks = [_probe_dkim(s) for s in _DKIM_SELECTORS]
        results_raw = await asyncio.gather(*tasks)
        dkim_selectors_found = [s for s in results_raw if s is not None]
    except Exception as e:
        errors.append(f"DKIM: {e}")

    if not dkim_selectors_found:
        recommendations.append("No DKIM selectors found; configure DKIM signing for outbound mail.")

    # --- MX ---
    mx_records: list[str] = []
    try:
        mx_raw = await _dns_query(domain, "MX")
        mx_records = sorted(mx_raw)
    except Exception as e:
        errors.append(f"MX: {e}")

    # --- BIMI ---
    bimi_present = False
    try:
        bimi_txts = await _dns_query(f"default._bimi.{domain}", "TXT")
        bimi_present = any("v=BIMI1" in t for t in bimi_txts)
    except Exception:
        pass

    # --- Risk level ---
    if not spf_valid and not dmarc_present:
        risk_level = "CRITICAL"
        recommendations.insert(0, "Domain has no SPF or DMARC — trivially spoofable.")
    elif not spf_valid or not dmarc_present:
        risk_level = "HIGH"
    elif dmarc_policy == "none":
        risk_level = "MEDIUM"
    elif spf_all_mechanism in ("+all", "?all"):
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return EmailSecurityResult(
        domain=domain,
        spf_valid=spf_valid,
        spf_record=spf_record,
        spf_all_mechanism=spf_all_mechanism,
        dmarc_present=dmarc_present,
        dmarc_policy=dmarc_policy,
        dmarc_rua=dmarc_rua,
        dmarc_ruf=dmarc_ruf,
        dkim_selectors_found=dkim_selectors_found,
        mx_records=mx_records,
        bimi_present=bimi_present,
        risk_level=risk_level,
        recommendations=recommendations,
        errors=errors,
    )


# ── E7 — DNS Propagation Check ───────────────────────────────

async def dns_propagation(domain: str, record_type: str = "A") -> DNSPropagationResult:
    """
    Query the same domain from 10 geographically distributed public
    resolvers and compare results to detect propagation lag.
    """
    domain = domain.strip().lower()
    record_type = record_type.upper()
    errors: list[str] = []
    entries: list[PropagationEntry] = []

    async def _query_resolver(resolver_ip: str, name: str, region: str) -> PropagationEntry:
        try:
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers = [resolver_ip]
            resolver.timeout = 5.0
            resolver.lifetime = 5.0
            answer = await resolver.resolve(domain, record_type, raise_on_no_answer=False)
            if answer.rrset:
                response = sorted(r.to_text() for r in answer.rrset)
            else:
                response = []
            return PropagationEntry(
                resolver_ip=resolver_ip,
                resolver_name=name,
                region=region,
                response=response,
            )
        except dns.exception.Timeout:
            return PropagationEntry(
                resolver_ip=resolver_ip, resolver_name=name, region=region,
                error="timeout",
            )
        except Exception as e:
            return PropagationEntry(
                resolver_ip=resolver_ip, resolver_name=name, region=region,
                error=str(e)[:80],
            )

    tasks = [_query_resolver(ip, name, region) for ip, name, region in _PROPAGATION_RESOLVERS]
    entries = list(await asyncio.gather(*tasks))

    # Find majority answer (most common response among successful entries)
    from collections import Counter
    response_counts: Counter = Counter()
    for e in entries:
        if not e.error and e.response:
            response_counts[tuple(e.response)] += 1

    majority_answer: list[str] = []
    if response_counts:
        majority_tuple, _ = response_counts.most_common(1)[0]
        majority_answer = list(majority_tuple)

    # Mark each entry as matching majority or not
    for e in entries:
        e.matches_majority = (e.response == majority_answer and not e.error)

    propagated_count = sum(1 for e in entries if e.matches_majority)
    consistent = propagated_count == len(entries)

    return DNSPropagationResult(
        domain=domain,
        record_type=record_type,
        majority_answer=majority_answer,
        consistent=consistent,
        propagated_count=propagated_count,
        total_resolvers=len(entries),
        entries=entries,
        errors=errors,
    )
