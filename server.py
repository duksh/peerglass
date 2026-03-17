"""
server.py — PeerGlass MCP Server (Phase 1 + 2 + 3 + 4)

Gives Claude the ability to query all 5 global Regional Internet Registries
simultaneously using RDAP (the modern JSON replacement for legacy WHOIS),
validate routes via RPKI, check BGP routing table visibility, audit
organization resources, trace full historical allocation timelines, and
integrate with PeeringDB for community peering intelligence.

Note on protocol: this server uses RDAP exclusively for live registry
queries. RDAP (RFC 7480–7484) is the IANA-mandated successor to legacy
WHOIS. The only place "historical-whois" appears is as the name of a
RIPE Stat API endpoint — that is the upstream API's own name, not our
protocol choice.

Phase 1 Tools (5):  RDAP registry lookups (Who owns this?)
Phase 2 Tools (4):  RPKI + BGP routing security (Is it valid/safe?)
Phase 3 Tools (4):  Historical timelines + global stats (What happened?)
Phase 4 Tools (4):  PeeringDB + IXP + health + monitoring (What's happening now?)
"""

import json
from mcp.server.fastmcp import FastMCP

import cache as cache_module
import rir_client
from models import (
    IPQueryInput,
    ASNQueryInput,
    AbuseContactInput,
    RPKICheckInput,
    BGPStatusInput,
    AnnouncedPrefixesInput,
    OrgAuditInput,
    PrefixHistoryInput,
    TransferDetectInput,
    IPv4StatsInput,
    PrefixOverviewInput,
    PeeringInfoInput,
    IXPLookupInput,
    NetworkHealthInput,
    ChangeMonitorInput,
    ResponseFormat,
    OrgAuditResult,
    DNSResolveInput,
    DNSEnumerateInput,
    DNSSECInput,
    DNSBLInput,
    EmailSecurityInput,
    DNSPropagationInput,
    TLSInspectInput,
    CTLogInput,
    ThreatIntelInput,
    PassiveDNSInput,
)
from normalizer import (
    normalize_ip_response,
    normalize_asn_response,
    extract_abuse_contact,
)
from formatters import (
    format_ip_results_md,
    format_asn_results_md,
    format_abuse_contact_md,
    format_rir_status_md,
    format_rpki_result_md,
    format_bgp_status_md,
    format_org_audit_md,
    format_prefix_history_md,
    format_transfer_detect_md,
    format_ipv4_stats_md,
    format_prefix_overview_md,
    format_peering_info_md,
    format_ixp_lookup_md,
    format_network_health_md,
    format_change_monitor_md,
    format_dns_resolve_md,
    format_dns_enumerate_md,
    format_dns_dnssec_md,
    format_dns_dnsbl_md,
    format_email_security_md,
    format_dns_propagation_md,
    format_tls_inspect_md,
    format_ct_logs_md,
    format_threat_intel_md,
    format_passive_dns_md,
    to_json,
)


# ──────────────────────────────────────────────────────────────
# MCP Server
# ──────────────────────────────────────────────────────────────

mcp = FastMCP(
    "peerglass",
    instructions="""
You are connected to PeerGlass — an internet resource intelligence MCP server.
Uses RDAP (the modern successor to legacy WHOIS) to query all 5 RIRs,
validates RPKI routes, checks BGP visibility, looks up PeeringDB peering
info and IXPs, runs combined health checks, and monitors resources for
registration and routing changes.

Quick tool selection guide:
  Who owns this IP / ASN?            → rir_query_ip / rir_query_asn
  Find abuse contact?                → rir_get_abuse_contact
  Is the BGP route RPKI valid?       → rir_check_rpki
  Is it announced in BGP?            → rir_check_bgp_status
  What prefixes does an ASN route?   → rir_get_announced_prefixes
  All resources for an org?          → rir_audit_org
  Full ownership history?            → rir_prefix_history
  Ever been transferred?             → rir_detect_transfers
  Global IPv4/IPv6 exhaustion stats? → rir_ipv4_stats
  Raw delegated IPv4 blocks?         → rir_ipv4_stats (include_blocks=true + rir_filter)
  Prefix parent/child hierarchy?     → rir_prefix_overview
  Peering policy + IXP presence?     → rir_peering_info
  IXPs in a country or by name?      → rir_ixp_lookup
  One-shot full health check?        → rir_network_health
  Detect registration/BGP changes?   → rir_change_monitor

Power workflows:
  BGP hijack:     rir_network_health → rir_check_rpki → rir_prefix_overview
  M&A due dilig.: rir_audit_org → rir_prefix_history → rir_detect_transfers
  NOC incident:   rir_network_health → rir_get_abuse_contact → rir_peering_info
  Ongoing watch:  rir_change_monitor (call repeatedly to detect drift)
""",
)


# ──────────────────────────────────────────────────────────────
# Tool 1 — Query IP Address
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_query_ip",
    annotations={
        "title":          "Query IP Address Across All 5 RIRs",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_query_ip(params: IPQueryInput) -> str:
    """
    Query all 5 global RIRs simultaneously for an IP address using RDAP.

    Fires parallel RDAP requests to AFRINIC, APNIC, ARIN, LACNIC, and RIPE NCC.
    Exactly one RIR will be authoritative; the others return 'not found'.
    Normalizes all responses into a unified schema and returns a clear summary.

    Results are cached for 1 hour to respect RIR rate limits.

    Args:
        params (IPQueryInput):
            - ip_address (str): IPv4 or IPv6 address e.g. '1.1.1.1', '2001:4860:4860::8888'
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Registration details including prefix, owner, country, allocation date,
             abuse email, and responses from all 5 RIRs.
             JSON schema:
             {
               "ip": str,
               "results":    [{"rir": str, "status": str, "error": str|null}],
               "normalized": [{"rir": str, "prefix": str, "name": str,
                               "org_name": str, "country": str,
                               "allocation_date": str, "abuse_email": str}]
             }
    """
    ip = params.ip_address.strip()
    cache_key = cache_module.make_ip_key(ip)
    cached = cache_module.get(cache_key)
    if cached:
        return cached["json"] if params.response_format == ResponseFormat.JSON else cached["markdown"]

    raw_results = await rir_client.query_ip_all_rirs(ip)

    normalized = []
    for result in raw_results:
        if result.status == "ok" and result.data:
            try:
                normalized.append(normalize_ip_response(result.rir.value, result.data))
            except Exception as exc:
                result.error = f"Normalization error: {exc}"

    md   = format_ip_results_md(ip, normalized, raw_results)
    jsn  = to_json({
        "ip":         ip,
        "results":    [r.model_dump(exclude={"data"}) for r in raw_results],
        "normalized": [n.model_dump(exclude={"raw"}) for n in normalized],
    })

    cache_module.set(cache_key, {"markdown": md, "json": jsn}, cache_module.TTL_IP)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 2 — Query ASN
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_query_asn",
    annotations={
        "title":          "Query ASN Across All 5 RIRs",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_query_asn(params: ASNQueryInput) -> str:
    """
    Query all 5 global RIRs simultaneously for an Autonomous System Number.

    An ASN is a unique number assigned to a network operator (ISP, CDN,
    large enterprise) that participates in BGP routing. Examples:
      AS15169 = Google, AS13335 = Cloudflare, AS36864 = AFRINIC itself.

    Accepts: 'AS15169', '15169', or named sets like 'AS-GOOGLE'.
    Results are cached for 1 hour.

    Args:
        params (ASNQueryInput):
            - asn (str): ASN in any format (e.g. 'AS15169', '13335', 'AS-CLOUDFLARE')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: ASN registration details including owner, country, allocation date,
             abuse email, and responses from all 5 RIRs.
             JSON schema:
             {
               "asn": str,
               "results":    [{"rir": str, "status": str}],
               "normalized": [{"rir": str, "asn": str, "name": str,
                               "org_name": str, "country": str, "abuse_email": str}]
             }
    """
    asn = params.asn.strip()
    cache_key = cache_module.make_asn_key(asn)
    cached = cache_module.get(cache_key)
    if cached:
        return cached["json"] if params.response_format == ResponseFormat.JSON else cached["markdown"]

    raw_results = await rir_client.query_asn_all_rirs(asn)

    normalized = []
    for result in raw_results:
        if result.status == "ok" and result.data:
            try:
                normalized.append(normalize_asn_response(result.rir.value, result.data))
            except Exception as exc:
                result.error = f"Normalization error: {exc}"

    md  = format_asn_results_md(asn, normalized, raw_results)
    jsn = to_json({
        "asn":        asn,
        "results":    [r.model_dump(exclude={"data"}) for r in raw_results],
        "normalized": [n.model_dump(exclude={"raw"}) for n in normalized],
    })

    cache_module.set(cache_key, {"markdown": md, "json": jsn}, cache_module.TTL_ASN)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 3 — Get Abuse Contact
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_get_abuse_contact",
    annotations={
        "title":          "Get Abuse Contact for an IP Address",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_get_abuse_contact(params: AbuseContactInput) -> str:
    """
    Find the abuse contact for any IP address globally using IANA bootstrap routing.

    Uses IANA RDAP Bootstrap to identify the authoritative RIR first (efficient),
    then queries only that RIR. Falls back to querying all 5 if bootstrap fails.
    Extracts abuse contacts from entity roles: 'abuse', 'technical', 'noc'.

    Use this tool as the first step in any network abuse reporting workflow:
    spam, DDoS attacks, port scanning, credential stuffing, etc.

    Results are cached for 1 hour.

    Args:
        params (AbuseContactInput):
            - ip_address (str): IPv4 or IPv6 address (e.g. '185.220.101.1')

    Returns:
        str: Markdown report with abuse email(s), phone(s), network name,
             organization, country, and authoritative RIR.
             JSON schema:
             {
               "ip_address": str,
               "authoritative_rir": str,
               "abuse_email": [str],
               "abuse_phone": [str],
               "network_name": str,
               "org_name": str,
               "country": str
             }
    """
    ip = params.ip_address.strip()
    cache_key = cache_module.make_abuse_key(ip)
    cached = cache_module.get(cache_key)
    if cached:
        return cached

    result = await rir_client.query_authoritative_rir(ip, "ip")
    if not result or not result.data:
        output = (
            f"## 🚨 Abuse Contact: `{ip}`\n\n"
            "> ⚠️ No registration data found for this address.\n"
            "> It may be private/reserved space (RFC 1918, RFC 4193) or the query failed.\n\n"
            "**Tip:** Run `rir_query_ip` for full diagnostics across all 5 RIRs.\n"
        )
        cache_module.set(cache_key, output, 300)
        return output

    contact = extract_abuse_contact(result.rir.value, ip, result.data)
    output  = format_abuse_contact_md(contact)
    cache_module.set(cache_key, output, cache_module.TTL_ABUSE)
    return output


# ──────────────────────────────────────────────────────────────
# Tool 4 — RIR Server Status
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_server_status",
    annotations={
        "title":          "Check Health of All 5 RIR RDAP Servers",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  False,
        "openWorldHint":   True,
    },
)
async def rir_server_status() -> str:
    """
    Check the real-time health of all 5 RIR RDAP servers simultaneously.

    Queries the /help endpoint of each RIR (lightweight, no IP/ASN needed).
    Returns RDAP conformance levels and availability status.

    Use this before bulk queries to verify connectivity, or to diagnose
    why a specific RIR's responses are failing.

    Returns:
        str: Markdown table with RIR name, region, status (Online/Unreachable),
             and supported RDAP conformance extensions.
    """
    stats = await rir_client.get_rir_server_status()
    stats_str = {str(k): v for k, v in stats.items()}
    return format_rir_status_md(stats_str)


# ──────────────────────────────────────────────────────────────
# Tool 5 — Cache Statistics
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_cache_stats",
    annotations={
        "title":          "View In-Memory Query Cache Statistics",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   False,
    },
)
async def rir_cache_stats() -> str:
    """
    View the current state of the in-memory TTL cache.

    The cache prevents repeated queries to RIRs within short windows,
    respecting rate limits and reducing latency for repeated lookups.

    Returns:
        str: JSON with cache entry counts (total, alive, expired)
             and the configured TTL for each query type.
             Schema:
             {
               "cache_stats": {"total_entries": int, "alive": int, "expired": int},
               "ttl_seconds": {"ip": int, "asn": int, "org": int,
                               "abuse": int, "bgp": int, "rpki": int}
             }
    """
    return json.dumps({
        "cache_stats": cache_module.stats(),
        "ttl_seconds": {
            "ip":    cache_module.TTL_IP,
            "asn":   cache_module.TTL_ASN,
            "org":   cache_module.TTL_ORG,
            "abuse": cache_module.TTL_ABUSE,
            "bgp":   cache_module.TTL_BGP,
            "rpki":  cache_module.TTL_RPKI,
        },
    }, indent=2)


# ──────────────────────────────────────────────────────────────
# Tool 6 — RPKI / ROA Validation  [Phase 2]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_check_rpki",
    annotations={
        "title":          "Validate RPKI/ROA Status for a Prefix + ASN",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_check_rpki(params: RPKICheckInput) -> str:
    """
    Validate a prefix + ASN pair against the global RPKI using Cloudflare's validator.

    RPKI (Resource Public Key Infrastructure) is the internet's route security
    framework. RIRs issue Route Origin Authorizations (ROAs) — digital certificates
    that cryptographically prove an ASN is authorized to announce a prefix.

    Validity states:
      ✅ VALID     — A matching ROA exists. Route is cryptographically authorized.
      🚨 INVALID   — A ROA exists but this ASN/prefix violates it. Possible hijack.
      ⚠️ NOT-FOUND — No ROA exists. Route is unverified (common, not inherently bad).
      ❓ UNKNOWN   — Could not determine validity.

    Combine with rir_check_bgp_status for full routing security assessment.

    Results are cached for 15 minutes (ROAs can change, but not frequently).

    Args:
        params (RPKICheckInput):
            - prefix (str): CIDR prefix e.g. '1.1.1.0/24' or '2400:cb00::/32'
            - asn (str): Originating ASN e.g. 'AS13335' or '13335'

    Returns:
        str: RPKI validity state, description, and list of covering ROAs.
             JSON schema:
             {
               "prefix": str, "asn": str,
               "validity": "valid"|"invalid"|"not-found"|"unknown",
               "covering_roas": [{"asn": int, "prefix": str, "maxLength": int}],
               "description": str
             }
    """
    cache_key = cache_module.make_rpki_key(params.prefix, params.asn)
    cached = cache_module.get(cache_key)
    if cached:
        return cached

    result = await rir_client.check_rpki(params.prefix, params.asn)
    output = format_rpki_result_md(result)
    cache_module.set(cache_key, output, cache_module.TTL_RPKI)
    return output


# ──────────────────────────────────────────────────────────────
# Tool 7 — BGP Routing Table Status  [Phase 2]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_check_bgp_status",
    annotations={
        "title":          "Check BGP Routing Table Visibility for a Prefix or ASN",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_check_bgp_status(params: BGPStatusInput) -> str:
    """
    Check whether a prefix or ASN is currently visible in the global BGP routing table.

    Uses RIPE Stat (which aggregates data from RIPE RIS route collectors worldwide).
    BGP is the internet's routing protocol — the "GPS" that tells traffic how to
    navigate from one network to another.

    For a prefix, returns:
      - Whether it is currently announced in BGP
      - Which ASN(s) are announcing it (multiple = potential hijack)
      - Percentage of global BGP peers that can see it (visibility)

    For an ASN, returns:
      - Whether the ASN has any active BGP announcements
      - A list of all announced prefixes (use rir_get_announced_prefixes for details)

    Combine with rir_check_rpki for complete routing security assessment.
    Results are cached for 5 minutes (BGP tables change frequently).

    Args:
        params (BGPStatusInput):
            - resource (str): Prefix (e.g. '1.1.1.0/24') or ASN (e.g. 'AS15169')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: BGP visibility, announcing ASNs, and prefix list.
             JSON schema:
             {
               "resource": str, "resource_type": str, "is_announced": bool,
               "announcing_asns": [str], "visibility_percent": float,
               "announced_prefixes": [{"prefix": str, "peers_seeing": int}]
             }
    """
    resource = params.resource.strip()
    cache_key = cache_module.make_bgp_key(resource)
    cached = cache_module.get(cache_key)
    if cached:
        return cached["json"] if params.response_format == ResponseFormat.JSON else cached["markdown"]

    result = await rir_client.get_bgp_status(resource)
    md  = format_bgp_status_md(result)
    jsn = to_json(result)

    cache_module.set(cache_key, {"markdown": md, "json": jsn}, cache_module.TTL_BGP)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 8 — Announced Prefixes by ASN  [Phase 2]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_get_announced_prefixes",
    annotations={
        "title":          "Get All BGP-Announced Prefixes for an ASN",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_get_announced_prefixes(params: AnnouncedPrefixesInput) -> str:
    """
    Retrieve all IP prefixes currently being announced by an ASN in BGP.

    This shows the ASN's complete routing footprint — every IP range it
    is actively advertising to the global internet via BGP. Uses RIPE
    Stat's announced-prefixes endpoint.

    Useful for:
    - Understanding an organization's complete IP footprint
    - Detecting unexpected prefix announcements (possible hijacks)
    - M&A due diligence on network assets
    - Security research and threat intelligence

    min_peers_seeing filters out unstable/flapping routes that only
    a small number of BGP peers can see. Higher = more stable routes only.

    Results are cached for 5 minutes.

    Args:
        params (AnnouncedPrefixesInput):
            - asn (str): ASN to query (e.g. 'AS13335' or '15169')
            - min_peers_seeing (int): Minimum peer count filter (default: 5)

    Returns:
        str: Complete list of announced prefixes with peer visibility and
             first/last seen timestamps.
             JSON schema:
             {
               "resource": str, "is_announced": bool,
               "announced_prefixes": [
                 {"prefix": str, "peers_seeing": int,
                  "first_seen": str, "last_seen": str}
               ]
             }
    """
    asn = params.asn.strip()
    cache_key = cache_module.make_bgp_key(f"prefixes:{asn}:{params.min_peers_seeing}")
    cached = cache_module.get(cache_key)
    if cached:
        return cached

    result = await rir_client.get_announced_prefixes(asn, params.min_peers_seeing)
    output = format_bgp_status_md(result)
    cache_module.set(cache_key, output, cache_module.TTL_BGP)
    return output


# ──────────────────────────────────────────────────────────────
# Tool 9 — Organization Resource Audit  [Phase 2]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_audit_org",
    annotations={
        "title":          "Audit All Internet Resources for an Organization",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_audit_org(params: OrgAuditInput) -> str:
    """
    Find all IP blocks and ASNs registered to an organization across all RIRs.

    Searches RDAP entity databases at AFRINIC, APNIC, ARIN, and RIPE
    (LACNIC does not support RDAP entity search — a limitation is noted).
    Aggregates results into a unified inventory.

    Use cases:
    - M&A due diligence: What internet resources does Company X own globally?
    - Security research: What is the full IP footprint of an organization?
    - ICANN/RIR policy: Are resources distributed across multiple RIRs?
    - Incident response: Did this org transfer/sell IP space recently?

    Tips:
    - Use org handles for precision (e.g. 'GOOGL-ARIN' not 'Google')
    - Partial name matching is supported (e.g. 'Cloudflare' finds 'Cloudflare Inc.')
    - Results are cached for 6 hours.

    Args:
        params (OrgAuditInput):
            - org_name (str): Organization name or handle (e.g. 'Cloudflare', 'GOOGL-ARIN')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Summary of all IP blocks and ASNs by RIR, with handles, names,
             countries, and allocation dates.
             JSON schema:
             {
               "org_query": str, "total_resources": int,
               "ip_blocks": [{"rir": str, "handle": str, "prefix_or_asn": str,
                              "name": str, "country": str}],
               "asns": [...],
               "rirs_found_in": [str], "errors": [str]
             }
    """
    org = params.org_name.strip()
    cache_key = cache_module.make_org_key(org)
    cached = cache_module.get(cache_key)
    if cached:
        return cached["json"] if params.response_format == ResponseFormat.JSON else cached["markdown"]

    resources, errors = await rir_client.search_org_all_rirs(org)

    ip_blocks = [r for r in resources if r.resource_type in ("ip", "entity")]
    asns      = [r for r in resources if r.resource_type == "asn"]
    rirs_found = list({r.rir for r in resources})

    audit = OrgAuditResult(
        org_query       = org,
        total_resources = len(resources),
        ip_blocks       = ip_blocks,
        asns            = asns,
        rirs_found_in   = rirs_found,
        errors          = errors,
    )

    md  = format_org_audit_md(audit)
    jsn = to_json(audit)

    cache_module.set(cache_key, {"markdown": md, "json": jsn}, cache_module.TTL_ORG)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 10 — Prefix / ASN History  [Phase 3]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_prefix_history",
    annotations={
        "title":           "Full Registration History for a Prefix or ASN",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_prefix_history(params: PrefixHistoryInput) -> str:
    """
    Fetch the complete registration history for an IP prefix or ASN.

    Returns a chronological timeline of every change ever recorded:
    - Initial registration (who, when, under which RIR)
    - Org / maintainer changes (potential ownership transfers)
    - Status changes (allocated → assigned → available)
    - Last-changed updates

    Uses RIPE Stat's historical-whois and allocation-history APIs.
    Coverage is best for RIPE NCC resources; partial for other RIRs.

    Use cases:
    - "Has this IP block ever changed hands?"
    - "When was this ASN first registered?"
    - "What organization historically owned this prefix?"
    - Due diligence, incident response, fraud investigation

    Results are cached for 12 hours (historical records are stable).

    Args:
        params (PrefixHistoryInput):
            - resource (str): IP prefix (e.g. '8.8.8.0/24') or ASN (e.g. 'AS15169')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Chronological event timeline with dates, event types, and attribute changes.
             JSON schema:
             {
               "resource": str, "resource_type": str,
               "current_holder": str, "current_rir": str,
               "registration_date": str, "total_events": int,
               "events": [{"event_date": str, "event_type": str,
                           "attribute": str, "old_value": str, "new_value": str}],
               "sources": [str], "errors": [str]
             }
    """
    resource = params.resource.strip()
    cache_key = cache_module.make_history_key(resource)
    cached = cache_module.get(cache_key)
    if cached:
        return cached["json"] if params.response_format == ResponseFormat.JSON else cached["markdown"]

    result = await rir_client.get_prefix_history(resource)
    md  = format_prefix_history_md(result)
    jsn = to_json(result)

    cache_module.set(cache_key, {"markdown": md, "json": jsn}, cache_module.TTL_HISTORY)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 11 — Transfer Detection  [Phase 3]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_detect_transfers",
    annotations={
        "title":           "Detect Cross-Org and Cross-RIR Resource Transfers",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_detect_transfers(params: TransferDetectInput) -> str:
    """
    Detect past ownership or cross-RIR transfers for an IP prefix or ASN.

    An ownership transfer happens when a registered org (e.g. 'GOOGL-ARIN')
    changes to another org ('META-1-ARIN') in the registration record.
    A cross-RIR transfer is rarer — it means the resource physically moved
    between registries (e.g. from ARIN to RIPE NCC after an acquisition).

    Transfer types detected:
      🏢 Org Change     — The registering organization changed
      🌍→🌎 Cross-RIR  — The resource moved to a different RIR
      🔄 Intra-RIR     — Maintainer changed within the same RIR

    How it works: compares consecutive historical WHOIS object versions.
    If 'org' or 'mnt-by' changed between versions, a transfer is flagged.
    If RIR-specific suffixes in the handles differ, it's cross-RIR.

    Results are cached for 12 hours.

    Args:
        params (TransferDetectInput):
            - resource (str): IP prefix (e.g. '8.8.8.0/24') or ASN (e.g. 'AS15169')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: List of detected transfers with dates, types, from/to org, and evidence.
             JSON schema:
             {
               "resource": str, "resource_type": str,
               "transfers_detected": int,
               "transfers": [{"transfer_date": str, "transfer_type": str,
                              "from_org": str, "to_org": str,
                              "from_rir": str, "to_rir": str, "evidence": str}],
               "current_holder": str, "first_registered": str,
               "sources": [str], "notes": [str]
             }
    """
    resource = params.resource.strip()
    cache_key = cache_module.make_transfer_key(resource)
    cached = cache_module.get(cache_key)
    if cached:
        return cached["json"] if params.response_format == ResponseFormat.JSON else cached["markdown"]

    result = await rir_client.detect_transfers(resource)
    md  = format_transfer_detect_md(result)
    jsn = to_json(result)

    cache_module.set(cache_key, {"markdown": md, "json": jsn}, cache_module.TTL_TRANSFER)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 12 — Global IPv4 / IPv6 / ASN Stats  [Phase 3]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_ipv4_stats",
    annotations={
        "title":           "Global IPv4 / IPv6 / ASN Exhaustion Dashboard",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_ipv4_stats(params: IPv4StatsInput) -> str:
    """
    Fetch global IPv4, IPv6, and ASN allocation statistics from all 5 RIRs.

    Parses the NRO Extended Delegation Stats files — the authoritative daily
    publication of how each RIR has distributed address space:
    - How many IPv4 prefixes allocated (to ISPs) vs assigned (to end users)
    - Remaining free IPv4 pool (where published — most RIRs are exhausted)
    - IPv6 prefix count and growth
    - Total ASNs issued

    Why this matters:
    - IPv4 was exhausted at IANA in 2011
    - APNIC exhausted in 2011, RIPE in 2012, ARIN in 2015
    - LACNIC near exhaustion 2020, AFRINIC followed
    - IPv6 transition is the only long-term solution
    - This tool lets you track adoption and exhaustion state in real time

    Results are cached for 24 hours (stats files are published once daily).

    Args:
        params (IPv4StatsInput):
            - rir_filter (str, optional): Filter to one RIR ('AFRINIC', 'APNIC',
              'ARIN', 'LACNIC', 'RIPE'). Leave empty for all 5.
            - include_blocks (bool): Include raw delegated IPv4 blocks for the selected RIR.
              Requires rir_filter to be set.
            - status_filter (str, optional): allocated | assigned | available (free is normalized).
            - country_filter (str, optional): 2-letter country code filter (e.g. 'GH', 'ZA').
            - limit (int): Max number of block rows when include_blocks=true.
            - offset (int): Pagination offset for block rows.
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Per-RIR table of IPv4/IPv6/ASN counts with totals and exhaustion context.
             JSON schema:
             {
               "queried_at": str,
               "rirs": [{"rir": str, "region": str,
                         "ipv4_total_prefixes": int, "ipv4_allocated": int,
                         "ipv4_assigned": int, "ipv4_available": int,
                         "ipv6_total_prefixes": int, "asn_total": int,
                         "stats_date": str}],
               "global_ipv4_prefixes": int,
               "global_ipv6_prefixes": int,
               "global_asns": int,
               "ipv4_blocks": [
                 {"rir": str, "country": str|null, "start_ip": str, "end_ip": str,
                  "address_count": int, "date": str|null, "status": str}
               ],
               "blocks_total": int,
               "blocks_returned": int,
               "blocks_limit": int|null,
               "blocks_offset": int|null,
               "blocks_filters": {"rir_filter": str|null, "status_filter": str|null, "country_filter": str|null}
             }
    """
    rir_filter = (params.rir_filter or "").upper().strip() or "all"
    cache_key  = cache_module.make_ipv4stat_key(
        rir_filter=rir_filter,
        include_blocks=params.include_blocks,
        status_filter=params.status_filter,
        country_filter=params.country_filter,
        limit=params.limit,
        offset=params.offset,
    )
    cached     = cache_module.get(cache_key)
    if cached:
        return cached["json"] if params.response_format == ResponseFormat.JSON else cached["markdown"]

    result = await rir_client.get_global_ipv4_stats(
        rir_filter=params.rir_filter or None,
        include_blocks=params.include_blocks,
        status_filter=params.status_filter,
        country_filter=params.country_filter,
        limit=params.limit,
        offset=params.offset,
    )
    md  = format_ipv4_stats_md(result)
    jsn = to_json(result)

    cache_module.set(cache_key, {"markdown": md, "json": jsn}, cache_module.TTL_IPV4STAT)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 13 — Prefix Overview / Hierarchy  [Phase 3]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_prefix_overview",
    annotations={
        "title":           "Prefix Hierarchy: Parent, Children, Siblings, and BGP Status",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_prefix_overview(params: PrefixOverviewInput) -> str:
    """
    Fetch a rich hierarchical overview of an IP prefix.

    IP address space is organized in a tree structure:
    - A /8 contains 256 /16s, each /16 contains 256 /24s, and so on.
    - 'Less-specific' = the parent block this prefix was carved from.
    - 'More-specific' = smaller blocks assigned within this prefix.

    Think of it like a real estate map:
      Less-specific = the city block (containing your property)
      The prefix itself = your land parcel
      More-specific = subdivisions within your parcel

    This tool fetches all three layers in parallel (3 RIPE Stat API calls
    simultaneously) and returns a unified view including:
    - Current holder and announcement status
    - Which ASN(s) are announcing it (multiple = potential hijack)
    - All less-specific (parent) prefixes up the tree
    - All more-specific (child) prefixes within the block

    Combine with rir_check_rpki to validate the announcing ASN.
    Results are cached for 1 hour.

    Args:
        params (PrefixOverviewInput):
            - prefix (str): IP prefix in CIDR notation (e.g. '1.1.1.0/24')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Holder info, BGP status, and full prefix hierarchy table.
             JSON schema:
             {
               "prefix": str, "holder": str, "rir": str, "country": str,
               "announced": bool, "announcing_asns": [str],
               "allocation_status": str,
               "related_prefixes": [{"prefix": str, "relationship": str,
                                     "holder": str, "origin_asn": str}],
               "errors": [str]
             }
    """
    prefix = params.prefix.strip()
    cache_key = cache_module.make_overview_key(prefix)
    cached = cache_module.get(cache_key)
    if cached:
        return cached["json"] if params.response_format == ResponseFormat.JSON else cached["markdown"]

    result = await rir_client.get_prefix_overview(prefix)
    md  = format_prefix_overview_md(result)
    jsn = to_json(result)

    cache_module.set(cache_key, {"markdown": md, "json": jsn}, cache_module.TTL_OVERVIEW)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 14 — PeeringDB Peering Info  [Phase 4]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_peering_info",
    annotations={
        "title":           "PeeringDB: Peering Policy, IXP Presence, NOC Contacts",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_peering_info(params: PeeringInfoInput) -> str:
    """
    Fetch peering policy, IXP presence, NOC contacts, and BGP neighbours for an ASN.

    Data sources (queried in parallel):
    - PeeringDB (www.peeringdb.com) — the internet's peering registry
    - RIPE Stat asn-neighbours — live BGP upstream/downstream relationships

    Information returned:
    - Peering policy: Open / Selective / Restrictive / No Peering
    - IRR AS-SET (used in route filters, e.g. AS-CLOUDFLARE)
    - NOC email, abuse email, peering contact email
    - IXP presence: which exchange points, peering IPs, link speed
    - BGP neighbours: up to 30 adjacent ASNs in the routing table

    Use cases:
    - "Does Cloudflare have an Open peering policy?"
    - "Which IXPs is AS13335 present at?"
    - "What is the NOC email for AS1234 to report an incident?"
    - "Is this ASN a residential ISP or a CDN?"

    Results are cached for 6 hours.

    Args:
        params (PeeringInfoInput):
            - asn (str): ASN to look up (e.g. 'AS13335', '13335', 'AS-CLOUDFLARE')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Peering policy table, IXP presence table, contacts, BGP neighbours.
             JSON schema:
             {
               "asn": str, "network_name": str, "policy_general": str,
               "noc_email": str, "irr_as_set": str,
               "ixp_presence": [{"name": str, "city": str, "country": str,
                                  "ipaddr4": str, "ipaddr6": str, "speed": int}],
               "neighbour_asns": [str], "errors": [str]
             }
    """
    asn = params.asn.strip()
    asn_num = asn.upper().lstrip("AS")
    cache_key = cache_module.make_peering_key(asn_num)
    cached = cache_module.get(cache_key)
    if cached:
        return cached["json"] if params.response_format == ResponseFormat.JSON else cached["markdown"]

    result = await rir_client.get_peering_info(asn_num)
    md  = format_peering_info_md(result)
    jsn = to_json(result)

    cache_module.set(cache_key, {"markdown": md, "json": jsn}, cache_module.TTL_PEERING)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 15 — IXP Lookup  [Phase 4]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_ixp_lookup",
    annotations={
        "title":           "Find Internet Exchange Points by Country or Name",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_ixp_lookup(params: IXPLookupInput) -> str:
    """
    Search PeeringDB for Internet Exchange Points (IXPs) by country code or name.

    An IXP is a physical location where ISPs and networks directly interconnect.
    Without IXPs, all traffic between two ISPs would travel via paid transit
    providers, costing more and adding latency. IXPs are the backbone of
    regional internet ecosystems.

    Searching by country:
    - Use 2-letter ISO country code: 'MU' (Mauritius), 'ZA' (South Africa),
      'DE' (Germany), 'US' (United States), 'SG' (Singapore)

    Searching by name:
    - Partial name match: 'AMS-IX', 'LINX', 'Nairobi', 'Frankfurt'

    Notable IXPs worldwide:
    - DE-CIX Frankfurt (Germany) — Europe's busiest, 13+ Tbps
    - AMS-IX (Netherlands) — 10+ Tbps
    - LINX (UK) — London Internet Exchange
    - JPNAP (Japan) — Asia-Pacific hub
    - Nap.Africa / JINX — African exchanges
    - MAURITIUS-IX — your local exchange!

    Results are cached for 12 hours.

    Args:
        params (IXPLookupInput):
            - query (str): 2-letter country code (e.g. 'MU') or IXP name fragment
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Table of matching IXPs with city, country, member count, and contact.
             JSON schema:
             {
               "query": str, "total_found": int,
               "ixps": [{"name": str, "city": str, "country": str,
                          "member_count": int, "website": str, "tech_email": str}],
               "errors": [str]
             }
    """
    query = params.query.strip()
    cache_key = cache_module.make_ixp_key(query)
    cached = cache_module.get(cache_key)
    if cached:
        return cached["json"] if params.response_format == ResponseFormat.JSON else cached["markdown"]

    result = await rir_client.lookup_ixps(query)
    md  = format_ixp_lookup_md(result)
    jsn = to_json(result)

    cache_module.set(cache_key, {"markdown": md, "json": jsn}, cache_module.TTL_IXP)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 16 — Combined Network Health Report  [Phase 4]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_network_health",
    annotations={
        "title":           "One-Shot Network Health: RDAP + BGP + RPKI + PeeringDB",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def rir_network_health(params: NetworkHealthInput) -> str:
    """
    Run a comprehensive parallel health check on any IP address, prefix, or ASN.

    Fires all checks simultaneously (parallel asyncio):
      RDAP      → Who owns it? Which RIR? Country? Abuse contact?
      BGP       → Is it announced? Which ASNs? What global visibility %?
      RPKI      → Is the announcing ASN cryptographically authorized? (prefix only)
      PeeringDB → Peering policy? NOC email? IXP count? (ASN only)

    Synthesises a health signal dashboard:
      ✅ All good   — registered, announced, RPKI valid
      ⚠️ Warning    — not announced, unprotected route (no ROA), missing contacts
      🚨 Critical   — RPKI invalid (possible hijack!), multiple origin ASNs (MOAS)

    This is your first-response tool for:
    - "Is this IP address legitimate?"
    - "Is this ASN healthy and reachable?"
    - "Is there anything suspicious about this prefix?"
    - NOC incident triage, security team first-response

    Results are cached for 5 minutes (includes live BGP data).

    Args:
        params (NetworkHealthInput):
            - resource (str): IP ('1.1.1.1'), prefix ('1.1.1.0/24'), or ASN ('AS13335')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Health signal dashboard + RDAP + BGP + RPKI + PeeringDB sections.
             JSON schema:
             {
               "resource": str, "resource_type": str, "queried_at": str,
               "rdap_holder": str, "rdap_rir": str, "rdap_country": str,
               "bgp_announced": bool, "bgp_announcing_asns": [str],
               "bgp_visibility_pct": float,
               "rpki_validity": str,
               "peering_policy": str, "peering_ixp_count": int,
               "health_signals": [str], "errors": [str]
             }
    """
    resource = params.resource.strip()
    cache_key = cache_module.make_health_key(resource)
    cached = cache_module.get(cache_key)
    if cached:
        return cached["json"] if params.response_format == ResponseFormat.JSON else cached["markdown"]

    result = await rir_client.get_network_health(resource)
    md  = format_network_health_md(result)
    jsn = to_json(result)

    cache_module.set(cache_key, {"markdown": md, "json": jsn}, cache_module.TTL_HEALTH)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 17 — Change Monitor  [Phase 4]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="rir_change_monitor",
    annotations={
        "title":           "Monitor a Prefix or ASN for Registration and BGP Changes",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  False,   # Side effect: updates baseline on change detection
        "openWorldHint":   True,
    },
)
async def rir_change_monitor(params: ChangeMonitorInput) -> str:
    """
    Monitor a prefix or ASN for registration and BGP routing changes between calls.

    How it works:
    - First call: captures a baseline snapshot of RDAP + BGP state. Stores it
      in memory for the server's lifetime.
    - Subsequent calls: fetches the current state and diffs it against the
      baseline. Reports exactly which fields changed and from what to what.
    - When changes are detected: automatically updates the baseline so the
      next call diffs from the new state (not the original).
    - reset_baseline=True: discards any stored baseline and captures fresh.

    Tracked fields (8 total):
      RDAP: Holder, RIR, Country, Allocation Status, Abuse Email
      BGP:  Announced (bool), Origin ASN(s), Visibility %

    Severity of changes:
      🔴 BGP Origin ASN changed  → possible hijack, verify with rir_check_rpki
      🔴 RDAP Holder changed     → possible transfer, check rir_detect_transfers
      🟡 BGP Announced changed   → prefix appeared/disappeared from routing
      🟡 Country changed         → registration country updated
      🟢 Visibility % changed    → normal BGP fluctuation

    Baseline persists in server memory — not in a database.
    If the server restarts, baselines are lost and will be recreated on next call.

    Args:
        params (ChangeMonitorInput):
            - resource (str): IP prefix (e.g. '8.8.8.0/24') or ASN (e.g. 'AS15169')
            - reset_baseline (bool): If True, discard baseline and start fresh

    Returns:
        str: Baseline created confirmation (first call), or diff table (subsequent calls).
             JSON schema:
             {
               "resource": str, "status": str,  (baseline_created|changes_detected|no_changes)
               "baseline_captured_at": str, "checked_at": str,
               "changes": [{"field": str, "old_value": str, "new_value": str}],
               "current_holder": str, "current_rir": str, "message": str
             }
    """
    result = await rir_client.run_change_monitor(
        resource       = params.resource.strip(),
        reset_baseline = params.reset_baseline,
    )
    md  = format_change_monitor_md(result)
    jsn = to_json(result)
    # Note: change_monitor results are NOT cached — each call is intentionally live
    return jsn if False else md  # always markdown (no format param for this tool)


# ──────────────────────────────────────────────────────────────
# Tool 18 — DNS Resolve  [Phase 5 / Sprint 2]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="peerglass_dns_resolve",
    annotations={
        "title":           "DNS Resolution with RDAP IP Correlation",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def peerglass_dns_resolve(params: DNSResolveInput) -> str:
    """
    Resolve a hostname or reverse-lookup an IP address and correlate the
    result with RDAP registration data (holder, country, RIR, covering prefix).

    Args:
        params (DNSResolveInput):
            - target (str): Hostname or IP address (e.g. '8.8.8.8', 'cloudflare.com')
            - record_type (str): DNS record type — A, AAAA, PTR, MX, TXT, NS, CNAME …
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: DNS records table + RDAP owner details for each resolved IP.
    """
    result = await rir_client.dns_resolve(params)
    md  = format_dns_resolve_md(result)
    jsn = to_json(result)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 19 — DNS Enumerate  [Phase 5 / Sprint 2]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="peerglass_dns_enumerate",
    annotations={
        "title":           "Full DNS Record Enumeration",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def peerglass_dns_enumerate(params: DNSEnumerateInput) -> str:
    """
    Enumerate all common DNS record types for a domain in one call:
    A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, SRV — plus extracts SPF and
    DMARC policies inline.

    Args:
        params (DNSEnumerateInput):
            - domain (str): Domain name (e.g. 'cloudflare.com')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Per-type record tables with TTL values and extracted SPF/DMARC.
    """
    result = await rir_client.dns_enumerate(params)
    md  = format_dns_enumerate_md(result)
    jsn = to_json(result)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 20 — DNSSEC Validation  [Phase 5 / Sprint 2]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="peerglass_dns_dnssec",
    annotations={
        "title":           "DNSSEC Chain Validation",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def peerglass_dns_dnssec(params: DNSSECInput) -> str:
    """
    Validate the DNSSEC chain-of-trust for a domain. Checks DNSKEY, DS,
    and RRSIG records and reports SECURE / INSECURE / BOGUS / INDETERMINATE.

    BOGUS status means signatures exist but fail validation — a serious
    indicator of misconfiguration or potential tampering.

    Args:
        params (DNSSECInput):
            - domain (str): Domain name (e.g. 'cloudflare.com')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: DNSSEC status, chain validity, record counts, and signing algorithms.
    """
    result = await rir_client.dns_dnssec(params)
    md  = format_dns_dnssec_md(result)
    jsn = to_json(result)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 21 — DNSBL / Blocklist Check  [Phase 5 / Sprint 2]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="peerglass_dns_dnsbl",
    annotations={
        "title":           "DNS Blocklist (DNSBL/RBL) Check",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def peerglass_dns_dnsbl(params: DNSBLInput) -> str:
    """
    Check an IPv4 address against 30 DNS blocklists simultaneously, including
    Spamhaus ZEN, Barracuda, SORBS, URIBL, and more. All queries run in
    parallel for fast results.

    Args:
        params (DNSBLInput):
            - ip (str): IPv4 address to check (e.g. '1.2.3.4')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Per-list listed/clean status with return codes and descriptions.
    """
    result = await rir_client.dns_dnsbl(params)
    md  = format_dns_dnsbl_md(result)
    jsn = to_json(result)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 22 — Email Security Audit  [Phase 5 / Sprint 2]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="peerglass_dns_email_security",
    annotations={
        "title":           "Email Security Audit (SPF + DMARC + DKIM + BIMI)",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def peerglass_dns_email_security(params: EmailSecurityInput) -> str:
    """
    Comprehensive email security posture check for a domain:
    - SPF: record presence, validity, and policy strength (-all / ~all / ?all)
    - DMARC: policy (none/quarantine/reject), pct coverage, rua/ruf reporting
    - DKIM: probes common selectors (google, selector1, default, k1, mail …)
    - MX: mail server records
    - BIMI: brand indicator for message identification
    - Risk score: LOW / MEDIUM / HIGH / CRITICAL with specific issues listed

    Args:
        params (EmailSecurityInput):
            - domain (str): Domain name (e.g. 'example.com')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Full email security audit with risk level, score, and recommendations.
    """
    result = await rir_client.dns_email_security(params)
    md  = format_email_security_md(result)
    jsn = to_json(result)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 23 — DNS Propagation  [Phase 5 / Sprint 2]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="peerglass_dns_propagation",
    annotations={
        "title":           "DNS Propagation Check (10 Global Resolvers)",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def peerglass_dns_propagation(params: DNSPropagationInput) -> str:
    """
    Check whether a recent DNS change has propagated globally by querying
    10 geographically distributed resolvers simultaneously:
    Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9, OpenDNS, Comodo,
    Verisign, Level3, FreeDNS, CleanBrowsing, and Alternate DNS.

    Compares each resolver's answer to the majority answer and reports
    which resolvers are stale, diverging, or failing.

    Args:
        params (DNSPropagationInput):
            - domain (str): Domain name (e.g. 'cloudflare.com')
            - record_type (str): DNS record type to check (default: A)
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Per-resolver answer table with propagation status and majority answer.
    """
    result = await rir_client.dns_propagation(params)
    md  = format_dns_propagation_md(result)
    jsn = to_json(result)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 24 — TLS Inspection  [Phase 6 / Sprint 3 F1]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="peerglass_tls_inspect",
    annotations={
        "title":           "TLS Certificate Inspection",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def peerglass_tls_inspect(params: TLSInspectInput) -> str:
    """
    Connect to hostname:port over TLS and return full certificate details:
    subject, issuer, Subject Alternative Names (SANs), expiry date, days
    remaining, self-signed flag, TLS protocol version, cipher suite,
    chain length, and HSTS header presence.

    Useful for:
    - Verifying certificate validity before expiry
    - Detecting self-signed or untrusted certificates
    - Checking TLS configuration (version, cipher suite)
    - Auditing HSTS deployment

    Args:
        params (TLSInspectInput):
            - hostname (str): Target hostname (e.g. 'cloudflare.com')
            - port (int): TCP port — default 443
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Certificate details, expiry countdown, issuer chain, and HSTS status.
    """
    result = await rir_client.tls_inspect(params)
    md  = format_tls_inspect_md(result)
    jsn = to_json(result)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 25 — Certificate Transparency Logs  [Phase 6 / Sprint 3 F2]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="peerglass_ct_logs",
    annotations={
        "title":           "Certificate Transparency Log Search",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def peerglass_ct_logs(params: CTLogInput) -> str:
    """
    Search crt.sh for all TLS certificates ever issued for a domain via
    Certificate Transparency logs. Returns deduplicated entries showing
    common name, issuer CA, validity period, and SAN name_value.

    Useful for:
    - Discovering shadow IT / undocumented subdomains
    - Auditing which CAs have been used for a domain
    - Finding certificates issued before/after security incidents
    - Verifying certificate rotation

    Args:
        params (CTLogInput):
            - domain (str): Domain name (e.g. 'cloudflare.com')
            - limit (int): Max entries to return (default 50, max 500)
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Certificate log table with CN, CA, validity dates, and unique CA summary.
    """
    result = await rir_client.ct_logs(params)
    md  = format_ct_logs_md(result)
    jsn = to_json(result)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 26 — Threat Intelligence  [Phase 6 / Sprint 3 G1]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="peerglass_threat_intel",
    annotations={
        "title":           "Threat Intelligence (Shodan + GreyNoise)",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def peerglass_threat_intel(params: ThreatIntelInput) -> str:
    """
    Passive threat intelligence for an IP address from two sources:

    1. Shodan InternetDB (always available, no API key required):
       - Open ports detected via internet scanning
       - CVE identifiers for detected services
       - Reverse DNS hostnames
       - Shodan tags (cdn, vpn, tor-exit, etc.)

    2. GreyNoise Community (requires GREYNOISE_API_KEY env var):
       - Classification: malicious / benign / unknown
       - RIOT flag: trusted service (Google, Amazon, etc.)
       - Noise flag: benign internet background scanner
       - Named actor or service attribution

    Produces an aggregated risk score (0–100) and level (LOW / MEDIUM / HIGH / CRITICAL).

    Args:
        params (ThreatIntelInput):
            - ip (str): IPv4 address (e.g. '1.2.3.4')
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Open ports, CVEs, GreyNoise classification, and risk assessment.
    """
    result = await rir_client.threat_intel(params)
    md  = format_threat_intel_md(result)
    jsn = to_json(result)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Tool 27 — Passive DNS  [Phase 6 / Sprint 3 E6]
# ──────────────────────────────────────────────────────────────

@mcp.tool(
    name="peerglass_passive_dns",
    annotations={
        "title":           "Passive DNS History (RIPE Stat)",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def peerglass_passive_dns(params: PassiveDNSInput) -> str:
    """
    Query RIPE Stat Passive DNS for historical DNS records associated with
    an IP address or domain name. Shows what hostnames pointed to an IP
    (or what IPs a hostname resolved to) over time, with first/last seen
    timestamps and observation counts.

    Useful for:
    - Tracing infrastructure changes over time
    - Finding previously-used domains for an IP
    - Investigating historical malware C2 infrastructure
    - Attribution and threat hunting

    Data source: RIPE NCC's Passive DNS system, which aggregates DNS
    queries from recursive resolvers across the network.

    Args:
        params (PassiveDNSInput):
            - resource (str): IP address or domain name
            - limit (int): Max records (default 100, max 500)
            - response_format (str): 'markdown' (default) or 'json'

    Returns:
        str: Historical DNS records table with rrtype, value, and first/last seen dates.
    """
    result = await rir_client.passive_dns(params)
    md  = format_passive_dns_md(result)
    jsn = to_json(result)
    return jsn if params.response_format == ResponseFormat.JSON else md


# ──────────────────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────────────────

def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
