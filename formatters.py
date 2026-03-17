"""
formatters.py — Render normalized data models into Markdown or JSON strings.

Claude receives tool output as a plain string. Markdown output is
optimised for human reading inside Claude's UI. JSON output is
optimised for programmatic use or further processing by Claude.
"""

from __future__ import annotations
import json
from typing import Any

from models import (
    NetworkResource,
    ASNResource,
    AbuseContact,
    RIRQueryResult,
    RPKIResult,
    RPKIValidity,
    BGPStatusResult,
    OrgAuditResult,
    PrefixHistoryResult,
    TransferDetectResult,
    GlobalIPv4Stats,
    PrefixOverviewResult,
    PeeringInfoResult,
    IXPLookupResult,
    NetworkHealthResult,
    ChangeMonitorResult,
    DNSResolveResult,
    DNSEnumerateResult,
    DNSSECResult,
    DNSBLResult,
    EmailSecurityResult,
    DNSPropagationResult,
    TLSCertResult,
    CTLogResult,
    ThreatIntelResult,
    PassiveDNSResult,
)


# ──────────────────────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────────────────────

RIR_FLAGS = {
    "AFRINIC": "🌍", "APNIC": "🌏", "ARIN": "🌎",
    "LACNIC":  "🌎", "RIPE":  "🌍",
}

RIR_REGIONS = {
    "AFRINIC": "Africa",
    "APNIC":   "Asia-Pacific",
    "ARIN":    "North America",
    "LACNIC":  "Latin America & Caribbean",
    "RIPE":    "Europe / Middle East / Central Asia",
}

STATUS_ICONS = {
    "ok":           "✅",
    "not_found":    "❌",
    "error":        "⚠️",
    "rate_limited": "🚦",
}


def _flag(rir: str) -> str:
    return RIR_FLAGS.get(rir.upper(), "🌐")


def _icon(status: str) -> str:
    return STATUS_ICONS.get(status, "❓")


def _row(label: str, value: Any, suffix: str = "") -> str:
    """Return a markdown list row only when value is truthy."""
    return f"- **{label}:** {value}{suffix}\n" if value else ""


def to_json(data: Any) -> str:
    """Serialize any Pydantic model, list, or dict to pretty-printed JSON."""
    if hasattr(data, "model_dump"):
        return json.dumps(data.model_dump(), indent=2, default=str)
    if isinstance(data, list):
        serialized = [
            item.model_dump() if hasattr(item, "model_dump") else item
            for item in data
        ]
        return json.dumps(serialized, indent=2, default=str)
    return json.dumps(data, indent=2, default=str)


# ──────────────────────────────────────────────────────────────
# Phase 1 — IP Network
# ──────────────────────────────────────────────────────────────

def _format_single_network(resource: NetworkResource) -> str:
    return (
        f"\n### {_flag(resource.rir)} {resource.rir}"
        f"  _{RIR_REGIONS.get(resource.rir, '')}_\n"
        + _row("Prefix",       resource.prefix)
        + _row("Name",         resource.name)
        + _row("Handle",       resource.handle)
        + _row("Organization", resource.org_name)
        + _row("Country",      resource.country)
        + _row("IP Version",   f"IPv{resource.ip_version}" if resource.ip_version else None)
        + _row("Status",       resource.status)
        + _row("Allocated",    resource.allocation_date)
        + _row("Last Changed", resource.last_changed)
        + _row("Abuse Email",  resource.abuse_email)
    )


def format_ip_results_md(
    ip: str,
    resources: list[NetworkResource],
    raw_results: list[RIRQueryResult],
) -> str:
    ok  = [r for r in raw_results if r.status == "ok"]
    nf  = [r for r in raw_results if r.status == "not_found"]
    err = [r for r in raw_results if r.status not in ("ok", "not_found")]

    lines = [
        f"## 🌐 Multi-RIR IP Query: `{ip}`\n\n",
        f"Queried all 5 RIRs simultaneously via RDAP.\n\n",
        f"| Metric | Count |\n|--------|-------|\n",
        f"| ✅ Found in | {len(ok)} RIR(s) |\n",
        f"| ❌ Not found | {len(nf)} |\n",
        f"| ⚠️ Errors | {len(err)} |\n\n",
    ]

    if resources:
        lines.append("---\n\n## 📋 Registration Details\n")
        for r in resources:
            lines.append(_format_single_network(r))
    else:
        lines.append(
            "\n> ℹ️ This address was not found in any RIR. "
            "It may be private/reserved (RFC 1918, 4193) or the address is invalid.\n"
        )

    if nf or err:
        lines.append("\n---\n\n### Other RIR Responses\n")
        for r in nf + err:
            lines.append(f"- {_icon(r.status)} **{r.rir.value}**: {r.error or 'No record found'}\n")

    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 1 — ASN
# ──────────────────────────────────────────────────────────────

def _format_single_asn(resource: ASNResource) -> str:
    return (
        f"\n### {_flag(resource.rir)} {resource.rir}"
        f"  _{RIR_REGIONS.get(resource.rir, '')}_\n"
        + _row("ASN",          resource.asn)
        + _row("Name",         resource.name)
        + _row("Organization", resource.org_name)
        + _row("Country",      resource.country)
        + _row("Status",       resource.status)
        + _row("Allocated",    resource.allocation_date)
        + _row("Last Changed", resource.last_changed)
        + _row("Abuse Email",  resource.abuse_email)
    )


def format_asn_results_md(
    asn: str,
    resources: list[ASNResource],
    raw_results: list[RIRQueryResult],
) -> str:
    ok  = [r for r in raw_results if r.status == "ok"]
    nf  = [r for r in raw_results if r.status == "not_found"]
    err = [r for r in raw_results if r.status not in ("ok", "not_found")]

    lines = [
        f"## 🌐 Multi-RIR ASN Query: `{asn}`\n\n",
        f"| Metric | Count |\n|--------|-------|\n",
        f"| ✅ Found in | {len(ok)} RIR(s) |\n",
        f"| ❌ Not found | {len(nf)} |\n",
        f"| ⚠️ Errors | {len(err)} |\n\n",
    ]

    if resources:
        lines.append("---\n\n## 📋 ASN Registration Details\n")
        for r in resources:
            lines.append(_format_single_asn(r))
    else:
        lines.append("\n> ℹ️ This ASN was not found in any RIR registry.\n")

    if nf or err:
        lines.append("\n---\n\n### Other RIR Responses\n")
        for r in nf + err:
            lines.append(f"- {_icon(r.status)} **{r.rir.value}**: {r.error or 'No record found'}\n")

    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 1 — Abuse Contact
# ──────────────────────────────────────────────────────────────

def format_abuse_contact_md(contact: AbuseContact) -> str:
    emails = ", ".join(contact.abuse_email) if contact.abuse_email else "_None found_"
    phones = ", ".join(contact.abuse_phone) if contact.abuse_phone else "_None found_"

    lines = [
        f"## 🚨 Abuse Contact: `{contact.ip_address}`\n\n",
        _row("Authoritative RIR", contact.authoritative_rir),
        _row("Network Name",      contact.network_name),
        _row("Network Handle",    contact.network_handle),
        _row("Organization",      contact.org_name),
        _row("Country",           contact.country),
        f"- **Abuse Email:** {emails}\n",
        f"- **Abuse Phone:** {phones}\n",
    ]

    if not contact.abuse_email:
        lines.append(
            "\n> ⚠️ No abuse email found in RDAP record. "
            "Try the RIR's web portal directly, or check "
            "[Spamhaus](https://www.spamhaus.org) or "
            "[AbuseIPDB](https://www.abuseipdb.com) for additional contacts.\n"
        )

    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 1 — RIR Server Status
# ──────────────────────────────────────────────────────────────

def format_rir_status_md(stats: dict) -> str:
    lines = [
        "## 📡 RIR RDAP Server Status\n\n",
        "| RIR | Region | Status | RDAP Conformance |\n",
        "|-----|--------|--------|------------------|\n",
    ]
    for rir_name, data in stats.items():
        flag   = _flag(str(rir_name))
        region = RIR_REGIONS.get(str(rir_name), "Unknown")
        if "error" in data:
            status       = "⚠️ Unreachable"
            conformance  = f"Error: {data['error']}"
        else:
            status       = "✅ Online"
            conf_list    = data.get("rdapConformance", [])
            conformance  = ", ".join(conf_list[:3]) if conf_list else "Online"
        lines.append(f"| {flag} **{rir_name}** | {region} | {status} | {conformance} |\n")
    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 2 — RPKI
# ──────────────────────────────────────────────────────────────

RPKI_ICONS = {
    RPKIValidity.VALID:     "✅",
    RPKIValidity.INVALID:   "🚨",
    RPKIValidity.NOT_FOUND: "⚠️",
    RPKIValidity.UNKNOWN:   "❓",
}


def format_rpki_result_md(result: RPKIResult) -> str:
    icon = RPKI_ICONS.get(result.validity, "❓")
    lines = [
        f"## {icon} RPKI Validation: `{result.prefix}` via `{result.asn}`\n\n",
        f"- **Validity:** `{result.validity.value.upper()}`\n",
        f"- **Source:** {result.source}\n\n",
        f"> {result.description}\n\n",
    ]

    if result.covering_roas:
        lines.append("### Covering ROAs\n\n")
        lines.append("| ASN | Prefix | Max Length |\n|-----|--------|------------|\n")
        for roa in result.covering_roas[:10]:
            asn    = roa.get("asn", "N/A")
            prefix = roa.get("prefix", "N/A")
            maxlen = roa.get("maxLength", "N/A")
            lines.append(f"| AS{asn} | {prefix} | /{maxlen} |\n")
    else:
        lines.append("_No covering ROAs found in the RPKI._\n")

    lines.append(
        "\n---\n**What is RPKI?** "
        "Route Origin Authorization (ROA) certificates are issued by RIRs "
        "to cryptographically prove that an ASN is authorized to announce "
        "a specific prefix. RPKI INVALID routes should be filtered by ISPs.\n"
    )
    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 2 — BGP Status
# ──────────────────────────────────────────────────────────────

def format_bgp_status_md(result: BGPStatusResult) -> str:
    announced_icon = "📡" if result.is_announced else "🔇"
    lines = [
        f"## {announced_icon} BGP Status: `{result.resource}`\n\n",
        f"- **Type:** {result.resource_type.upper()}\n",
        f"- **Announced in BGP:** {'Yes ✅' if result.is_announced else 'No ❌'}\n",
        f"- **Source:** {result.source}\n",
        f"- **Queried At:** {result.queried_at or 'N/A'}\n",
    ]

    if result.visibility_percent is not None:
        lines.append(f"- **Global Visibility:** {result.visibility_percent}%\n")

    if result.announcing_asns:
        asns = ", ".join(result.announcing_asns[:10])
        if len(result.announcing_asns) > 10:
            asns += f" _…and {len(result.announcing_asns) - 10} more_"
        lines.append(f"- **Announcing ASN(s):** {asns}\n")

    if result.announced_prefixes:
        lines.append(f"\n### Announced Prefixes ({len(result.announced_prefixes)} total)\n\n")
        lines.append("| Prefix | Peers Seeing | First Seen | Last Seen |\n")
        lines.append("|--------|-------------|------------|----------|\n")
        for p in result.announced_prefixes[:20]:
            peers  = p.peers_seeing or "N/A"
            first  = (p.first_seen or "N/A")[:10]
            last   = (p.last_seen  or "N/A")[:10]
            lines.append(f"| `{p.prefix}` | {peers} | {first} | {last} |\n")
        if len(result.announced_prefixes) > 20:
            lines.append(f"\n_…and {len(result.announced_prefixes) - 20} more prefixes. Use JSON format for full list._\n")

    if getattr(result, "communities", None):
        lines.append(f"\n### BGP Communities ({len(result.communities)} unique)\n\n")
        lines.append("| ASN | Value | Description |\n")
        lines.append("|-----|-------|-------------|\n")
        for c in result.communities[:20]:
            desc = c.description or "—"
            lines.append(f"| {c.asn} | {c.value} | {desc} |\n")
        if len(result.communities) > 20:
            lines.append(f"\n_…and {len(result.communities) - 20} more. Use JSON format for full list._\n")

    if not result.is_announced:
        lines.append(
            "\n> ⚠️ This resource has no active BGP announcements. "
            "Traffic to these IPs will be unreachable on the public internet.\n"
        )

    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 2 — Org Audit
# ──────────────────────────────────────────────────────────────

def format_org_audit_md(result: OrgAuditResult) -> str:
    lines = [
        f"## 🏢 Organization Audit: `{result.org_query}`\n\n",
        f"| Metric | Count |\n|--------|-------|\n",
        f"| Total Resources Found | {result.total_resources} |\n",
        f"| IP Blocks | {len(result.ip_blocks)} |\n",
        f"| ASNs | {len(result.asns)} |\n",
        f"| RIRs Found In | {', '.join(result.rirs_found_in) or 'None'} |\n\n",
    ]

    if result.ip_blocks:
        lines.append("---\n\n### 🗺️ IP Blocks\n\n")
        lines.append("| RIR | Prefix / Handle | Name | Country | Status |\n")
        lines.append("|-----|-----------------|------|---------|--------|\n")
        for r in result.ip_blocks:
            flag = _flag(r.rir)
            lines.append(
                f"| {flag} {r.rir} | `{r.prefix_or_asn or r.handle or 'N/A'}` "
                f"| {r.name or 'N/A'} | {r.country or 'N/A'} | {r.status or 'N/A'} |\n"
            )

    if result.asns:
        lines.append("\n---\n\n### 📡 Autonomous Systems\n\n")
        lines.append("| RIR | ASN | Name | Country | Status |\n")
        lines.append("|-----|-----|------|---------|--------|\n")
        for r in result.asns:
            flag = _flag(r.rir)
            lines.append(
                f"| {flag} {r.rir} | `{r.prefix_or_asn or r.handle or 'N/A'}` "
                f"| {r.name or 'N/A'} | {r.country or 'N/A'} | {r.status or 'N/A'} |\n"
            )

    if not result.ip_blocks and not result.asns:
        lines.append(
            "\n> ℹ️ No registered resources found for this organization name. "
            "Try the organization's RIR handle (e.g. 'GOOGL-ARIN' instead of 'Google'), "
            "or query each RIR's web portal directly.\n"
        )

    if result.errors:
        lines.append("\n---\n\n### ⚠️ Errors / Limitations\n\n")
        for err in result.errors:
            lines.append(f"- {err}\n")

    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 3 — Prefix History
# ──────────────────────────────────────────────────────────────

EVENT_ICONS = {
    "created":      "🟢",
    "updated":      "✏️",
    "transferred":  "🔄",
    "allocation":   "📦",
    "status_change":"🔀",
}


def format_prefix_history_md(result: PrefixHistoryResult) -> str:
    lines = [
        f"## 📜 Registration History: `{result.resource}`\n\n",
        f"| Field | Value |\n|-------|-------|\n",
        f"| Resource Type | {result.resource_type.upper()} |\n",
        f"| Current Holder | {result.current_holder or '_Unknown_'} |\n",
        f"| Current RIR | {result.current_rir or '_Unknown_'} |\n",
        f"| First Registered | {result.registration_date or '_Unknown_'} |\n",
        f"| Total Events | {result.total_events} |\n",
        f"| Sources | {', '.join(result.sources) or 'None'} |\n\n",
    ]

    if result.events:
        lines.append("---\n\n### 📅 Event Timeline (oldest → newest)\n\n")
        lines.append("| Date | Type | Field | Change |\n|------|------|-------|--------|\n")
        for ev in result.events:
            icon = EVENT_ICONS.get(ev.event_type, "•")
            date = ev.event_date or "Unknown"
            etype = f"{icon} {ev.event_type}"
            field = ev.attribute or "—"
            if ev.old_value and ev.new_value:
                change = f"`{ev.old_value}` → `{ev.new_value}`"
            elif ev.new_value:
                change = f"`{ev.new_value}`"
            else:
                change = "—"
            lines.append(f"| {date} | {etype} | {field} | {change} |\n")
    else:
        lines.append(
            "\n> ℹ️ No historical events found. "
            "This resource may be outside RIPE Stat's historical coverage window "
            "(best for RIPE NCC resources; partial for other RIRs).\n"
        )

    if result.errors:
        lines.append("\n---\n\n### ⚠️ Retrieval Errors\n")
        for e in result.errors:
            lines.append(f"- {e}\n")

    lines.append(
        "\n---\n**Coverage note:** Historical WHOIS data is most complete for "
        "RIPE NCC resources. ARIN, APNIC, LACNIC, and AFRINIC resources may "
        "have partial history only.\n"
    )
    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 3 — Transfer Detection
# ──────────────────────────────────────────────────────────────

TRANSFER_TYPE_LABELS = {
    "inter-rir":  "🌍→🌎 Cross-RIR Transfer",
    "org-change": "🏢 Org Change",
    "intra-rir":  "🔄 Intra-RIR Transfer",
}


def format_transfer_detect_md(result: TransferDetectResult) -> str:
    transfer_icon = "🔄" if result.transfers_detected > 0 else "✅"
    lines = [
        f"## {transfer_icon} Transfer Detection: `{result.resource}`\n\n",
        f"| Field | Value |\n|-------|-------|\n",
        f"| Resource Type | {result.resource_type.upper()} |\n",
        f"| Transfers Detected | **{result.transfers_detected}** |\n",
        f"| Current Holder | {result.current_holder or '_Unknown_'} |\n",
        f"| Current RIR | {result.current_rir or '_Unknown_'} |\n",
        f"| First Registered | {result.first_registered or '_Unknown_'} |\n",
        f"| Sources | {', '.join(result.sources) or 'None'} |\n\n",
    ]

    if result.transfers:
        lines.append("---\n\n### 🔄 Detected Transfers\n\n")
        for i, t in enumerate(result.transfers, 1):
            label = TRANSFER_TYPE_LABELS.get(t.transfer_type, t.transfer_type)
            lines.append(f"#### Transfer #{i} — {label}\n\n")
            lines.append(f"| | |\n|--|--|\n")
            lines.append(f"| **Date** | {t.transfer_date or 'Unknown'} |\n")
            lines.append(f"| **Type** | {label} |\n")
            if t.from_org:
                lines.append(f"| **From Org** | `{t.from_org}` |\n")
            if t.to_org:
                lines.append(f"| **To Org** | `{t.to_org}` |\n")
            if t.from_rir:
                lines.append(f"| **From RIR** | {t.from_rir} |\n")
            if t.to_rir:
                lines.append(f"| **To RIR** | {t.to_rir} |\n")
            if t.evidence:
                lines.append(f"| **Evidence** | {t.evidence} |\n")
            lines.append("\n")
    else:
        lines.append(
            "\n> ✅ No ownership transfers detected in available records.\n\n"
            "> This could mean:\n"
            "> - The resource has always belonged to the same organization\n"
            "> - The transfer occurred before RIPE Stat's historical coverage\n"
            "> - The resource is outside RIPE Stat's primary coverage (non-RIPE NCC resources)\n\n"
        )

    if result.notes:
        lines.append("---\n\n### 📝 Notes\n")
        for note in result.notes:
            lines.append(f"- {note}\n")

    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 3 — Global IPv4 / IPv6 / ASN Stats
# ──────────────────────────────────────────────────────────────

RIR_REGIONS_FMT = {
    "AFRINIC": "Africa",
    "APNIC":   "Asia-Pacific",
    "ARIN":    "North America",
    "LACNIC":  "Latin America & Caribbean",
    "RIPE":    "Europe / ME / Central Asia",
}


def _fmt_int(n: int) -> str:
    """Format large integers with comma separators."""
    return f"{n:,}"


def format_ipv4_stats_md(result: GlobalIPv4Stats) -> str:
    lines = [
        "## 🌐 Global IP Address Space Statistics\n\n",
        f"*Queried at: {result.queried_at} | Source: NRO Extended Delegation Stats*\n\n",
        "---\n\n",
        "### 📊 Per-RIR Summary\n\n",
        "| RIR | Region | IPv4 Prefixes | IPv4 Allocated | IPv4 Assigned | IPv6 Prefixes | ASNs |\n",
        "|-----|--------|--------------|----------------|---------------|--------------|------|\n",
    ]

    for r in result.rirs:
        flag   = _flag(r.rir)
        region = RIR_REGIONS_FMT.get(r.rir, r.region)
        date_note = f" _(stats: {r.stats_date[:4]}-{r.stats_date[4:6]}-{r.stats_date[6:8]})_" \
                    if r.stats_date and len(r.stats_date) >= 8 else ""
        lines.append(
            f"| {flag} **{r.rir}**{date_note} | {region} "
            f"| {_fmt_int(r.ipv4_total_prefixes)} "
            f"| {_fmt_int(r.ipv4_allocated)} "
            f"| {_fmt_int(r.ipv4_assigned)} "
            f"| {_fmt_int(r.ipv6_total_prefixes)} "
            f"| {_fmt_int(r.asn_total)} |\n"
        )

    lines.append(
        f"| **🌐 GLOBAL** | All Regions "
        f"| **{_fmt_int(result.global_ipv4_prefixes)}** "
        f"| — | — "
        f"| **{_fmt_int(result.global_ipv6_prefixes)}** "
        f"| **{_fmt_int(result.global_asns)}** |\n\n"
    )

    # Per-RIR detail cards
    lines.append("---\n\n### 🔍 Per-RIR Detail\n\n")
    for r in result.rirs:
        flag = _flag(r.rir)
        lines.append(f"#### {flag} {r.rir} — {RIR_REGIONS_FMT.get(r.rir, r.region)}\n\n")
        lines.append(f"- **IPv4 Records:** {_fmt_int(r.ipv4_total_prefixes)}\n")
        lines.append(f"  - Allocated (to ISPs): {_fmt_int(r.ipv4_allocated)} IPs\n")
        lines.append(f"  - Assigned (to end users): {_fmt_int(r.ipv4_assigned)} IPs\n")
        if r.ipv4_available > 0:
            lines.append(f"  - Available pool: {_fmt_int(r.ipv4_available)} IPs\n")
        lines.append(f"- **IPv6 Records:** {_fmt_int(r.ipv6_total_prefixes)}\n")
        lines.append(f"- **ASN Records:** {_fmt_int(r.asn_total)}\n")
        if r.errors:
            for e in r.errors:
                lines.append(f"- ⚠️ {e}\n")
        lines.append("\n")

    if result.ipv4_blocks:
        lines.append("---\n\n### 🧾 Delegated IPv4 Blocks (Filtered)\n\n")
        lines.append(
            f"- **Rows returned:** {_fmt_int(result.blocks_returned)} / {_fmt_int(result.blocks_total)}\n"
        )
        if result.blocks_limit is not None:
            lines.append(f"- **Pagination:** limit={result.blocks_limit}, offset={result.blocks_offset or 0}\n")

        filters = result.blocks_filters or {}
        if filters:
            lines.append(
                f"- **Filters:** RIR={filters.get('rir_filter') or 'N/A'}, "
                f"status={filters.get('status_filter') or 'any'}, "
                f"country={filters.get('country_filter') or 'any'}\n"
            )

        lines.append(
            "\n| RIR | Country | Start IP | End IP | Addresses | Status | Date |\n"
            "|-----|---------|----------|--------|-----------|--------|------|\n"
        )
        for b in result.ipv4_blocks:
            lines.append(
                f"| {b.rir} | {b.country or '-'} | `{b.start_ip}` | `{b.end_ip}` "
                f"| {_fmt_int(b.address_count)} | {b.status} | {b.date or '-'} |\n"
            )
        lines.append("\n")

    lines.append(
        "---\n\n**What does this mean?**\n\n"
        "The global IPv4 address pool is essentially exhausted at the IANA level. "
        "Each RIR now manages its own remaining free pool or relies entirely on the "
        "transfer market. IPv6 adoption is the long-term solution — this dashboard "
        "tracks how each region is progressing.\n"
    )

    if result.errors:
        lines.append("\n---\n\n### ⚠️ Errors\n")
        for e in result.errors:
            lines.append(f"- {e}\n")

    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 3 — Prefix Overview (hierarchy)
# ──────────────────────────────────────────────────────────────

def format_prefix_overview_md(result: PrefixOverviewResult) -> str:
    announced_str = "Yes 📡" if result.announced else ("No 🔇" if result.announced is False else "Unknown")
    asns_str = ", ".join(result.announcing_asns) if result.announcing_asns else "_None_"

    lines = [
        f"## 🗺️ Prefix Overview: `{result.prefix}`\n\n",
        f"| Field | Value |\n|-------|-------|\n",
        f"| **Holder** | {result.holder or '_Unknown_'} |\n",
        f"| **RIR / Block** | {result.rir or '_Unknown_'} |\n",
        f"| **Country** | {result.country or '_Unknown_'} |\n",
        f"| **Announced in BGP** | {announced_str} |\n",
        f"| **Announcing ASN(s)** | {asns_str} |\n",
        f"| **Allocation Status** | {result.allocation_status or '_Unknown_'} |\n",
        f"| **Source** | {result.source} |\n\n",
    ]

    # Group related prefixes by relationship
    less = [p for p in result.related_prefixes if p.relationship == "less-specific"]
    more = [p for p in result.related_prefixes if p.relationship == "more-specific"]

    if less:
        lines.append("---\n\n### 🔼 Parent / Less-Specific Prefixes\n\n")
        lines.append("These are the larger blocks that **contain** `" + result.prefix + "`:\n\n")
        lines.append("| Prefix | Holder |\n|--------|--------|\n")
        for p in less:
            lines.append(f"| `{p.prefix}` | {p.holder or '_Unknown_'} |\n")
        lines.append("\n")

    if more:
        lines.append("---\n\n### 🔽 Child / More-Specific Prefixes\n\n")
        lines.append("These are the smaller blocks **inside** `" + result.prefix + "`:\n\n")
        lines.append("| Prefix | Origin ASN | Announced |\n|--------|------------|----------|\n")
        for p in more[:30]:
            asn = p.origin_asn or "_Unknown_"
            ann = "✅" if p.announced else ("❌" if p.announced is False else "?")
            lines.append(f"| `{p.prefix}` | {asn} | {ann} |\n")
        if len(more) > 30:
            lines.append(f"\n_…and {len(more) - 30} more sub-prefixes. Use JSON format for full list._\n")
        lines.append("\n")

    if not less and not more:
        lines.append(
            "\n> ℹ️ No parent or child prefixes found. "
            "This prefix may be a standalone allocation with no known sub-assignments.\n\n"
        )

    lines.append(
        "---\n\n**Prefix hierarchy explained:**\n"
        "- **Less-specific** = the parent block this prefix was carved from (e.g. a /16 containing a /24)\n"
        "- **More-specific** = the sub-prefixes assigned within this block (e.g. /28s inside a /24)\n"
        "- Multiple origin ASNs on the same prefix may indicate anycast or a BGP hijack — "
        "use `rir_check_rpki` to validate.\n"
    )

    if result.errors:
        lines.append("\n---\n\n### ⚠️ Errors\n")
        for e in result.errors:
            lines.append(f"- {e}\n")

    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 4 — PeeringDB / Peering Info
# ──────────────────────────────────────────────────────────────

POLICY_ICONS = {
    "Open":        "🟢",
    "Selective":   "🟡",
    "Restrictive": "🔴",
    "No Peering":  "⛔",
}


def format_peering_info_md(result: PeeringInfoResult) -> str:
    policy_icon = POLICY_ICONS.get(result.policy_general or "", "❓")
    lines = [
        f"## 📡 PeeringDB: `{result.asn}`",
        f" — {result.network_name}\n\n" if result.network_name else "\n\n",
        "### 🏢 Network Overview\n\n",
        f"| Field | Value |\n|-------|-------|\n",
        f"| **ASN** | `{result.asn}` |\n",
        f"| **Name** | {result.network_name or '_Not registered_'} |\n",
    ]
    if result.aka:
        lines.append(f"| **Also Known As** | {result.aka} |\n")
    if result.info_type:
        lines.append(f"| **Network Type** | {result.info_type} |\n")
    if result.website:
        lines.append(f"| **Website** | {result.website} |\n")
    if result.irr_as_set:
        lines.append(f"| **IRR AS-SET** | `{result.irr_as_set}` |\n")
    if result.info_prefixes4 is not None:
        lines.append(f"| **IPv4 Prefixes** | {result.info_prefixes4:,} |\n")
    if result.info_prefixes6 is not None:
        lines.append(f"| **IPv6 Prefixes** | {result.info_prefixes6:,} |\n")
    lines.append("\n")

    # Peering policy
    lines.append("---\n\n### 🤝 Peering Policy\n\n")
    lines.append(f"| Field | Value |\n|-------|-------|\n")
    lines.append(f"| **General Policy** | {policy_icon} **{result.policy_general or 'Not specified'}** |\n")
    if result.policy_locations:
        lines.append(f"| **Locations** | {result.policy_locations} |\n")
    if result.policy_ratio is not None:
        lines.append(f"| **Requires Traffic Ratio** | {'Yes' if result.policy_ratio else 'No'} |\n")
    if result.policy_contracts:
        lines.append(f"| **Contracts Required** | {result.policy_contracts} |\n")
    lines.append("\n")

    # Contacts
    lines.append("---\n\n### 📞 Contacts\n\n")
    lines.append(f"| Role | Contact |\n|------|--------|\n")
    if result.noc_email:
        lines.append(f"| NOC Email | {result.noc_email} |\n")
    if result.noc_phone:
        lines.append(f"| NOC Phone | {result.noc_phone} |\n")
    if result.abuse_email:
        lines.append(f"| Abuse Email | {result.abuse_email} |\n")
    if result.peering_email:
        lines.append(f"| Peering Email | {result.peering_email} |\n")
    if not any([result.noc_email, result.noc_phone, result.abuse_email, result.peering_email]):
        lines.append(f"| — | _No contacts registered in PeeringDB_ |\n")
    lines.append("\n")

    # IXP presence
    if result.ixp_presence:
        lines.append(f"---\n\n### 🏛️ IXP Presence ({len(result.ixp_presence)} exchange(s))\n\n")
        lines.append("| IXP | City | Country | IPv4 | IPv6 | Speed |\n")
        lines.append("|-----|------|---------|------|------|-------|\n")
        for ix in result.ixp_presence:
            speed_str = f"{ix.speed:,} Mbps" if ix.speed else "—"
            lines.append(
                f"| **{ix.name}** | {ix.city or '—'} | {ix.country or '—'} "
                f"| {ix.ipaddr4 or '—'} | {ix.ipaddr6 or '—'} | {speed_str} |\n"
            )
        lines.append("\n")
    else:
        lines.append("---\n\n> ℹ️ No IXP presence found in PeeringDB for this ASN.\n\n")

    # BGP neighbours
    if result.neighbour_asns:
        lines.append(f"---\n\n### 🔗 BGP Neighbours ({len(result.neighbour_asns)})\n\n")
        lines.append("_Sourced from RIPE Stat ASN neighbours (live BGP view)_\n\n")
        lines.append("`" + "` `".join(result.neighbour_asns[:20]) + "`")
        if len(result.neighbour_asns) > 20:
            lines.append(f"\n\n_…and {len(result.neighbour_asns) - 20} more. Use JSON format for full list._")
        lines.append("\n\n")

    lines.append(
        "---\n\n**What is PeeringDB?** The internet's peering registry — "
        "where network operators register their exchange point presence, peering "
        "policies, and technical contacts. Widely used for BGP session setup, "
        "routing policy filtering, and NOC escalation.\n"
    )

    if result.errors:
        lines.append("\n---\n\n### ⚠️ Errors\n")
        for e in result.errors:
            lines.append(f"- {e}\n")

    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 4 — IXP Lookup
# ──────────────────────────────────────────────────────────────

def format_ixp_lookup_md(result: IXPLookupResult) -> str:
    lines = [
        f"## 🏛️ IXP Lookup: `{result.query}`\n\n",
        f"**{result.total_found}** Internet Exchange Point(s) found.\n\n",
    ]

    if result.ixps:
        lines.append("| IXP Name | City | Country | Members | Website |\n")
        lines.append("|----------|------|---------|---------|--------|\n")
        for ix in result.ixps:
            members = f"{ix.member_count:,}" if ix.member_count is not None else "—"
            website = f"[link]({ix.website})" if ix.website else "—"
            lines.append(
                f"| **{ix.name}** | {ix.city or '—'} | {ix.country or '—'} "
                f"| {members} | {website} |\n"
            )
        lines.append("\n")

        # Detail cards for small result sets
        if len(result.ixps) <= 5:
            lines.append("---\n\n### 🔍 Detail\n\n")
            for ix in result.ixps:
                lines.append(f"#### 🏛️ {ix.name}\n\n")
                if ix.name_long and ix.name_long != ix.name:
                    lines.append(f"_{ix.name_long}_\n\n")
                lines.append(f"| | |\n|--|--|\n")
                lines.append(f"| **City** | {ix.city or '—'} |\n")
                lines.append(f"| **Country** | {ix.country or '—'} |\n")
                lines.append(f"| **Region** | {ix.region or '—'} |\n")
                if ix.member_count is not None:
                    lines.append(f"| **Members** | {ix.member_count:,} |\n")
                if ix.tech_email:
                    lines.append(f"| **Tech Email** | {ix.tech_email} |\n")
                if ix.website:
                    lines.append(f"| **Website** | {ix.website} |\n")
                lines.append("\n")
    else:
        lines.append(f"\n> 🔍 No IXPs found matching `{result.query}`.\n\n")
        lines.append("> Try a 2-letter country code (e.g. `MU`, `ZA`, `DE`) "
                     "or partial IXP name (e.g. `AMS-IX`, `LINX`, `Nairobi`).\n\n")

    lines.append(
        "---\n\n**What is an IXP?** An Internet Exchange Point is a physical facility "
        "where ISPs and networks interconnect to exchange traffic directly, "
        "reducing latency and cost by avoiding transit providers. "
        "The internet backbone literally passes through these buildings.\n"
    )

    if result.errors:
        lines.append("\n---\n\n### ⚠️ Errors\n")
        for e in result.errors:
            lines.append(f"- {e}\n")

    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 4 — Network Health Report
# ──────────────────────────────────────────────────────────────

def format_network_health_md(result: NetworkHealthResult) -> str:
    # Overall status badge
    has_critical = any("🚨" in s for s in result.health_signals)
    has_warning  = any("⚠️" in s for s in result.health_signals)
    if has_critical:
        badge = "🚨 CRITICAL ISSUES DETECTED"
    elif has_warning:
        badge = "⚠️ Warnings"
    else:
        badge = "✅ All Checks Passed"

    lines = [
        f"## 🩺 Network Health Report: `{result.resource}`\n\n",
        f"> **{badge}** | Checked at {result.queried_at}\n\n",
        "---\n\n",
        "### 🚦 Health Signals\n\n",
    ]
    for signal in result.health_signals:
        lines.append(f"- {signal}\n")
    lines.append("\n")

    # RDAP section
    lines.append("---\n\n### 📋 RDAP Registration\n\n")
    lines.append("| Field | Value |\n|-------|-------|\n")
    lines.append(f"| **Holder** | {result.rdap_holder or '_Unknown_'} |\n")
    lines.append(f"| **RIR** | {result.rdap_rir or '_Unknown_'} |\n")
    lines.append(f"| **Country** | {result.rdap_country or '_Unknown_'} |\n")
    lines.append(f"| **Status** | {result.rdap_status or '_Unknown_'} |\n")
    lines.append(f"| **Abuse Email** | {result.rdap_abuse_email or '_Not registered_'} |\n")
    lines.append("\n")

    # BGP section
    lines.append("---\n\n### 📡 BGP Routing Status\n\n")
    lines.append("| Field | Value |\n|-------|-------|\n")
    bgp_ann = "✅ Yes" if result.bgp_announced else ("❌ No" if result.bgp_announced is False else "Unknown")
    lines.append(f"| **Announced** | {bgp_ann} |\n")
    if result.bgp_announcing_asns:
        lines.append(f"| **Origin ASN(s)** | {', '.join(result.bgp_announcing_asns[:5])} |\n")
    if result.bgp_visibility_pct is not None:
        lines.append(f"| **Global Visibility** | {result.bgp_visibility_pct}% of route collectors |\n")
    lines.append("\n")

    # RPKI section
    if result.rpki_validity and result.rpki_validity != "N/A":
        rpki_icons = {"valid": "✅", "invalid": "🚨", "not-found": "⚠️", "unknown": "❓"}
        icon = rpki_icons.get(result.rpki_validity, "❓")
        lines.append("---\n\n### 🔐 RPKI Validity\n\n")
        lines.append(f"| **Result** | {icon} **{result.rpki_validity.upper()}** |\n|--|--|\n\n")
        if result.rpki_validity == "invalid":
            lines.append("> 🚨 **INVALID route**: The announcing ASN is NOT authorized "
                         "by a Route Origin Authorization (ROA). This is a strong indicator "
                         "of a BGP hijack or misconfiguration. Investigate immediately.\n\n")
        elif result.rpki_validity == "not-found":
            lines.append("> ⚠️ **No ROA found**: This route has no cryptographic protection. "
                         "It is vulnerable to accidental or malicious BGP hijacking. "
                         "The holder should publish a ROA at their RIR.\n\n")

    # PeeringDB section
    if result.peering_policy:
        lines.append("---\n\n### 🤝 PeeringDB\n\n")
        lines.append("| Field | Value |\n|-------|-------|\n")
        policy_icon = POLICY_ICONS.get(result.peering_policy, "❓")
        lines.append(f"| **Peering Policy** | {policy_icon} {result.peering_policy} |\n")
        if result.peering_ixp_count is not None:
            lines.append(f"| **IXP Presence** | {result.peering_ixp_count} exchange point(s) |\n")
        if result.peering_noc_email:
            lines.append(f"| **NOC Email** | {result.peering_noc_email} |\n")
        lines.append("\n")

    lines.append(
        "---\n\n**Tip:** For deeper investigation use:\n"
        "- `rir_prefix_history` — full ownership timeline\n"
        "- `rir_detect_transfers` — past ownership changes\n"
        "- `rir_peering_info` — full PeeringDB record\n"
        "- `rir_prefix_overview` — parent/child prefix hierarchy\n"
    )

    if result.errors:
        lines.append("\n---\n\n### ⚠️ Errors\n")
        for e in result.errors:
            lines.append(f"- {e}\n")

    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Phase 4 — Change Monitor
# ──────────────────────────────────────────────────────────────

CHANGE_FIELD_ICONS = {
    "RDAP Holder":       "🏢",
    "RIR":               "🌍",
    "Country":           "🗺️",
    "Allocation Status": "📋",
    "Abuse Email":       "📧",
    "BGP Announced":     "📡",
    "BGP Origin ASN(s)": "🔀",
    "BGP Visibility %":  "👁️",
}


def format_change_monitor_md(result: ChangeMonitorResult) -> str:
    if result.status == "baseline_created":
        return (
            f"## 📸 Change Monitor: `{result.resource}`\n\n"
            f"{result.message}\n\n"
            "---\n\n"
            "**How it works:**\n"
            "- This was the **first call** — a baseline snapshot was captured.\n"
            "- Call `rir_change_monitor` again later to detect changes.\n"
            "- Tracked fields: RDAP holder, RIR, country, allocation status, "
            "abuse email, BGP announced, BGP origin ASN(s), BGP visibility.\n"
            "- Use `reset_baseline=True` to reset after reviewing changes.\n"
        )

    status_icon = "🔔" if result.status == "changes_detected" else "✅"
    lines = [
        f"## {status_icon} Change Monitor: `{result.resource}`\n\n",
        f"{result.message}\n\n",
        f"| | |\n|--|--|\n",
        f"| **Baseline captured** | {result.baseline_captured_at or 'Unknown'} |\n",
        f"| **Checked at** | {result.checked_at} |\n",
        f"| **Current holder** | {result.current_holder or 'Unknown'} |\n",
        f"| **Current RIR** | {result.current_rir or 'Unknown'} |\n\n",
    ]

    if result.changes:
        lines.append("---\n\n### 🔔 Detected Changes\n\n")
        lines.append("| Field | Was | Now |\n|-------|-----|-----|\n")
        for change in result.changes:
            icon = CHANGE_FIELD_ICONS.get(change.field, "•")
            old = f"`{change.old_value}`" if change.old_value else "_None_"
            new = f"`{change.new_value}`" if change.new_value else "_None_"
            lines.append(f"| {icon} **{change.field}** | {old} | {new} |\n")
        lines.append("\n")

        # Specific warnings for high-severity changes
        for change in result.changes:
            if change.field == "BGP Origin ASN(s)":
                lines.append(
                    "> ⚠️ **BGP origin ASN changed** — verify this is legitimate using "
                    "`rir_check_rpki`. Unexpected ASN changes can indicate a BGP hijack.\n\n"
                )
            if change.field == "RDAP Holder":
                lines.append(
                    "> ⚠️ **Holder changed** — the registered organization for this resource "
                    "has changed. This may indicate a transfer or re-assignment. "
                    "Use `rir_detect_transfers` for full history.\n\n"
                )
    else:
        lines.append(
            "> ✅ **No changes detected.** Registration and BGP state are identical "
            "to the stored baseline.\n\n"
        )

    return "".join(lines)


# ---------------------------------------------------------------------------
# DNS Formatters (Sprint 2 — E1–E5, E7)
# ---------------------------------------------------------------------------

def format_dns_resolve_md(result: DNSResolveResult) -> str:
    """Render DNS resolve/PTR result as Markdown."""
    lines: list[str] = []
    lines.append(f"## DNS Resolution: `{result.query}`\n\n")
    lines.append(f"- **Type:** {result.query_type}\n")
    lines.append(f"- **Resolver:** {result.resolver}\n")
    lines.append(f"- **Records found:** {len(result.records)}\n\n")

    if result.records:
        lines.append("### Records\n\n")
        lines.append("| Type | TTL | Value |\n")
        lines.append("|------|-----|-------|\n")
        for rec in result.records:
            lines.append(f"| {rec.record_type} | {rec.ttl}s | `{rec.value}` |\n")
        lines.append("\n")

    if result.rdap_correlation:
        c = result.rdap_correlation
        lines.append("### RDAP Correlation\n\n")
        if c.get("holder"):
            lines.append(f"- **Holder:** {c['holder']}\n")
        if c.get("country"):
            lines.append(f"- **Country:** {c['country']}\n")
        if c.get("rir"):
            lines.append(f"- **RIR:** {c['rir']}\n")
        if c.get("prefix"):
            lines.append(f"- **Covering prefix:** `{c['prefix']}`\n")
        lines.append("\n")

    if result.error:
        lines.append(f"> ⚠️ **Error:** {result.error}\n\n")

    return "".join(lines)


def format_dns_enumerate_md(result: DNSEnumerateResult) -> str:
    """Render full DNS record enumeration as Markdown."""
    lines: list[str] = []
    lines.append(f"## DNS Enumeration: `{result.domain}`\n\n")

    all_records = [r for rtype_records in result.records.values() for r in rtype_records]
    lines.append(f"- **Total records:** {len(all_records)}\n")
    lines.append(f"- **Record types found:** {', '.join(sorted(result.records.keys())) or 'none'}\n\n")

    for rtype in sorted(result.records.keys()):
        recs = result.records[rtype]
        lines.append(f"### {rtype} Records\n\n")
        lines.append("| TTL | Value |\n")
        lines.append("|-----|-------|\n")
        for rec in recs:
            lines.append(f"| {rec.ttl}s | `{rec.value}` |\n")
        lines.append("\n")

    if result.spf:
        lines.append(f"### SPF Policy\n\n```\n{result.spf}\n```\n\n")
    if result.dmarc:
        lines.append(f"### DMARC Policy\n\n```\n{result.dmarc}\n```\n\n")

    return "".join(lines)


def format_dns_dnssec_md(result: DNSSECResult) -> str:
    """Render DNSSEC validation result as Markdown."""
    ICONS = {
        "SECURE": "✅",
        "INSECURE": "❌",
        "BOGUS": "🚨",
        "INDETERMINATE": "❓",
    }
    icon = ICONS.get(result.status, "❓")
    lines: list[str] = []
    lines.append(f"## DNSSEC Status: `{result.domain}`\n\n")
    lines.append(f"- **Status:** {icon} **{result.status}**\n")
    lines.append(f"- **Chain valid:** {'Yes' if result.chain_valid else 'No'}\n")
    lines.append(f"- **DNSKEY records:** {result.dnskey_count}\n")
    lines.append(f"- **DS records:** {result.ds_count}\n")
    lines.append(f"- **RRSIG records:** {result.rrsig_count}\n\n")

    if result.algorithms:
        lines.append(f"- **Signing algorithms:** {', '.join(result.algorithms)}\n\n")

    if result.errors:
        lines.append("### Validation Errors\n\n")
        for err in result.errors:
            lines.append(f"- {err}\n")
        lines.append("\n")

    STATUS_NOTES = {
        "SECURE": "> ✅ DNSSEC chain validates correctly to a trusted root anchor.\n\n",
        "INSECURE": "> ❌ Domain does not have DNSSEC configured.\n\n",
        "BOGUS": "> 🚨 **DNSSEC validation FAILED** — signatures are invalid or chain is broken. This may indicate tampering or misconfiguration.\n\n",
        "INDETERMINATE": "> ❓ DNSSEC status could not be determined (delegation missing or resolver error).\n\n",
    }
    lines.append(STATUS_NOTES.get(result.status, ""))
    return "".join(lines)


def format_dns_dnsbl_md(result: DNSBLResult) -> str:
    """Render DNSBL/blocklist lookup result as Markdown."""
    lines: list[str] = []
    listed_count = sum(1 for e in result.entries if e.listed)
    status_icon = "🚨" if listed_count > 0 else "✅"
    lines.append(f"## DNSBL Lookup: `{result.ip}`\n\n")
    lines.append(f"- **Status:** {status_icon} **{'LISTED on ' + str(listed_count) + ' list(s)' if listed_count else 'CLEAN'}**\n")
    lines.append(f"- **Lists checked:** {result.lists_checked}\n")
    lines.append(f"- **Listed:** {listed_count}\n")
    lines.append(f"- **Clean:** {result.lists_checked - listed_count}\n\n")

    if listed_count:
        lines.append("### Listed On\n\n")
        lines.append("| List | Return Code | Description |\n")
        lines.append("|------|-------------|-------------|\n")
        for entry in result.entries:
            if entry.listed:
                lines.append(
                    f"| `{entry.list_name}` | `{entry.return_code or 'N/A'}` | {entry.description or ''} |\n"
                )
        lines.append("\n")
        lines.append("> ⚠️ Being listed may affect email deliverability and connectivity. "
                     "Contact each list's removal process to delist.\n\n")

    return "".join(lines)


def format_email_security_md(result: EmailSecurityResult) -> str:
    """Render email security (SPF/DMARC/DKIM) result as Markdown."""
    lines: list[str] = []
    risk_icons = {"LOW": "✅", "MEDIUM": "⚠️", "HIGH": "🚨", "CRITICAL": "🔴"}
    risk_icon = risk_icons.get(result.risk_level, "❓")

    lines.append(f"## Email Security: `{result.domain}`\n\n")
    lines.append(f"- **Overall Risk:** {risk_icon} **{result.risk_level}**\n")
    lines.append(f"- **Score:** {result.score}/100\n\n")

    lines.append("### SPF\n\n")
    lines.append(f"- **Present:** {'Yes' if result.spf_present else 'No'}\n")
    if result.spf_record:
        lines.append(f"- **Record:** `{result.spf_record}`\n")
    lines.append(f"- **Valid:** {'Yes' if result.spf_valid else 'No'}\n")
    if result.spf_policy:
        lines.append(f"- **Policy:** `{result.spf_policy}`\n")
    lines.append("\n")

    lines.append("### DMARC\n\n")
    lines.append(f"- **Present:** {'Yes' if result.dmarc_present else 'No'}\n")
    if result.dmarc_record:
        lines.append(f"- **Record:** `{result.dmarc_record}`\n")
    lines.append(f"- **Valid:** {'Yes' if result.dmarc_valid else 'No'}\n")
    if result.dmarc_policy:
        lines.append(f"- **Policy:** `{result.dmarc_policy}` (p=)\n")
    if result.dmarc_pct is not None:
        lines.append(f"- **Coverage:** {result.dmarc_pct}%\n")
    lines.append("\n")

    if result.dkim_selectors_found:
        lines.append("### DKIM\n\n")
        lines.append(f"- **Selectors found:** {', '.join(f'`{s}`' for s in result.dkim_selectors_found)}\n\n")

    if result.mx_records:
        lines.append("### MX Records\n\n")
        for mx in result.mx_records:
            lines.append(f"- `{mx}`\n")
        lines.append("\n")

    if result.bimi_present:
        lines.append("### BIMI\n\n")
        lines.append(f"- **Present:** Yes\n")
        if result.bimi_record:
            lines.append(f"- **Record:** `{result.bimi_record}`\n")
        lines.append("\n")

    if result.issues:
        lines.append("### Issues Found\n\n")
        for issue in result.issues:
            lines.append(f"- {issue}\n")
        lines.append("\n")

    return "".join(lines)


def format_dns_propagation_md(result: DNSPropagationResult) -> str:
    """Render DNS propagation check result as Markdown."""
    lines: list[str] = []
    propagated_count = sum(1 for e in result.results if e.matches_majority)
    total = len(result.results)

    lines.append(f"## DNS Propagation: `{result.domain}` ({result.record_type})\n\n")
    lines.append(f"- **Propagated:** {propagated_count}/{total} resolvers\n")
    lines.append(f"- **Majority answer:** {', '.join(f'`{v}`' for v in result.majority_answer) if result.majority_answer else 'N/A'}\n")
    lines.append(f"- **Fully propagated:** {'Yes ✅' if result.propagation_complete else 'No ⏳'}\n\n")

    lines.append("### Resolver Results\n\n")
    lines.append("| Resolver | Location | Answer | Status |\n")
    lines.append("|----------|----------|--------|--------|\n")
    for entry in result.results:
        status = "✅" if entry.matches_majority else ("⚠️" if entry.answers else "❌")
        answers = ", ".join(f"`{a}`" for a in entry.answers) if entry.answers else f"*{entry.error or 'timeout'}*"
        lines.append(
            f"| {entry.resolver_name} ({entry.resolver_ip}) | {entry.location} | {answers} | {status} |\n"
        )
    lines.append("\n")

    if not result.propagation_complete:
        lines.append(
            "> ⏳ DNS changes may take 24–48 hours to fully propagate globally. "
            "TTL values on the old records control how long resolvers cache stale data.\n\n"
        )

    return "".join(lines)


# ---------------------------------------------------------------------------
# Sprint 3 Formatters — TLS (F1), CT Logs (F2), Threat Intel (G1), PDNS (E6)
# ---------------------------------------------------------------------------

def format_tls_inspect_md(result: TLSCertResult) -> str:
    lines: list[str] = []
    lines.append(f"## TLS Certificate: `{result.hostname}:{result.port}`\n\n")

    if result.error and not result.not_after:
        lines.append(f"> 🚨 **Connection failed:** {result.error}\n\n")
        return "".join(lines)

    # Expiry status
    if result.expired:
        exp_icon = "🚨"
        exp_note = "**EXPIRED**"
    elif result.days_until_expiry <= 14:
        exp_icon = "⚠️"
        exp_note = f"expires in {result.days_until_expiry}d — renew soon"
    else:
        exp_icon = "✅"
        exp_note = f"valid, {result.days_until_expiry} days remaining"

    lines.append(f"- **Expiry:** {exp_icon} {exp_note}\n")
    lines.append(f"- **Valid from:** {result.not_before}\n")
    lines.append(f"- **Valid until:** {result.not_after}\n")
    lines.append(f"- **Self-signed:** {'Yes ⚠️' if result.self_signed else 'No'}\n")
    lines.append(f"- **Chain length:** {result.chain_length} cert(s)\n")
    if result.protocol_version:
        lines.append(f"- **TLS version:** {result.protocol_version}\n")
    if result.cipher_suite:
        lines.append(f"- **Cipher suite:** `{result.cipher_suite}`\n")
    lines.append(f"- **HSTS:** {'Yes' if result.hsts else 'No'}")
    if result.hsts and result.hsts_max_age is not None:
        lines.append(f" (max-age={result.hsts_max_age}s)")
    lines.append("\n\n")

    if result.subject:
        lines.append("### Subject\n\n")
        for k, v in result.subject.items():
            lines.append(f"- **{k}:** {v}\n")
        lines.append("\n")

    if result.issuer:
        lines.append("### Issuer\n\n")
        for k, v in result.issuer.items():
            lines.append(f"- **{k}:** {v}\n")
        lines.append("\n")

    if result.san:
        lines.append("### Subject Alternative Names\n\n")
        for name in result.san[:20]:
            lines.append(f"- `{name}`\n")
        if len(result.san) > 20:
            lines.append(f"- *(and {len(result.san) - 20} more)*\n")
        lines.append("\n")

    if result.error:
        lines.append(f"> ⚠️ **Note:** {result.error}\n\n")

    return "".join(lines)


def format_ct_logs_md(result: CTLogResult) -> str:
    lines: list[str] = []
    lines.append(f"## Certificate Transparency Logs: `{result.domain}`\n\n")

    if result.error:
        lines.append(f"> 🚨 **Error:** {result.error}\n\n")
        return "".join(lines)

    lines.append(f"- **Total certs found:** {result.total_found}\n")
    lines.append(f"- **Showing:** {result.returned}\n")
    lines.append(f"- **Unique CAs:** {len(result.unique_issuers)}\n\n")

    if result.unique_issuers:
        lines.append("### Certificate Authorities Seen\n\n")
        for ca in result.unique_issuers[:10]:
            lines.append(f"- {ca}\n")
        lines.append("\n")

    if result.entries:
        lines.append("### Certificate Log Entries\n\n")
        lines.append("| Common Name | Issuer CA | Not Before | Not After |\n")
        lines.append("|-------------|-----------|------------|-----------|\n")
        for e in result.entries[:30]:
            cn = e.common_name[:40] if e.common_name else "*"
            ca = e.issuer_cn[:30] if e.issuer_cn else "?"
            lines.append(f"| `{cn}` | {ca} | {str(e.not_before)[:10]} | {str(e.not_after)[:10]} |\n")
        if result.returned > 30:
            lines.append(f"\n*…{result.returned - 30} more entries not shown.*\n")
        lines.append("\n")

    return "".join(lines)


def format_threat_intel_md(result: ThreatIntelResult) -> str:
    risk_icons = {"LOW": "✅", "MEDIUM": "⚠️", "HIGH": "🚨", "CRITICAL": "🔴"}
    icon = risk_icons.get(result.risk_level, "❓")
    lines: list[str] = []
    lines.append(f"## Threat Intelligence: `{result.ip}`\n\n")
    lines.append(f"- **Risk:** {icon} **{result.risk_level}** (score: {result.risk_score}/100)\n\n")

    lines.append("### Shodan InternetDB\n\n")
    if result.shodan_error:
        lines.append(f"> ⚠️ {result.shodan_error}\n\n")
    else:
        lines.append(f"- **Open ports:** {', '.join(f'`{p}`' for p in sorted(result.open_ports)) or 'none found'}\n")
        if result.hostnames:
            lines.append(f"- **Hostnames:** {', '.join(result.hostnames[:5])}\n")
        if result.tags:
            lines.append(f"- **Tags:** {', '.join(result.tags)}\n")
        if result.vulnerabilities:
            lines.append(f"- **CVEs:** {', '.join(result.vulnerabilities[:10])}")
            if len(result.vulnerabilities) > 10:
                lines.append(f" *(+{len(result.vulnerabilities) - 10} more)*")
            lines.append("\n")
        lines.append("\n")

    lines.append("### GreyNoise Community\n\n")
    if result.greynoise_error and result.classification is None:
        lines.append(f"> ℹ️ {result.greynoise_error}\n\n")
    else:
        if result.riot:
            lines.append("> ✅ **RIOT** — this IP belongs to a known trusted service.\n\n")
        elif result.classification == "malicious":
            lines.append("> 🚨 **Classified MALICIOUS** by GreyNoise.\n\n")
        elif result.noise:
            lines.append("> ℹ️ IP is a **benign internet scanner** (GreyNoise noise = true).\n\n")

        cl = result.classification or "unknown"
        lines.append(f"- **Classification:** {cl}\n")
        if result.greynoise_name:
            lines.append(f"- **Name:** {result.greynoise_name}\n")
        if result.greynoise_link:
            lines.append(f"- **Profile:** {result.greynoise_link}\n")
        lines.append("\n")

    return "".join(lines)


def format_passive_dns_md(result: PassiveDNSResult) -> str:
    lines: list[str] = []
    lines.append(f"## Passive DNS History: `{result.resource}`\n\n")

    if result.error:
        lines.append(f"> 🚨 **Error:** {result.error}\n\n")
        return "".join(lines)

    lines.append(f"- **Total records:** {result.total}\n")
    if result.query_starttime:
        lines.append(f"- **Query window start:** {result.query_starttime}\n")
    if result.query_endtime:
        lines.append(f"- **Query window end:** {result.query_endtime}\n")
    lines.append("\n")

    if result.records:
        lines.append("### DNS History\n\n")
        lines.append("| Type | Value | First Seen | Last Seen | Count |\n")
        lines.append("|------|-------|------------|-----------|-------|\n")
        for rec in result.records[:50]:
            first = str(rec.time_first)[:10]
            last  = str(rec.time_last)[:10]
            lines.append(
                f"| {rec.rrtype} | `{rec.rdata[:50]}` | {first} | {last} | {rec.count} |\n"
            )
        if result.total > 50:
            lines.append(f"\n*…{result.total - 50} more records not shown.*\n")
        lines.append("\n")
    else:
        lines.append("> No passive DNS records found for this resource.\n\n")

    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Sprint 5 — Humanitarian / Crisis formatters
# ──────────────────────────────────────────────────────────────

_SEVERITY_ICONS = {
    "NORMAL":           "🟢",
    "DEGRADED":         "🟡",
    "PARTIAL_SHUTDOWN": "🔴",
    "FULL_SHUTDOWN":    "🚨",
    "UNKNOWN":          "❓",
}


def format_shutdown_detect_md(result) -> str:
    icon = _SEVERITY_ICONS.get(result.severity, "❓")
    lines = [f"## {icon} BGP Shutdown Detection — `{result.country_code}`\n\n"]
    lines.append(f"- **Severity:** {icon} {result.severity.replace('_', ' ').title()}\n")
    lines.append(f"- **Withdrawn:** {result.withdrawn_pct}%\n")
    lines.append(f"- **Baseline prefixes:** {result.baseline_prefixes}\n")
    lines.append(f"- **Current prefixes:** {result.current_prefixes}\n")
    if result.detected_at:
        lines.append(f"- **Checked at:** {result.detected_at}\n")
    if result.note:
        lines.append(f"\n> ℹ️ {result.note}\n")
    lines.append("\n")
    if result.affected_asns:
        lines.append("### Sampled ASNs\n\n")
        lines.append("| ASN | Current Prefixes |\n")
        lines.append("|-----|------------------|\n")
        for a in result.affected_asns[:15]:
            lines.append(f"| {a.asn} | {a.current_prefixes} |\n")
        if len(result.affected_asns) > 15:
            lines.append(f"\n*…{len(result.affected_asns) - 15} more ASNs sampled.*\n")
        lines.append("\n")
    if result.errors:
        for e in result.errors:
            lines.append(f"> ⚠️ {e}\n")
        lines.append("\n")
    lines.append(
        "> **Note:** Baseline is established on first run. Severity is calculated by comparing "
        "current announced prefix count against stored baseline.\n"
    )
    return "".join(lines)


def format_monitor_register_md(result) -> str:
    icon = "✅" if result.registered else "❌"
    lines = [f"## {icon} Monitor Registration — `{result.resource}`\n\n"]
    lines.append(f"- **Registered:** {'Yes' if result.registered else 'No'}\n")
    lines.append(f"- **Resource:** {result.resource}\n")
    lines.append(f"- **Webhook URL:** {result.webhook_url}\n")
    lines.append(f"\n{result.message}\n")
    return "".join(lines)


def format_shutdown_timeline_md(result) -> str:
    lines = [f"## 📅 Shutdown Timeline — `{result.resource}`\n\n"]
    lines.append(f"- **Period:** {result.period_start} → {result.period_end}\n")
    lines.append(f"- **Total downtime:** {result.total_downtime_hours:.1f} hours\n")
    lines.append(f"- **Longest outage:** {result.longest_outage_hours:.1f} hours\n")
    lines.append(f"- **Affected ASNs:** {result.affected_asn_count}\n")
    if result.content_hash:
        lines.append(f"- **Evidence SHA-256:** `{result.content_hash[:16]}…`\n")
    lines.append("\n")
    if result.events:
        lines.append("### Events (max 100)\n\n")
        lines.append("| Timestamp | ASN | Event |\n")
        lines.append("|-----------|-----|-------|\n")
        for ev in result.events[:50]:
            ev_icon = "🔇" if ev.event_type == "WITHDRAWN" else "📡"
            lines.append(f"| {ev.timestamp[:19]} | {ev.asn} | {ev_icon} {ev.event_type} |\n")
        if len(result.events) > 50:
            lines.append(f"\n*…{len(result.events) - 50} more events not shown.*\n")
        lines.append("\n")
    else:
        lines.append("> No BGP state changes found in this period.\n\n")
    if result.errors:
        for e in result.errors:
            lines.append(f"> ⚠️ {e}\n")
        lines.append("\n")
    lines.append(
        "> **Integrity:** The `content_hash` is a SHA-256 digest of the full event list "
        "and can be used to verify evidence has not been tampered with.\n"
    )
    return "".join(lines)


def format_censorship_probe_md(result) -> str:
    icon = "🚨" if result.censored else "✅"
    lines = [f"## {icon} DNS Censorship Probe — `{result.domain}`\n\n"]
    lines.append(f"- **Censored:** {'Yes' if result.censored else 'No'}\n")
    if result.technique:
        lines.append(f"- **Technique:** {result.technique.replace('_', ' ').title()}\n")
    if result.truth_ips:
        lines.append(f"- **Truth IPs (neutral resolvers):** {', '.join(result.truth_ips)}\n")
    if result.affected_resolvers:
        lines.append(f"- **Affected resolvers:** {', '.join(result.affected_resolvers)}\n")
    lines.append("\n")
    if result.entries:
        lines.append("### Resolver Responses\n\n")
        lines.append("| Resolver | Region | Type | IPs | Matches? |\n")
        lines.append("|----------|--------|------|-----|----------|\n")
        for e in result.entries:
            match_icon = "✅" if e.matches_truth else "❌"
            ips_str    = ", ".join(e.response_ips[:3]) or "—"
            lines.append(
                f"| {e.resolver_name} | {e.region} | {e.response_type} "
                f"| {ips_str} | {match_icon} |\n"
            )
        lines.append("\n")
    if result.errors:
        for e in result.errors:
            lines.append(f"> ⚠️ {e}\n")
        lines.append("\n")
    return "".join(lines)


def format_satellite_connectivity_md(result) -> str:
    icon = "🛰️" if result.any_satellite_active else "📡"
    lines = [f"## {icon} Satellite Connectivity — `{result.country_code}`\n\n"]
    lines.append(f"- **Any satellite active:** {'Yes' if result.any_satellite_active else 'No'}\n\n")
    if result.providers:
        lines.append("### Satellite Providers\n\n")
        lines.append("| Provider | ASN | Active | Prefixes Announced |\n")
        lines.append("|----------|-----|--------|--------------------|\n")
        for p in result.providers:
            active_icon = "✅" if p.is_active else "❌"
            lines.append(f"| {p.name} | {p.asn} | {active_icon} | {p.prefixes_announced} |\n")
        lines.append("\n")
    if result.errors:
        for e in result.errors:
            lines.append(f"> ⚠️ {e}\n")
        lines.append("\n")
    lines.append(
        "> **Note:** Satellite ASN activity indicates global BGP presence; "
        "coverage of a specific country requires beam / capacity data not available here.\n"
    )
    return "".join(lines)


def format_chokepoints_md(result) -> str:
    score = result.resilience_score
    if score >= 70:   r_icon = "🟢"
    elif score >= 40: r_icon = "🟡"
    else:             r_icon = "🔴"

    lines = [f"## {r_icon} Internet Chokepoints — `{result.country_code}`\n\n"]
    lines.append(f"- **Resilience score:** {r_icon} {result.resilience_score}/100\n")
    lines.append(f"- **Total in-country ASNs:** {result.total_in_country_asns}\n")
    lines.append(f"- **Single-upstream (critical) ASNs:** {result.single_upstream_asns}\n")
    lines.append("\n")
    if result.transit_providers:
        lines.append("### Top Transit Providers (by dependency)\n\n")
        lines.append("| Provider ASN | Name | Dependent ASNs | Impact |\n")
        lines.append("|-------------|------|----------------|--------|\n")
        for p in result.transit_providers[:10]:
            name = p.name or "—"
            lines.append(f"| {p.asn} | {name} | {p.dependent_country_asns} | {p.impact_pct}% |\n")
        lines.append("\n")
    else:
        lines.append("> No transit provider data available.\n\n")
    if result.errors:
        for e in result.errors:
            lines.append(f"> ⚠️ {e}\n")
        lines.append("\n")
    lines.append(
        "> **Resilience score:** 100 = highly diverse transit, 0 = single point of failure. "
        "Lower score = greater risk of complete internet isolation if a transit provider is cut.\n"
    )
    return "".join(lines)


def format_ooni_report_md(result) -> str:
    lines = [f"## 🔭 OONI Censorship Report — `{result.country_code}`\n\n"]
    if result.period:
        lines.append(f"- **Period:** {result.period}\n")
    lines.append(f"- **Measurements:** {result.measurements_count}\n")
    if result.tor_accessible is not None:
        tor_icon = "✅" if result.tor_accessible else "❌"
        lines.append(f"- **Tor accessible:** {tor_icon}\n")
    lines.append("\n")
    if result.blocked_domains:
        lines.append("### Confirmed Blocked Domains\n\n")
        for d in result.blocked_domains[:20]:
            lines.append(f"- `{d}`\n")
        if len(result.blocked_domains) > 20:
            lines.append(f"\n*…{len(result.blocked_domains) - 20} more domains blocked.*\n")
        lines.append("\n")
    else:
        lines.append("> No confirmed blocked domains in this period.\n\n")
    if result.accessible_tools:
        lines.append(f"**Accessible circumvention tools:** {', '.join(result.accessible_tools)}\n\n")
    if result.errors:
        for e in result.errors:
            lines.append(f"> ⚠️ {e}\n")
        lines.append("\n")
    lines.append("> Data from [OONI (Open Observatory of Network Interference)](https://ooni.org/)\n")
    return "".join(lines)


def format_country_health_md(result) -> str:
    icon = _SEVERITY_ICONS.get(result.severity, "❓")
    lines = [f"## {icon} Country Internet Health — `{result.country_code}`\n\n"]
    lines.append(f"- **Overall score:** {icon} {result.score}/100 — {result.severity.replace('_', ' ').title()}\n")
    lines.append(f"- **BGP routing score:** {result.bgp_score}/100 (weight 40%)\n")
    lines.append(f"- **DNS censorship score:** {result.dns_score}/100 (weight 30%)\n")
    lines.append(f"- **App accessibility score:** {result.app_score}/100 (weight 20%)\n")
    sat_icon = "✅" if result.satellite_available else "❌"
    lines.append(f"- **Satellite available:** {sat_icon} (weight 10%)\n")
    if result.last_checked:
        lines.append(f"- **Last checked:** {result.last_checked}\n")
    lines.append("\n")
    if result.summary:
        lines.append(f"**Summary:** {result.summary}\n\n")
    if result.errors:
        lines.append("### Partial Errors\n\n")
        for e in result.errors:
            lines.append(f"> ⚠️ {e}\n")
        lines.append("\n")
    lines.append(
        "> **Methodology:** BGP score from shutdown detection, DNS score from censorship probe "
        "against neutral resolvers, App score from OONI measurements, Satellite from BGP announced-prefixes.\n"
    )
    return "".join(lines)


# ──────────────────────────────────────────────────────────────
# Sprint 4 — BGP Depth formatters
# ──────────────────────────────────────────────────────────────

def format_irr_result_md(result) -> str:
    from models import IRRResult
    lines = []
    icon = "✅" if result.consistent else ("⚠️" if result.route_objects else "❌")
    lines.append(f"## {icon} IRR Validation — `{result.prefix}` (origin {result.asn})\n\n")

    status = "Consistent — all route objects match query ASN" if result.consistent else (
        "Inconsistent — route objects do not all match query ASN" if result.route_objects
        else "No route objects found in any IRR database"
    )
    lines.append(f"**Status:** {status}\n\n")

    if result.irr_sources_found:
        lines.append(f"- **IRR sources with objects:** {', '.join(result.irr_sources_found)}\n")
    if result.missing_irr_sources:
        lines.append(f"- **Not found in:** {', '.join(result.missing_irr_sources)}\n")
    lines.append("\n")

    if result.route_objects:
        lines.append("### Route Objects\n\n")
        lines.append("| IRR Source | Route | Origin ASN | Matches? |\n")
        lines.append("|-----------|-------|-----------|----------|\n")
        for obj in result.route_objects[:30]:
            match_icon = "✅" if obj.matches_query_asn else "❌"
            lines.append(f"| {obj.irr_source} | `{obj.route}` | {obj.origin_asn} | {match_icon} |\n")
        if len(result.route_objects) > 30:
            lines.append(f"\n*…{len(result.route_objects) - 30} more route objects not shown.*\n")
        lines.append("\n")

    if result.errors:
        for e in result.errors:
            lines.append(f"> ⚠️ {e}\n")
        lines.append("\n")

    lines.append(
        "> **Note:** IRR (Internet Routing Registry) route objects tell ISPs which ASN is "
        "authorised to announce a prefix. Inconsistent or missing objects can cause route "
        "filtering and prefix reachability issues.\n"
    )
    return "".join(lines)


def format_route_leak_md(result) -> str:
    CONF_ICONS = {"high": "🚨", "medium": "⚠️", "low": "🟡", "none": "✅"}
    icon = CONF_ICONS.get(result.confidence, "❓")
    lines = []
    lines.append(f"## {icon} Route Leak Detection — `{result.prefix}`\n\n")
    lines.append(f"- **Leak detected:** {'Yes' if result.leak_detected else 'No'}\n")
    lines.append(f"- **Confidence:** {result.confidence.upper()}\n")
    if result.origin_asns:
        lines.append(f"- **Origin ASNs seen:** {', '.join(result.origin_asns)}\n")
    lines.append(f"- **Source:** {result.source}\n\n")

    if result.suspect_asns:
        lines.append(f"**Suspect ASNs:** {', '.join(result.suspect_asns)}\n\n")

    if result.affected_paths:
        lines.append("### Anomalous AS Paths\n\n")
        lines.append("| Suspect ASN | Collector | AS Path |\n")
        lines.append("|-------------|-----------|--------|\n")
        for path in result.affected_paths[:10]:
            as_path_str = " → ".join(path.as_path) if path.as_path else "—"
            collector   = path.collector or "—"
            lines.append(f"| {path.suspect_asn} | {collector} | `{as_path_str[:80]}` |\n")
        lines.append("\n")
    else:
        lines.append("> No anomalous AS paths detected.\n\n")

    if result.errors:
        for e in result.errors:
            lines.append(f"> ⚠️ {e}\n")
        lines.append("\n")

    lines.append(
        "> **Note:** Route leaks occur when an ASN re-announces routes it received from an "
        "upstream to another upstream (valley-free violation). This analysis checks for "
        "AS-path loops and multiple origin ASNs — cross-reference with RPKI for confirmation.\n"
    )
    return "".join(lines)


def format_looking_glass_md(result) -> str:
    lines = []
    announced = bool(result.entries)
    icon = "📡" if announced else "🔇"
    lines.append(f"## {icon} BGP Looking Glass — `{result.prefix}`\n\n")
    lines.append(f"- **Unique AS paths:** {result.unique_as_paths}\n")
    lines.append(f"- **Vantage points shown:** {len(result.entries)}\n")
    if result.queried_at:
        lines.append(f"- **Queried at:** {result.queried_at}\n")
    lines.append(f"- **Source:** {result.source}\n\n")

    if result.entries:
        lines.append("### AS Paths by Vantage Point\n\n")
        lines.append("| Collector | Region | Peer ASN | AS Path | Communities |\n")
        lines.append("|-----------|--------|----------|---------|-------------|\n")
        for entry in result.entries:
            as_path_str = " → ".join(entry.as_path) if entry.as_path else "—"
            comms_str   = ", ".join(entry.communities) if entry.communities else "—"
            region      = entry.region or "—"
            lines.append(
                f"| {entry.collector} | {region} | AS{entry.peer_asn} "
                f"| `{as_path_str[:60]}` | {comms_str[:40]} |\n"
            )
        lines.append("\n")
    else:
        lines.append("> No routing table entries found for this prefix.\n\n")

    if result.errors:
        for e in result.errors:
            lines.append(f"> ⚠️ {e}\n")
        lines.append("\n")

    return "".join(lines)


def format_route_stability_md(result) -> str:
    score = result.stability_score
    if score >= 90:
        score_icon = "🟢"
    elif score >= 60:
        score_icon = "🟡"
    else:
        score_icon = "🔴"

    lines = []
    lines.append(f"## {score_icon} Route Stability — `{result.prefix}`\n\n")
    lines.append(f"- **Stability score:** {score_icon} {result.stability_score}/100\n")
    lines.append(f"- **State changes:** {result.state_changes}\n")
    lines.append(f"- **Uptime:** {result.uptime_pct}%\n")
    lines.append(f"- **Stable:** {'Yes' if result.is_stable else 'No (>2 state changes)'}\n")
    lines.append(f"- **Window analysed:** last {result.hours_analyzed} hour(s)\n")
    lines.append(f"- **Source:** {result.source}\n\n")

    if result.events:
        lines.append("### Route Events (most recent 20)\n\n")
        lines.append("| Timestamp | Event |\n")
        lines.append("|-----------|-------|\n")
        for ev in result.events[-20:]:
            ev_icon = "📡" if ev.event_type == "announced" else "🔇"
            lines.append(f"| {ev.timestamp[:19]} | {ev_icon} {ev.event_type.title()} |\n")
        lines.append("\n")
    else:
        lines.append("> No state-change events found in this window (route appears stable).\n\n")

    if result.errors:
        for e in result.errors:
            lines.append(f"> ⚠️ {e}\n")
        lines.append("\n")

    return "".join(lines)
