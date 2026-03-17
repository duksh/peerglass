"""
models.py — Pydantic data models for PeerGlass.

Phase 1: IP, ASN, Abuse Contact queries across all 5 RIRs
Phase 2: RPKI/ROA validation, BGP routing status, Org resource auditing
Phase 3: Historical allocation tracking, transfer detection, IPv4 exhaustion,
         prefix hierarchy (parent/child/sibling relationships)
"""

from __future__ import annotations
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional, List, Any
from enum import Enum


# ──────────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────────

class RIRName(str, Enum):
    AFRINIC = "AFRINIC"
    APNIC   = "APNIC"
    ARIN    = "ARIN"
    LACNIC  = "LACNIC"
    RIPE    = "RIPE"


class ResponseFormat(str, Enum):
    MARKDOWN = "markdown"
    JSON     = "json"


class RPKIValidity(str, Enum):
    VALID     = "valid"
    INVALID   = "invalid"
    NOT_FOUND = "not-found"
    UNKNOWN   = "unknown"


# ──────────────────────────────────────────────────────────────
# Input Models — Phase 1
# ──────────────────────────────────────────────────────────────

class IPQueryInput(BaseModel):
    """Input for querying an IP address across all 5 RIRs."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    ip_address: str = Field(
        ...,
        description="IPv4 or IPv6 address (e.g. '1.1.1.1' or '2001:4860:4860::8888')",
        min_length=3, max_length=45,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for machine-readable",
    )


class ASNQueryInput(BaseModel):
    """Input for querying an ASN across all 5 RIRs."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    asn: str = Field(
        ...,
        description="Autonomous System Number. Accepts 'AS15169', '15169', or 'AS-GOOGLE'",
        min_length=1, max_length=20,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for machine-readable",
    )


class AbuseContactInput(BaseModel):
    """Input for abuse contact lookup by IP address."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    ip_address: str = Field(
        ...,
        description="IPv4 or IPv6 address to find abuse contact for (e.g. '185.220.101.1')",
        min_length=3, max_length=45,
    )


# ──────────────────────────────────────────────────────────────
# Input Models — Phase 2
# ──────────────────────────────────────────────────────────────

class RPKICheckInput(BaseModel):
    """Input for RPKI/ROA validity check."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    prefix: str = Field(
        ...,
        description="IP prefix in CIDR notation (e.g. '1.1.1.0/24' or '2400:cb00::/32')",
        min_length=7, max_length=50,
    )
    asn: str = Field(
        ...,
        description="ASN claiming to originate this prefix (e.g. 'AS13335' or '13335')",
        min_length=1, max_length=20,
    )

    @field_validator("asn")
    @classmethod
    def normalize_asn(cls, v: str) -> str:
        stripped = v.upper().lstrip("AS")
        return stripped if stripped.isdigit() else v


class BGPStatusInput(BaseModel):
    """Input for BGP routing table status check."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    resource: str = Field(
        ...,
        description=(
            "IP prefix (e.g. '1.1.1.0/24') or ASN (e.g. 'AS15169') "
            "to check in the global BGP routing table"
        ),
        min_length=2, max_length=50,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for machine-readable",
    )


class OrgAuditInput(BaseModel):
    """Input for organization-wide resource audit across all RIRs."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    org_name: str = Field(
        ...,
        description=(
            "Organization name or handle to audit (e.g. 'Cloudflare', 'GOOGL-ARIN'). "
            "Partial matches are supported."
        ),
        min_length=2, max_length=100,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for machine-readable",
    )


class AnnouncedPrefixesInput(BaseModel):
    """Input for fetching all BGP-announced prefixes by an ASN."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    asn: str = Field(
        ...,
        description="ASN whose announced prefixes to fetch (e.g. 'AS13335' or '15169')",
        min_length=1, max_length=20,
    )
    min_peers_seeing: int = Field(
        default=5,
        description="Minimum BGP peer count seeing the prefix (filters out noise)",
        ge=1, le=500,
    )


# ──────────────────────────────────────────────────────────────
# Output Models — Phase 1
# ──────────────────────────────────────────────────────────────

class RIRQueryResult(BaseModel):
    """Raw result from a single RIR RDAP query."""
    rir: RIRName
    status: str                         # ok | not_found | error | rate_limited
    queried_at: Optional[str]  = None
    data: Optional[dict[str, Any]] = None
    error: Optional[str]       = None


class NetworkResource(BaseModel):
    """Normalized IP network registration — unified schema across all 5 RIRs."""
    rir: str
    prefix: Optional[str]          = None
    handle: Optional[str]          = None
    name: Optional[str]            = None
    org_name: Optional[str]        = None
    country: Optional[str]         = None
    allocation_date: Optional[str] = None
    last_changed: Optional[str]    = None
    abuse_email: Optional[str]     = None
    status: Optional[str]          = None
    ip_version: Optional[int]      = None
    raw: Optional[dict[str, Any]]  = None


class ASNResource(BaseModel):
    """Normalized ASN registration — unified schema across all 5 RIRs."""
    rir: str
    asn: Optional[str]             = None
    name: Optional[str]            = None
    org_name: Optional[str]        = None
    country: Optional[str]         = None
    allocation_date: Optional[str] = None
    last_changed: Optional[str]    = None
    abuse_email: Optional[str]     = None
    status: Optional[str]          = None
    raw: Optional[dict[str, Any]]  = None


class AbuseContact(BaseModel):
    """Extracted abuse contact for a given IP address."""
    ip_address: str
    authoritative_rir: Optional[str]   = None
    abuse_email: List[str]             = Field(default_factory=list)
    abuse_phone: List[str]             = Field(default_factory=list)
    network_name: Optional[str]        = None
    network_handle: Optional[str]      = None
    org_name: Optional[str]            = None
    country: Optional[str]             = None
    raw: Optional[dict[str, Any]]      = None


# ──────────────────────────────────────────────────────────────
# Output Models — Phase 2
# ──────────────────────────────────────────────────────────────

class RPKIResult(BaseModel):
    """RPKI/ROA validity result for a prefix + ASN pair."""
    prefix: str
    asn: str
    validity: RPKIValidity
    covering_roas: List[dict[str, Any]] = Field(default_factory=list)
    source: str                         = "Cloudflare RPKI Validator"
    description: Optional[str]         = None


class BGPPrefix(BaseModel):
    """A single BGP-announced prefix entry from the routing table."""
    prefix: str
    origin_asn: Optional[str]          = None
    peers_seeing: Optional[int]        = None
    first_seen: Optional[str]          = None
    last_seen: Optional[str]           = None
    is_more_specific: Optional[bool]   = None


class BGPCommunity(BaseModel):
    """A single BGP community value attached to a route announcement."""
    asn: int
    value: int
    description: Optional[str] = None


# Well-known BGP communities (RFC 1997, RFC 7999) decoded to human-readable descriptions.
# Keyed by (asn, value) tuples.
BGP_WELL_KNOWN_COMMUNITIES: dict[tuple[int, int], str] = {
    (65535, 65281): "NO_EXPORT — do not advertise beyond this AS boundary",
    (65535, 65282): "NO_ADVERTISE — do not advertise to any BGP peer",
    (65535, 65283): "NO_EXPORT_SUBCONFED — do not advertise outside local confederation",
    (65535, 666):   "BLACKHOLE (RFC 7999) — discard traffic, do not forward",
    (65535, 65284): "NOPEER — do not export to peer AS (RFC 3765)",
}


class BGPStatusResult(BaseModel):
    """BGP routing table status for a prefix or ASN resource."""
    resource: str
    resource_type: str                  # prefix | asn
    is_announced: bool
    announcing_asns: List[str]          = Field(default_factory=list)
    announced_prefixes: List[BGPPrefix] = Field(default_factory=list)
    visibility_percent: Optional[float] = None
    communities: List[BGPCommunity]     = Field(default_factory=list)
    source: str                         = "RIPE Stat"
    queried_at: Optional[str]          = None


class OrgResource(BaseModel):
    """A single IP block or ASN resource belonging to an organization."""
    rir: str
    resource_type: str                  # ip | asn
    handle: Optional[str]              = None
    prefix_or_asn: Optional[str]       = None
    name: Optional[str]                = None
    country: Optional[str]             = None
    status: Optional[str]              = None
    allocation_date: Optional[str]     = None


class OrgAuditResult(BaseModel):
    """Aggregated view of all resources registered to an organization across all RIRs."""
    org_query: str
    total_resources: int
    ip_blocks: List[OrgResource]        = Field(default_factory=list)
    asns: List[OrgResource]             = Field(default_factory=list)
    rirs_found_in: List[str]            = Field(default_factory=list)
    errors: List[str]                   = Field(default_factory=list)


# ──────────────────────────────────────────────────────────────
# Input Models — Phase 3
# ──────────────────────────────────────────────────────────────

class PrefixHistoryInput(BaseModel):
    """Input for historical ownership query on a prefix or ASN."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    resource: str = Field(
        ...,
        description=(
            "IP prefix in CIDR notation (e.g. '1.1.1.0/24') or ASN (e.g. 'AS15169'). "
            "Returns full ownership timeline and registration change events."
        ),
        min_length=2, max_length=50,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for machine-readable",
    )


class TransferDetectInput(BaseModel):
    """Input for cross-org / cross-RIR transfer detection."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    resource: str = Field(
        ...,
        description=(
            "IP prefix (e.g. '8.8.8.0/24') or ASN (e.g. 'AS15169') "
            "to scan for past ownership transfers between organizations or RIRs."
        ),
        min_length=2, max_length=50,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for machine-readable",
    )


class IPv4StatsInput(BaseModel):
    """Input for the global IPv4 exhaustion / allocation statistics dashboard."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    rir_filter: Optional[str] = Field(
        default=None,
        description=(
            "Optional: filter to a single RIR. "
            "Accepts 'AFRINIC', 'APNIC', 'ARIN', 'LACNIC', or 'RIPE'. "
            "Leave empty to get all 5 RIRs."
        ),
        pattern="^(AFRINIC|APNIC|ARIN|LACNIC|RIPE)?$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for machine-readable",
    )
    include_blocks: bool = Field(
        default=False,
        description=(
            "If true, include raw delegated IPv4 block rows from the selected RIR. "
            "Requires rir_filter to be set."
        ),
    )
    status_filter: Optional[str] = Field(
        default=None,
        description=(
            "Optional IPv4 status filter for block rows: allocated, assigned, available. "
            "'free' is normalized to 'available'."
        ),
    )
    country_filter: Optional[str] = Field(
        default=None,
        description="Optional 2-letter ISO country code filter for IPv4 block rows (e.g. 'GH', 'ZA').",
    )
    limit: int = Field(
        default=100,
        description="Maximum number of IPv4 block rows to return when include_blocks=true.",
        ge=1,
        le=5000,
    )
    offset: int = Field(
        default=0,
        description="Pagination offset for IPv4 block rows when include_blocks=true.",
        ge=0,
        le=1_000_000,
    )

    @field_validator("status_filter")
    @classmethod
    def normalize_status_filter(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v:
            return None
        status = v.strip().lower()
        if status == "free":
            status = "available"
        allowed = {"allocated", "assigned", "available"}
        if status not in allowed:
            raise ValueError("status_filter must be one of: allocated, assigned, available, free")
        return status

    @field_validator("country_filter")
    @classmethod
    def normalize_country_filter(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v:
            return None
        country = v.strip().upper()
        if len(country) != 2 or not country.isalpha():
            raise ValueError("country_filter must be a 2-letter ISO country code")
        return country


class PrefixOverviewInput(BaseModel):
    """Input for prefix hierarchy and rich overview query."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    prefix: str = Field(
        ...,
        description=(
            "IP prefix in CIDR notation (e.g. '1.1.1.0/24'). "
            "Returns the parent allocation, sibling blocks, and child assignments."
        ),
        min_length=7, max_length=50,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for machine-readable",
    )


# ──────────────────────────────────────────────────────────────
# Output Models — Phase 3
# ──────────────────────────────────────────────────────────────

class HistoricalEvent(BaseModel):
    """A single dated event in a resource's registration history."""
    event_date: Optional[str]       = None   # ISO date string
    event_type: str                 = ""     # created | updated | transferred | status_change
    attribute: Optional[str]        = None   # which RDAP field changed (legacy sources may say WHOIS)
    old_value: Optional[str]        = None
    new_value: Optional[str]        = None
    source: Optional[str]           = None   # which API provided this


class PrefixHistoryResult(BaseModel):
    """Full historical record for a prefix or ASN."""
    resource: str
    resource_type: str                       # prefix | asn
    current_holder: Optional[str]           = None
    current_rir: Optional[str]              = None
    registration_date: Optional[str]        = None
    total_events: int                       = 0
    events: List[HistoricalEvent]           = Field(default_factory=list)
    sources: List[str]                      = Field(default_factory=list)
    errors: List[str]                       = Field(default_factory=list)


class TransferEvent(BaseModel):
    """A detected transfer of a resource between organizations or RIRs."""
    transfer_date: Optional[str]            = None
    transfer_type: str                      = ""   # inter-rir | intra-rir | org-change
    from_org: Optional[str]                = None
    to_org: Optional[str]                  = None
    from_rir: Optional[str]                = None
    to_rir: Optional[str]                  = None
    evidence: Optional[str]                = None  # which field change triggered detection


class TransferDetectResult(BaseModel):
    """Transfer history for a prefix or ASN."""
    resource: str
    resource_type: str
    transfers_detected: int
    transfers: List[TransferEvent]          = Field(default_factory=list)
    current_holder: Optional[str]          = None
    current_rir: Optional[str]             = None
    first_registered: Optional[str]        = None
    sources: List[str]                     = Field(default_factory=list)
    notes: List[str]                       = Field(default_factory=list)


class IPv4DelegatedBlock(BaseModel):
    """A single IPv4 delegated row from an RIR extended stats file."""
    rir: str
    country: Optional[str]                 = None
    start_ip: str
    end_ip: str
    address_count: int
    date: Optional[str]                    = None
    status: str


class RIRDelegationStats(BaseModel):
    """IPv4, IPv6, and ASN delegation statistics for one RIR."""
    rir: str
    region: str
    ipv4_allocated: int                    = 0   # /32 equivalents allocated to LIRs
    ipv4_assigned: int                     = 0   # /32 equivalents assigned to end-users
    ipv4_available: int                    = 0   # remaining free pool (where published)
    ipv4_total_prefixes: int               = 0   # count of distinct IPv4 records
    ipv6_allocated: int                    = 0   # /48 equivalents
    ipv6_total_prefixes: int               = 0
    asn_allocated: int                     = 0
    asn_total: int                         = 0
    stats_date: Optional[str]             = None
    source: str                            = "NRO Delegation Stats"
    errors: List[str]                      = Field(default_factory=list)


class GlobalIPv4Stats(BaseModel):
    """Aggregated IPv4/IPv6/ASN stats across all 5 RIRs."""
    queried_at: str
    rirs: List[RIRDelegationStats]         = Field(default_factory=list)
    global_ipv4_prefixes: int             = 0
    global_ipv6_prefixes: int             = 0
    global_asns: int                      = 0
    ipv4_blocks: List[IPv4DelegatedBlock] = Field(default_factory=list)
    blocks_total: int                     = 0
    blocks_returned: int                  = 0
    blocks_limit: Optional[int]           = None
    blocks_offset: Optional[int]          = None
    blocks_filters: dict[str, Any]        = Field(default_factory=dict)
    errors: List[str]                      = Field(default_factory=list)


class RelatedPrefix(BaseModel):
    """A prefix related to the queried one (parent, sibling, or child)."""
    prefix: str
    relationship: str                      # parent | more-specific | less-specific | sibling
    announced: Optional[bool]             = None
    holder: Optional[str]                 = None
    origin_asn: Optional[str]            = None


class PrefixOverviewResult(BaseModel):
    """Rich overview of a prefix: holder, hierarchy, BGP status, related blocks."""
    prefix: str
    holder: Optional[str]                 = None
    holder_handle: Optional[str]          = None
    rir: Optional[str]                    = None
    country: Optional[str]               = None
    announced: Optional[bool]            = None
    announcing_asns: List[str]            = Field(default_factory=list)
    block_size_ips: Optional[int]        = None
    related_prefixes: List[RelatedPrefix] = Field(default_factory=list)
    allocation_status: Optional[str]     = None
    source: str                           = "RIPE Stat"
    errors: List[str]                     = Field(default_factory=list)


# ──────────────────────────────────────────────────────────────
# Input Models — Phase 4
# ──────────────────────────────────────────────────────────────

class PeeringInfoInput(BaseModel):
    """Input for PeeringDB lookup of an ASN."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    asn: str = Field(
        ...,
        description=(
            "Autonomous System Number to look up in PeeringDB "
            "(e.g. 'AS13335', '13335', 'AS-CLOUDFLARE'). "
            "Returns peering policy, IXP presence, and NOC contact."
        ),
        min_length=1, max_length=20,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for machine-readable",
    )


class IXPLookupInput(BaseModel):
    """Input for IXP lookup by country or name."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    query: str = Field(
        ...,
        description=(
            "Country code (e.g. 'MU', 'US', 'DE') or partial IXP name "
            "(e.g. 'LINX', 'AMS-IX', 'Nairobi'). "
            "Returns matching Internet Exchange Points with member counts."
        ),
        min_length=1, max_length=60,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for machine-readable",
    )


class NetworkHealthInput(BaseModel):
    """Input for the combined network health report."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    resource: str = Field(
        ...,
        description=(
            "IP address, prefix in CIDR notation, or ASN "
            "(e.g. '1.1.1.1', '1.1.1.0/24', 'AS13335'). "
            "Runs RDAP + BGP + RPKI + PeeringDB checks in parallel."
        ),
        min_length=2, max_length=50,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for machine-readable",
    )


class ChangeMonitorInput(BaseModel):
    """Input for session-scoped change monitoring."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    resource: str = Field(
        ...,
        description=(
            "IP prefix (e.g. '8.8.8.0/24') or ASN (e.g. 'AS15169') to monitor. "
            "On first call, captures a baseline snapshot. "
            "On subsequent calls, reports what changed since the baseline."
        ),
        min_length=2, max_length=50,
    )
    reset_baseline: bool = Field(
        default=False,
        description=(
            "If True, discard the existing baseline and capture a fresh snapshot. "
            "Use this to reset monitoring after reviewing detected changes."
        ),
    )


# ──────────────────────────────────────────────────────────────
# Output Models — Phase 4
# ──────────────────────────────────────────────────────────────

class IXPRecord(BaseModel):
    """A single Internet Exchange Point from PeeringDB."""
    ix_id: Optional[int]               = None
    name: str                          = ""
    name_long: Optional[str]           = None
    city: Optional[str]                = None
    country: Optional[str]             = None
    region: Optional[str]              = None
    website: Optional[str]             = None
    tech_email: Optional[str]          = None
    member_count: Optional[int]        = None
    speed_avg_mbps: Optional[int]      = None
    traffic_stats_url: Optional[str]   = None
    # For peering_info: the AS's local peering IP at this IX
    ipaddr4: Optional[str]             = None
    ipaddr6: Optional[str]             = None
    speed: Optional[int]               = None


class PeeringInfoResult(BaseModel):
    """PeeringDB record for an ASN including peering policy and IXP presence."""
    asn: str
    network_name: Optional[str]        = None
    aka: Optional[str]                 = None
    website: Optional[str]             = None
    info_type: Optional[str]           = None        # NSP | Cable | Educational | ...
    policy_general: Optional[str]      = None        # Open | Selective | Restrictive | No Peering
    policy_locations: Optional[str]    = None
    policy_ratio: Optional[bool]       = None
    policy_contracts: Optional[str]    = None
    noc_email: Optional[str]           = None
    noc_phone: Optional[str]           = None
    abuse_email: Optional[str]         = None
    peering_email: Optional[str]       = None
    irr_as_set: Optional[str]          = None        # e.g. AS-CLOUDFLARE
    info_prefixes4: Optional[int]      = None        # IPv4 prefixes announced
    info_prefixes6: Optional[int]      = None
    ixp_presence: List[IXPRecord]      = Field(default_factory=list)
    neighbour_asns: List[str]          = Field(default_factory=list)
    source: str                        = "PeeringDB + RIPE Stat"
    errors: List[str]                  = Field(default_factory=list)


class IXPLookupResult(BaseModel):
    """Results of an IXP search by country or name."""
    query: str
    total_found: int
    ixps: List[IXPRecord]              = Field(default_factory=list)
    errors: List[str]                  = Field(default_factory=list)


class NetworkHealthResult(BaseModel):
    """Combined health report: RDAP + BGP + RPKI + PeeringDB."""
    resource: str
    resource_type: str                 # ip | prefix | asn
    queried_at: str

    # RDAP
    rdap_holder: Optional[str]         = None
    rdap_rir: Optional[str]            = None
    rdap_country: Optional[str]        = None
    rdap_abuse_email: Optional[str]    = None
    rdap_status: Optional[str]         = None

    # BGP
    bgp_announced: Optional[bool]      = None
    bgp_announcing_asns: List[str]     = Field(default_factory=list)
    bgp_visibility_pct: Optional[float]= None

    # RPKI (only for prefix queries)
    rpki_validity: Optional[str]       = None    # valid | invalid | not-found | unknown | N/A

    # PeeringDB (only when an ASN is known)
    peering_policy: Optional[str]      = None
    peering_ixp_count: Optional[int]   = None
    peering_noc_email: Optional[str]   = None

    # Overall health signal
    health_signals: List[str]          = Field(default_factory=list)
    errors: List[str]                  = Field(default_factory=list)


class FieldDelta(BaseModel):
    """A single changed field in a change monitoring diff."""
    field: str
    old_value: Optional[str]           = None
    new_value: Optional[str]           = None
    changed_at: str                    = ""


class ChangeMonitorResult(BaseModel):
    """Result of comparing current state against a stored baseline."""
    resource: str
    resource_type: str
    status: str                        # "baseline_created" | "changes_detected" | "no_changes"
    baseline_captured_at: Optional[str]= None
    checked_at: str                    = ""
    changes: List[FieldDelta]          = Field(default_factory=list)
    current_holder: Optional[str]      = None
    current_rir: Optional[str]         = None
    message: str                       = ""
