/**
 * PeerGlass API client — typed wrappers for all 41 REST endpoints.
 * Base URL is read from VITE_API_BASE_URL env var (defaults to http://localhost:8000).
 */

const BASE = (import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000').replace(/\/$/, '')

type Format = 'markdown' | 'json'

// Called on each retry attempt so the UI can show a "warming up" message.
type RetryCallback = (attempt: number, maxAttempts: number) => void
let _retryCallback: RetryCallback | null = null
export function setRetryCallback(fn: RetryCallback | null): void { _retryCallback = fn }

// Retries on network failures (TypeError: Failed to fetch) up to MAX_RETRIES times
// with linear 10 s backoff. HTTP errors are not retried.
async function fetchWithRetry(url: string, options?: RequestInit): Promise<Response> {
  const MAX_RETRIES = 3
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fetch(url, options)
    } catch (err) {
      if (attempt === MAX_RETRIES) throw err
      _retryCallback?.(attempt, MAX_RETRIES - 1)
      await new Promise(r => setTimeout(r, 10_000 * attempt)) // 10 s, 20 s
    }
  }
  throw new Error('unreachable')
}

async function get(path: string, params: Record<string, string | number | boolean | undefined> = {}, format: Format = 'markdown'): Promise<string> {
  const url = new URL(BASE + path)
  Object.entries({ ...params, format }).forEach(([k, v]) => {
    if (v !== undefined) url.searchParams.set(k, String(v))
  })
  const res = await fetchWithRetry(url.toString())
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
  if (format === 'json') return res.text()
  return res.text()
}

async function post(path: string, body: unknown, format: Format = 'markdown'): Promise<string> {
  const url = new URL(BASE + path)
  url.searchParams.set('format', format)
  const res = await fetchWithRetry(url.toString(), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
  return res.text()
}

// ── Registry ─────────────────────────────────────────────────
export const queryIp    = (ip: string, fmt?: Format)  => get(`/v1/ip/${encodeURIComponent(ip)}`, {}, fmt)
export const queryAsn   = (asn: string, fmt?: Format) => get(`/v1/asn/${encodeURIComponent(asn)}`, {}, fmt)
export const queryAbuse = (ip: string, fmt?: Format)  => get(`/v1/abuse/${encodeURIComponent(ip)}`, {}, fmt)
export const queryOrg   = (name: string, fmt?: Format) => get('/v1/org', { name }, fmt)

// ── Routing ──────────────────────────────────────────────────
export const checkRpki         = (prefix: string, asn: string, fmt?: Format) => get('/v1/rpki', { prefix, asn }, fmt)
export const checkBgp          = (resource: string, fmt?: Format) => get(`/v1/bgp/${encodeURIComponent(resource)}`, {}, fmt)
export const announcedPrefixes = (asn: string, fmt?: Format) => get(`/v1/announced/${encodeURIComponent(asn)}`, {}, fmt)
export const prefixOverview    = (prefix: string, fmt?: Format) => get(`/v1/overview/${encodeURIComponent(prefix)}`, {}, fmt)

// ── History ───────────────────────────────────────────────────
export const prefixHistory     = (resource: string, fmt?: Format) => get(`/v1/history/${encodeURIComponent(resource)}`, {}, fmt)
export const detectTransfers   = (resource: string, fmt?: Format) => get(`/v1/transfers/${encodeURIComponent(resource)}`, {}, fmt)
export const ipv4Stats         = (params?: { rir?: string; include_blocks?: boolean; status?: string; country?: string; limit?: number }, fmt?: Format) => get('/v1/stats/ipv4', params ?? {}, fmt)

// ── Peering ───────────────────────────────────────────────────
export const peeringInfo       = (asn: string, fmt?: Format)    => get(`/v1/peering/${encodeURIComponent(asn)}`, {}, fmt)
export const ixpLookup         = (query: string, fmt?: Format)  => get('/v1/ixp', { query }, fmt)
export const networkHealth     = (resource: string, fmt?: Format) => get(`/v1/health/${encodeURIComponent(resource)}`, {}, fmt)
export const changeMonitor     = (resource: string, fmt?: Format) => get(`/v1/monitor/${encodeURIComponent(resource)}`, {}, fmt)

// ── DNS ───────────────────────────────────────────────────────
export const dnsResolve     = (target: string, fmt?: Format)             => get(`/v1/dns/resolve/${encodeURIComponent(target)}`, {}, fmt)
export const dnsEnumerate   = (domain: string, fmt?: Format)             => get(`/v1/dns/enumerate/${encodeURIComponent(domain)}`, {}, fmt)
export const dnsDnssec      = (domain: string, fmt?: Format)             => get(`/v1/dns/dnssec/${encodeURIComponent(domain)}`, {}, fmt)
export const dnsDnsbl       = (ip: string, fmt?: Format)                 => get(`/v1/dns/dnsbl/${encodeURIComponent(ip)}`, {}, fmt)
export const dnsEmail       = (domain: string, fmt?: Format)             => get(`/v1/dns/email/${encodeURIComponent(domain)}`, {}, fmt)
export const dnsPropagation = (domain: string, record_type: string = 'A', fmt?: Format) => get(`/v1/dns/propagation/${encodeURIComponent(domain)}`, { record_type }, fmt)

// ── TLS & Certs ───────────────────────────────────────────────
export const tlsInspect = (hostname: string, port: number = 443, fmt?: Format) => get(`/v1/tls/${encodeURIComponent(hostname)}`, { port }, fmt)
export const ctLogs     = (domain: string, fmt?: Format)                        => get(`/v1/ct/${encodeURIComponent(domain)}`, {}, fmt)

// ── Threat Intel ─────────────────────────────────────────────
export const threatIntel = (ip: string, fmt?: Format)      => get(`/v1/threat/${encodeURIComponent(ip)}`, {}, fmt)
export const passiveDns  = (resource: string, fmt?: Format) => get(`/v1/pdns/${encodeURIComponent(resource)}`, {}, fmt)

// ── BGP Depth ────────────────────────────────────────────────
export const checkIrr         = (prefix: string, asn: string, fmt?: Format) => get('/v1/irr', { prefix, asn }, fmt)
export const detectRouteLeak  = (prefix: string, fmt?: Format)               => get(`/v1/route-leak/${encodeURIComponent(prefix)}`, {}, fmt)
export const lookingGlass     = (prefix: string, vantage_points: number = 5, fmt?: Format) => get(`/v1/looking-glass/${encodeURIComponent(prefix)}`, { vantage_points }, fmt)
export const routeStability   = (prefix: string, hours: number = 24, fmt?: Format)         => get(`/v1/stability/${encodeURIComponent(prefix)}`, { hours }, fmt)

// ── Crisis / Humanitarian ────────────────────────────────────
export const shutdownDetect   = (country_code: string, fmt?: Format)                              => get(`/v1/shutdown/${country_code.toUpperCase()}`, {}, fmt)
export const shutdownTimeline = (resource: string, start_date: string, end_date: string, fmt?: Format) => get(`/v1/shutdown/timeline/${encodeURIComponent(resource)}`, { start_date, end_date }, fmt)
export const dnsCensorship    = (domain: string, country_code?: string, fmt?: Format)              => get(`/v1/censorship/${encodeURIComponent(domain)}`, country_code ? { country_code } : {}, fmt)
export const satelliteConn    = (country_code: string, fmt?: Format)                              => get(`/v1/satellite/${country_code.toUpperCase()}`, {}, fmt)
export const chokepoints      = (country_code: string, fmt?: Format)                              => get(`/v1/chokepoints/${country_code.toUpperCase()}`, {}, fmt)
export const ooniReport       = (country_code: string, domain?: string, fmt?: Format)             => get(`/v1/ooni/${country_code.toUpperCase()}`, domain ? { domain } : {}, fmt)
export const countryHealth    = (country_code: string, fmt?: Format)                              => get(`/v1/health/country/${country_code.toUpperCase()}`, {}, fmt)

// ── Advanced ─────────────────────────────────────────────────
export const asRelationships  = (asn: string, fmt?: Format)                      => get(`/v1/as-relationships/${encodeURIComponent(asn)}`, {}, fmt)
export const geoLookup        = (ip: string, fmt?: Format)                       => get(`/v1/geo/${encodeURIComponent(ip)}`, {}, fmt)
export const atlasTrace       = (target: string, probes: number = 5, fmt?: Format) => get(`/v1/atlas/${encodeURIComponent(target)}`, { probes }, fmt)

// ── Bulk ─────────────────────────────────────────────────────
export const bulkQuery = (resources: string[], query_type: string = 'auto', fmt?: Format) =>
  post('/v1/bulk', { resources, query_type }, fmt)

// ── Meta ─────────────────────────────────────────────────────
export const metaCache  = () => get('/v1/meta/cache', {}, 'json')
export const metaStatus = () => get('/v1/meta/status', {}, 'json')
export const openaiTools = () => get('/v1/meta/openai-tools', {}, 'json')
