import { useState, useCallback } from 'react'
import * as api from '../api/client'

export type QueryState = {
  loading: boolean
  warmingUp: boolean
  result: string | null
  error: string | null
}

export type ResourceType = 'ip' | 'asn' | 'prefix' | 'domain' | 'country' | 'hostname' | 'unknown'

export function detectType(input: string): ResourceType {
  const s = input.trim()
  if (/^(AS)?\d+$/i.test(s)) return 'asn'
  if (/^[0-9a-f:]+\/\d+$/i.test(s)) return 'prefix'  // IPv6 CIDR
  if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(s)) return 'prefix'
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) return 'ip'
  if (/^[0-9a-f:]+$/i.test(s) && s.includes(':')) return 'ip'  // IPv6
  if (/^[A-Z]{2}$/i.test(s)) return 'country'
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+$/i.test(s)) return 'domain'
  return 'unknown'
}

export function usePeerGlass() {
  const [state, setState] = useState<QueryState>({ loading: false, warmingUp: false, result: null, error: null })

  const query = useCallback(async (input: string, tool: string) => {
    setState({ loading: true, warmingUp: false, result: null, error: null })
    api.setRetryCallback(() => {
      setState(prev => ({ ...prev, warmingUp: true }))
    })
    try {
      const s = input.trim()
      let result: string

      switch (tool) {
        // Registry
        case 'ip':           result = detectType(s) === 'prefix' ? await api.checkBgp(s) : await api.queryIp(s); break
        case 'asn':          result = await api.queryAsn(s); break
        case 'abuse':        result = await api.queryAbuse(s); break
        case 'org':          result = await api.queryOrg(s); break
        // Routing
        case 'bgp':          result = await api.checkBgp(s); break
        case 'announced':    result = await api.announcedPrefixes(s); break
        case 'overview':     result = await api.prefixOverview(s); break
        case 'irr':          {
          const [prefix, asn] = s.split(/\s+/)
          result = await api.checkIrr(prefix, asn || '')
          break
        }
        case 'route-leak':   result = await api.detectRouteLeak(s); break
        case 'looking-glass': result = await api.lookingGlass(s); break
        case 'stability':    result = await api.routeStability(s); break
        // RPKI
        case 'rpki':         {
          const [prefix, asn] = s.split(/\s+/)
          result = await api.checkRpki(prefix, asn || '')
          break
        }
        // History
        case 'history':      result = await api.prefixHistory(s); break
        case 'transfers':    result = await api.detectTransfers(s); break
        case 'ipv4stats':    result = await api.ipv4Stats(); break
        // Peering
        case 'peering':      result = await api.peeringInfo(s); break
        case 'ixp':          result = await api.ixpLookup(s); break
        case 'health':       result = await api.networkHealth(s); break
        case 'monitor':      result = await api.changeMonitor(s); break
        // DNS
        case 'dns':          result = await api.dnsResolve(s); break
        case 'dns-enumerate': result = await api.dnsEnumerate(s); break
        case 'dnssec':       result = await api.dnsDnssec(s); break
        case 'dnsbl':        result = await api.dnsDnsbl(s); break
        case 'email':        result = await api.dnsEmail(s); break
        case 'propagation':  result = await api.dnsPropagation(s); break
        case 'censorship':   result = await api.dnsCensorship(s); break
        // TLS
        case 'tls':          result = await api.tlsInspect(s); break
        case 'ct':           result = await api.ctLogs(s); break
        // Threat
        case 'threat':       result = await api.threatIntel(s); break
        case 'pdns':         result = await api.passiveDns(s); break
        case 'geo':          result = await api.geoLookup(s); break
        // Crisis
        case 'shutdown':     result = await api.shutdownDetect(s); break
        case 'satellite':    result = await api.satelliteConn(s); break
        case 'chokepoints':  result = await api.chokepoints(s); break
        case 'ooni':         result = await api.ooniReport(s); break
        case 'country-health': result = await api.countryHealth(s); break
        // Advanced
        case 'as-relationships': result = await api.asRelationships(s); break
        case 'atlas':        result = await api.atlasTrace(s); break
        // Auto-detect
        default: {
          const type = detectType(s)
          if (type === 'ip') result = await api.queryIp(s)
          else if (type === 'asn') result = await api.queryAsn(s)
          else if (type === 'prefix') result = await api.checkBgp(s)
          else if (type === 'domain') result = await api.dnsResolve(s)
          else if (type === 'country') result = await api.countryHealth(s)
          else result = await api.queryIp(s)
        }
      }

      setState({ loading: false, warmingUp: false, result, error: null })
    } catch (err) {
      console.error('[PeerGlass] query failed:', err)
      const msg = String(err)
      const isNetworkError = msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('fetch')
      setState({
        loading: false,
        warmingUp: false,
        result: null,
        error: isNetworkError
          ? `Backend unreachable (${msg}) — check browser Console/Network tab for details. The API may be restarting.`
          : msg,
      })
    } finally {
      api.setRetryCallback(null)
    }
  }, [])

  const clear = useCallback(() => {
    setState({ loading: false, warmingUp: false, result: null, error: null })
  }, [])

  return { ...state, query, clear }
}
