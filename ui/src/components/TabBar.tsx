export type Tab = {
  id: string
  label: string
  tools: Array<{
    id: string
    label: string
    placeholder: string
    hint?: string
  }>
}

export const TABS: Tab[] = [
  {
    id: 'auto',
    label: '✨ Auto',
    tools: [
      { id: 'auto', label: 'Auto-detect', placeholder: 'IP · ASN · prefix/CIDR · domain · country code' },
    ],
  },
  {
    id: 'registry',
    label: '📋 Registry',
    tools: [
      { id: 'ip',    label: 'IP Lookup',      placeholder: '1.1.1.1 or 2001:db8::1' },
      { id: 'asn',   label: 'ASN Lookup',     placeholder: 'AS13335 or 13335' },
      { id: 'abuse', label: 'Abuse Contact',  placeholder: '1.1.1.1' },
      { id: 'org',   label: 'Org Audit',      placeholder: 'Cloudflare Inc.' },
    ],
  },
  {
    id: 'routing',
    label: '🛣️ Routing',
    tools: [
      { id: 'bgp',          label: 'BGP Status',     placeholder: '1.1.1.0/24 or AS13335' },
      { id: 'rpki',         label: 'RPKI Validate',  placeholder: '1.1.1.0/24 AS13335', hint: 'prefix then ASN, space-separated' },
      { id: 'announced',    label: 'Announced Prefixes', placeholder: 'AS13335' },
      { id: 'overview',     label: 'Prefix Overview', placeholder: '1.1.1.0/24' },
      { id: 'irr',          label: 'IRR Validation',  placeholder: '1.1.1.0/24 AS13335', hint: 'prefix then ASN, space-separated' },
      { id: 'route-leak',   label: 'Route Leak',      placeholder: '1.1.1.0/24' },
      { id: 'looking-glass',label: 'Looking Glass',   placeholder: '1.1.1.0/24' },
      { id: 'stability',    label: 'Route Stability',  placeholder: '1.1.1.0/24' },
    ],
  },
  {
    id: 'dns',
    label: '🔤 DNS',
    tools: [
      { id: 'dns',         label: 'DNS Resolve',    placeholder: 'cloudflare.com or 1.1.1.1' },
      { id: 'dns-enumerate',label: 'DNS Enumerate', placeholder: 'cloudflare.com' },
      { id: 'dnssec',      label: 'DNSSEC',         placeholder: 'cloudflare.com' },
      { id: 'dnsbl',       label: 'DNSBL Check',    placeholder: '1.1.1.1' },
      { id: 'email',       label: 'Email Security', placeholder: 'cloudflare.com' },
      { id: 'propagation', label: 'Propagation',    placeholder: 'cloudflare.com' },
      { id: 'censorship',  label: 'DNS Censorship', placeholder: 'twitter.com (+ optional country code)' },
    ],
  },
  {
    id: 'tls',
    label: '🔒 TLS',
    tools: [
      { id: 'tls', label: 'TLS Inspect', placeholder: 'cloudflare.com' },
      { id: 'ct',  label: 'CT Logs',     placeholder: 'cloudflare.com' },
    ],
  },
  {
    id: 'threat',
    label: '🎯 Threat',
    tools: [
      { id: 'threat', label: 'Threat Intel',  placeholder: '198.41.0.4' },
      { id: 'pdns',   label: 'Passive DNS',   placeholder: '1.1.1.1 or cloudflare.com' },
      { id: 'geo',    label: 'GeoIP Lookup',  placeholder: '1.1.1.1' },
    ],
  },
  {
    id: 'crisis',
    label: '🚨 Crisis',
    tools: [
      { id: 'shutdown',      label: 'Shutdown Detect', placeholder: 'SY (ISO country code)' },
      { id: 'country-health',label: 'Country Health',  placeholder: 'UA (ISO country code)' },
      { id: 'satellite',     label: 'Satellite Conn.', placeholder: 'MM (ISO country code)' },
      { id: 'chokepoints',   label: 'Chokepoints',     placeholder: 'BY (ISO country code)' },
      { id: 'ooni',          label: 'OONI Report',     placeholder: 'IR (ISO country code)' },
    ],
  },
  {
    id: 'peering',
    label: '🤝 Peering',
    tools: [
      { id: 'peering',         label: 'Peering Info',      placeholder: 'AS13335' },
      { id: 'ixp',             label: 'IXP Lookup',        placeholder: 'DE-CIX' },
      { id: 'as-relationships',label: 'AS Relationships',  placeholder: 'AS13335' },
      { id: 'atlas',           label: 'Atlas Traceroute',  placeholder: '1.1.1.1' },
      { id: 'health',          label: 'Network Health',    placeholder: '1.1.1.0/24 or AS13335' },
      { id: 'monitor',         label: 'Change Monitor',    placeholder: '1.1.1.0/24' },
    ],
  },
]

interface TabBarProps {
  activeTab: string
  activeTool: string
  onTabChange: (tabId: string, toolId: string) => void
}

export default function TabBar({ activeTab, activeTool, onTabChange }: TabBarProps) {
  const currentTab = TABS.find(t => t.id === activeTab) ?? TABS[0]

  return (
    <div className="space-y-2">
      {/* Tab row */}
      <div className="flex flex-wrap gap-1.5">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id, tab.tools[0].id)}
            className={`tab-button ${activeTab === tab.id ? 'active' : ''}`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tool row */}
      {currentTab.tools.length > 1 && (
        <div className="flex flex-wrap gap-1">
          {currentTab.tools.map(tool => (
            <button
              key={tool.id}
              onClick={() => onTabChange(activeTab, tool.id)}
              className={`text-xs px-2 py-1 rounded font-mono transition-colors cursor-pointer
                ${activeTool === tool.id
                  ? 'text-terminal-green border border-terminal-green/50 bg-terminal-green/10'
                  : 'text-terminal-muted border border-transparent hover:border-terminal-border hover:text-terminal-text'
                }`}
            >
              {tool.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
