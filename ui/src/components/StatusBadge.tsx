interface StatusBadgeProps {
  status: 'valid' | 'invalid' | 'not-found' | 'warning' | 'normal' | 'degraded' | 'partial' | 'full' | 'unknown'
  label?: string
}

const CONFIG: Record<string, { icon: string; color: string }> = {
  valid:    { icon: '✅', color: 'text-terminal-green border-terminal-green/40 bg-terminal-green/10' },
  invalid:  { icon: '❌', color: 'text-terminal-red border-terminal-red/40 bg-terminal-red/10' },
  'not-found': { icon: '⚪', color: 'text-terminal-muted border-terminal-muted/40 bg-terminal-muted/10' },
  warning:  { icon: '⚠️', color: 'text-terminal-yellow border-terminal-yellow/40 bg-terminal-yellow/10' },
  normal:   { icon: '🟢', color: 'text-terminal-green border-terminal-green/40 bg-terminal-green/10' },
  degraded: { icon: '🟡', color: 'text-terminal-yellow border-terminal-yellow/40 bg-terminal-yellow/10' },
  partial:  { icon: '🟠', color: 'text-orange-400 border-orange-400/40 bg-orange-400/10' },
  full:     { icon: '🔴', color: 'text-terminal-red border-terminal-red/40 bg-terminal-red/10' },
  unknown:  { icon: '❓', color: 'text-terminal-muted border-terminal-border bg-terminal-surface' },
}

export default function StatusBadge({ status, label }: StatusBadgeProps) {
  const cfg = CONFIG[status] ?? CONFIG.unknown
  return (
    <span className={`status-badge border ${cfg.color}`}>
      <span>{cfg.icon}</span>
      <span>{label ?? status}</span>
    </span>
  )
}
