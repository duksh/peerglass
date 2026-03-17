import { useState } from 'react'
import { usePeerGlass } from '../hooks/usePeerGlass'
import ResultPanel from './ResultPanel'

const CRISIS_COUNTRIES = [
  { code: 'SY', name: 'Syria' },
  { code: 'MM', name: 'Myanmar' },
  { code: 'BY', name: 'Belarus' },
  { code: 'IR', name: 'Iran' },
  { code: 'RU', name: 'Russia' },
  { code: 'UA', name: 'Ukraine' },
  { code: 'CU', name: 'Cuba' },
  { code: 'VE', name: 'Venezuela' },
]

export default function CountryDashboard() {
  const [selected, setSelected] = useState<string | null>(null)
  const { loading, result, error, query } = usePeerGlass()

  const run = (code: string) => {
    setSelected(code)
    query(code, 'country-health')
  }

  return (
    <div className="space-y-4">
      <div className="terminal-card p-4">
        <h2 className="text-terminal-cyan font-mono text-sm mb-3">🌍 Crisis Country Dashboard</h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {CRISIS_COUNTRIES.map(c => (
            <button
              key={c.code}
              onClick={() => run(c.code)}
              className={`p-3 rounded border font-mono text-sm transition-colors text-left
                ${selected === c.code
                  ? 'border-terminal-cyan text-terminal-cyan bg-terminal-cyan/10'
                  : 'border-terminal-border text-terminal-text hover:border-terminal-cyan/50 hover:text-terminal-cyan'
                }`}
            >
              <div className="text-lg">{c.code}</div>
              <div className="text-xs text-terminal-muted">{c.name}</div>
            </button>
          ))}
        </div>
      </div>
      {(selected || loading) && (
        <ResultPanel result={result} error={error} loading={loading} />
      )}
    </div>
  )
}
