import { useState, type FormEvent } from 'react'
import { detectType } from '../hooks/usePeerGlass'

interface SearchBarProps {
  onSearch: (input: string) => void
  loading?: boolean
  placeholder?: string
}

const EXAMPLES = [
  '1.1.1.1', 'AS13335', '1.1.1.0/24',
  'cloudflare.com', 'UA', 'google.com',
]

export default function SearchBar({ onSearch, loading, placeholder }: SearchBarProps) {
  const [value, setValue] = useState('')

  const handle = (e: FormEvent) => {
    e.preventDefault()
    if (value.trim()) onSearch(value.trim())
  }

  const type = value.trim() ? detectType(value.trim()) : null

  const typeColor: Record<string, string> = {
    ip:       'text-terminal-green',
    asn:      'text-terminal-cyan',
    prefix:   'text-terminal-yellow',
    domain:   'text-purple-400',
    country:  'text-orange-400',
    hostname: 'text-terminal-text',
    unknown:  'text-terminal-muted',
  }

  return (
    <form onSubmit={handle} className="w-full">
      <div className="relative flex items-center gap-2">
        <div className="relative flex-1">
          <span className="absolute left-4 top-1/2 -translate-y-1/2 text-terminal-cyan font-mono text-sm select-none">$</span>
          <input
            type="text"
            value={value}
            onChange={e => setValue(e.target.value)}
            placeholder={placeholder ?? 'IP · ASN · Prefix · Domain · Country code...'}
            className="terminal-input w-full pl-8 pr-32 text-sm"
            disabled={loading}
            autoFocus
            spellCheck={false}
          />
          {type && value.trim() && (
            <span className={`absolute right-3 top-1/2 -translate-y-1/2 text-xs uppercase tracking-widest ${typeColor[type]}`}>
              {type}
            </span>
          )}
        </div>
        <button
          type="submit"
          disabled={!value.trim() || loading}
          className="px-5 py-3 bg-terminal-cyan text-terminal-bg font-mono text-sm rounded-lg
                     hover:bg-terminal-green transition-colors disabled:opacity-40 disabled:cursor-not-allowed
                     whitespace-nowrap"
        >
          {loading ? '⏳' : 'Query →'}
        </button>
      </div>
      <div className="mt-2 flex flex-wrap gap-2">
        {EXAMPLES.map(ex => (
          <button
            key={ex}
            type="button"
            onClick={() => { setValue(ex); onSearch(ex) }}
            className="text-xs text-terminal-muted hover:text-terminal-cyan font-mono border border-terminal-border/50 rounded px-2 py-0.5 transition-colors"
          >
            {ex}
          </button>
        ))}
      </div>
    </form>
  )
}
