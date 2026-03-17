import ReactMarkdown from 'react-markdown'

interface ResultPanelProps {
  result: string | null
  error: string | null
  loading: boolean
}

export default function ResultPanel({ result, error, loading }: ResultPanelProps) {
  if (loading) {
    return (
      <div className="terminal-card p-6 flex items-center gap-3 text-terminal-muted">
        <span className="animate-spin">⏳</span>
        <span className="font-mono text-sm">Querying internet resources...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="terminal-card p-4 border-terminal-red">
        <p className="text-terminal-red font-mono text-sm">
          <span className="text-terminal-muted">error: </span>{error}
        </p>
      </div>
    )
  }

  if (!result) {
    return (
      <div className="terminal-card p-8 flex flex-col items-center justify-center text-center text-terminal-muted min-h-48">
        <div className="text-4xl mb-3">🔍</div>
        <p className="font-mono text-sm">Enter an IP address, ASN, prefix, domain, or country code above.</p>
        <p className="font-mono text-xs mt-1 text-terminal-muted/60">
          Auto-detects type · 42 tools · 41 endpoints
        </p>
      </div>
    )
  }

  return (
    <div className="terminal-card p-5 overflow-auto max-h-[70vh]">
      <div className="prose-terminal">
        <ReactMarkdown>{result}</ReactMarkdown>
      </div>
    </div>
  )
}
