import { useState } from 'react'
import { usePeerGlass } from './hooks/usePeerGlass'
import SearchBar from './components/SearchBar'
import ResultPanel from './components/ResultPanel'
import TabBar, { TABS } from './components/TabBar'
import CountryDashboard from './components/CountryDashboard'

export default function App() {
  const [activeTab, setActiveTab] = useState('auto')
  const [activeTool, setActiveTool] = useState('auto')
  const { loading, result, error, query, clear } = usePeerGlass()

  const currentTab = TABS.find(t => t.id === activeTab) ?? TABS[0]
  const currentTool = currentTab.tools.find(t => t.id === activeTool) ?? currentTab.tools[0]

  const handleTabChange = (tabId: string, toolId: string) => {
    setActiveTab(tabId)
    setActiveTool(toolId)
    clear()
  }

  const handleSearch = (input: string) => {
    query(input, activeTool)
  }

  return (
    <div className="min-h-screen bg-terminal-bg flex flex-col">
      {/* Header */}
      <header className="border-b border-terminal-border bg-terminal-surface sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-terminal-cyan font-mono font-bold text-lg tracking-tight">PeerGlass</span>
            <span className="text-terminal-muted font-mono text-xs border border-terminal-border rounded px-2 py-0.5">
              v1.0 · 42 tools
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs text-terminal-muted font-mono">
            <span className="hidden sm:inline">RIR · BGP · RPKI · DNS · TLS · Crisis</span>
            <a
              href="/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="text-terminal-cyan hover:underline"
            >
              API docs →
            </a>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1 max-w-5xl mx-auto w-full px-4 py-6 space-y-4">
        {/* Tab navigation */}
        <TabBar activeTab={activeTab} activeTool={activeTool} onTabChange={handleTabChange} />

        {/* Crisis country dashboard shortcut */}
        {activeTab === 'crisis' && activeTool === 'country-health' ? (
          <CountryDashboard />
        ) : (
          <>
            {/* Search bar */}
            <div className="terminal-card p-4">
              <div className="text-xs text-terminal-muted font-mono mb-2">
                {currentTool.hint ? (
                  <span>💡 {currentTool.hint}</span>
                ) : (
                  <span className="text-terminal-cyan">{currentTool.label}</span>
                )}
              </div>
              <SearchBar
                onSearch={handleSearch}
                loading={loading}
                placeholder={currentTool.placeholder}
              />
            </div>

            {/* Result */}
            <ResultPanel result={result} error={error} loading={loading} />
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-terminal-border bg-terminal-surface mt-auto">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between text-xs text-terminal-muted font-mono">
          <span>PeerGlass · Internet resource intelligence</span>
          <div className="flex gap-4">
            <a href="/docs" target="_blank" rel="noopener" className="hover:text-terminal-cyan">Swagger</a>
            <a href="/redoc" target="_blank" rel="noopener" className="hover:text-terminal-cyan">ReDoc</a>
            <a href="https://github.com/duksh/peerglass" target="_blank" rel="noopener" className="hover:text-terminal-cyan">GitHub</a>
          </div>
        </div>
      </footer>
    </div>
  )
}
