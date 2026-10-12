import { useState, useEffect, useRef } from 'react'
import ThreatGlobe from './components/ThreatGlobe'
import CVEPanel from './components/CVEPanel'

export default function App() {
  const [cves, setCves] = useState({ nodes: [], edges: [] })
  const [selected, setSelected] = useState(null)
  const [status, setStatus] = useState('connecting')
  const wsRef = useRef(null)

  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8000/ws')

    ws.onopen = () => setStatus('connected')

    ws.onmessage = (event) => {
      const payload = JSON.parse(event.data)

      if (payload.status === 'ok') {
        console.log(
          "Kev Matches:",
          payload.data.nodes.filter(c => c.is_kev).length,
          "Out Of",
          payload.data.nodes.length
        )

        setCves(payload.data)
      }
    }

    ws.onclose = () => setStatus('disconnected')
    ws.onerror = () => setStatus('error')

    wsRef.current = ws

    return () => ws.close()
  }, [])

  // Auto-Update The Selected Panel When New Artificial Intelligence Threat Intelligence Arrives
  useEffect(() => {
    if (selected && cves.nodes.length > 0) {
      const updatedNode = cves.nodes.find(n => n.id === selected.id)

      if (
        updatedNode &&
        JSON.stringify(updatedNode) !== JSON.stringify(selected)
      ) {
        setSelected(updatedNode)
      }
    }
  }, [cves, selected])

  return (
    <div className="min-h-screen bg-black text-white flex flex-col">

      {/* Header */}
      <header className="border-b border-neutral-800 px-6 py-3 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-black tracking-tight text-white">
            ThreatMesh <span className="text-emerald-400">3D</span>
          </h1>

          <p className="text-xs text-neutral-500 font-mono uppercase tracking-widest">
            Live Cve Intelligence
          </p>
        </div>

        {/* Export Button + Connection Status */}
        <div className="flex items-center gap-3">

          <button
            onClick={() =>
              window.open(
                'http://127.0.0.1:8000/report/pdf',
                '_blank'
              )
            }
            className="text-xs font-mono text-neutral-400 uppercase px-3 py-1 rounded-full bg-neutral-900 border border-neutral-800 hover:border-emerald-500/50 hover:text-emerald-400 transition-colors"
          >
            Export PDF Report
          </button>

          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-neutral-900 border border-neutral-800">
            <div
              className={`w-2 h-2 rounded-full ${status === 'connected'
                ? 'bg-emerald-500 animate-pulse'
                : status === 'connecting'
                  ? 'bg-yellow-500 animate-pulse'
                  : 'bg-red-500'
                }`}
            />

            <span className="text-xs font-mono text-neutral-400 uppercase">
              {status}
            </span>
          </div>

        </div>
      </header>

      {/* Main */}
      <div className="flex flex-1 overflow-hidden">

        {/* 3D Globe — Fixed Width When Panel Open */}
        <div className={selected ? "flex-1 min-w-0" : "flex-1"}>
          <ThreatGlobe
            cves={cves}
            onSelect={setSelected}
          />
        </div>

        {/* Cve Detail Panel */}
        {selected && (
          <div className="w-96 shrink-0 border-l border-neutral-800 overflow-y-auto">
            <CVEPanel
              cve={selected}
              onClose={() => setSelected(null)}
            />
          </div>
        )}

      </div>

      {/* Footer */}
      <footer className="border-t border-neutral-800 px-6 py-2 flex items-center justify-between">
        <span className="text-xs text-neutral-600 font-mono">
          Source: NVD API + CISA KEV — Rolling Live Updates
        </span>

        <span className="text-xs text-neutral-600 font-mono">
          {cves.nodes.length} Threats Loaded
        </span>
      </footer>

    </div>
  )
}