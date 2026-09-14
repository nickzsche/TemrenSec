'use client'

type Node = { id: string; label: string; severity: string; x: number; y: number }
type Edge = { from: string; to: string }

const nodes: Node[] = [
  { id: 'entry', label: 'Public Login', severity: 'INFO', x: 50, y: 100 },
  { id: 'xss', label: 'Reflected XSS', severity: 'HIGH', x: 220, y: 60 },
  { id: 'cookie', label: 'Missing HttpOnly', severity: 'MEDIUM', x: 220, y: 160 },
  { id: 'session', label: 'Session Hijack', severity: 'HIGH', x: 400, y: 100 },
  { id: 'idor', label: 'IDOR /api/users/:id', severity: 'HIGH', x: 580, y: 60 },
  { id: 'pii', label: 'PII Exfil', severity: 'CRITICAL', x: 760, y: 100 },
]

const edges: Edge[] = [
  { from: 'entry', to: 'xss' },
  { from: 'entry', to: 'cookie' },
  { from: 'xss', to: 'session' },
  { from: 'cookie', to: 'session' },
  { from: 'session', to: 'idor' },
  { from: 'idor', to: 'pii' },
]

const color: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#2563eb',
  INFO: '#52525b',
}

export default function AttackPathsPage() {
  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold">Attack Paths</h1>
        <p className="text-sm text-zinc-500">AI-derived chains that compose multiple findings into a single exploit.</p>
      </header>
      <div className="rounded-lg border bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900">
        <svg viewBox="0 0 900 220" className="w-full">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />
            </marker>
          </defs>
          {edges.map((e, i) => {
            const a = nodes.find((n) => n.id === e.from)!
            const b = nodes.find((n) => n.id === e.to)!
            return <line key={i} x1={a.x + 60} y1={a.y} x2={b.x} y2={b.y} stroke="#94a3b8" strokeWidth={2} markerEnd="url(#arrow)" />
          })}
          {nodes.map((n) => (
            <g key={n.id} transform={`translate(${n.x},${n.y})`}>
              <rect x={-60} y={-20} width={120} height={40} rx={6} fill={color[n.severity]} opacity={0.85} />
              <text textAnchor="middle" dominantBaseline="middle" fontSize={11} fill="white" fontWeight={600}>{n.label}</text>
            </g>
          ))}
        </svg>
        <div className="mt-4 rounded-md bg-zinc-50 p-3 text-sm dark:bg-zinc-950">
          <p className="font-semibold">Chain: Account Takeover</p>
          <ol className="ml-5 list-decimal text-zinc-600 dark:text-zinc-400">
            <li>Reflected XSS lands in victim's browser via crafted URL.</li>
            <li>Cookie lacks HttpOnly — XSS reads it.</li>
            <li>Attacker replays the session against authenticated API.</li>
            <li>IDOR enumerates other users' records.</li>
            <li>PII is exfiltrated, breaching GDPR Article 32 and PCI-DSS 3.5.</li>
          </ol>
        </div>
      </div>
    </div>
  )
}
