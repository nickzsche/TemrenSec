'use client'

const SCANNERS = ['SQLi', 'XSS', 'SSRF', 'IDOR', 'XXE', 'SSTI', 'Auth', 'Headers', 'JWT', 'CORS', 'Deser', 'GraphQL']
const ENVIRONMENTS = ['Production', 'Staging', 'Dev', 'Internal']

const cellValue = (s: string, e: string) => {
  const seed = (s.length * 7 + e.length * 13 + s.charCodeAt(0)) % 11
  return seed
}

function cellColor(v: number) {
  if (v >= 8) return 'bg-red-600 text-white'
  if (v >= 6) return 'bg-red-400 text-white'
  if (v >= 4) return 'bg-orange-400 text-white'
  if (v >= 2) return 'bg-yellow-300 text-zinc-900'
  if (v >= 1) return 'bg-green-300 text-zinc-900'
  return 'bg-zinc-100 text-zinc-500 dark:bg-zinc-900'
}

export default function RiskHeatmapPage() {
  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold">Risk Heatmap</h1>
        <p className="text-sm text-zinc-500">Where each vulnerability class concentrates across environments.</p>
      </header>

      <div className="overflow-x-auto rounded-lg border bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900">
        <table className="min-w-full text-sm">
          <thead>
            <tr>
              <th className="p-2 text-left text-zinc-500"></th>
              {ENVIRONMENTS.map((e) => (
                <th key={e} className="p-2 text-left text-zinc-500">{e}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {SCANNERS.map((s) => (
              <tr key={s}>
                <td className="p-2 font-semibold">{s}</td>
                {ENVIRONMENTS.map((e) => {
                  const v = cellValue(s, e)
                  return (
                    <td key={e} className="p-2">
                      <div className={`flex h-12 items-center justify-center rounded-md font-mono ${cellColor(v)}`}>{v}</div>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
        <div className="mt-4 flex items-center gap-4 text-xs text-zinc-500">
          <span>Severity:</span>
          <span className="flex items-center gap-1"><span className="h-3 w-3 rounded bg-green-300"></span> Low</span>
          <span className="flex items-center gap-1"><span className="h-3 w-3 rounded bg-yellow-300"></span> Medium</span>
          <span className="flex items-center gap-1"><span className="h-3 w-3 rounded bg-orange-400"></span> High</span>
          <span className="flex items-center gap-1"><span className="h-3 w-3 rounded bg-red-600"></span> Critical</span>
        </div>
      </div>
    </div>
  )
}
