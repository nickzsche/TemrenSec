'use client'

import { useEffect, useState } from 'react'

type Asset = {
  id: string
  name: string
  type: string
  url: string
  tags: string[]
  risk_score: number
  last_scan: string
  vulnerabilities: { critical: number; high: number; medium: number; low: number }
}

const DEMO: Asset[] = [
  { id: 'a1', name: 'Public Landing', type: 'web', url: 'https://example.com', tags: ['prod', 'edge'], risk_score: 24, last_scan: '2 hours ago', vulnerabilities: { critical: 0, high: 1, medium: 3, low: 5 } },
  { id: 'a2', name: 'Customer API', type: 'api', url: 'https://api.example.com', tags: ['prod', 'pii'], risk_score: 71, last_scan: '1 day ago', vulnerabilities: { critical: 1, high: 3, medium: 4, low: 8 } },
  { id: 'a3', name: 'Auth Service', type: 'oidc', url: 'https://auth.example.com', tags: ['prod', 'secrets'], risk_score: 58, last_scan: '3 hours ago', vulnerabilities: { critical: 0, high: 2, medium: 5, low: 6 } },
  { id: 'a4', name: 'Internal Admin', type: 'web', url: 'https://admin.internal', tags: ['internal'], risk_score: 39, last_scan: '6 hours ago', vulnerabilities: { critical: 0, high: 1, medium: 4, low: 7 } },
]

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>(DEMO)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    const url = process.env.NEXT_PUBLIC_API_URL || '/api/v1'
    fetch(`${url}/assets`).then((r) => (r.ok ? r.json() : null)).then((d) => d && setAssets(d)).catch(() => {})
  }, [])

  const filtered = assets.filter((a) =>
    !filter ||
    a.name.toLowerCase().includes(filter.toLowerCase()) ||
    a.tags.some((t) => t.toLowerCase().includes(filter.toLowerCase())),
  )

  return (
    <div className="space-y-6 p-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Asset Inventory</h1>
          <p className="text-sm text-zinc-500">Every scannable surface tracked by Temren.</p>
        </div>
        <input
          placeholder="filter…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="rounded-md border px-3 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-900"
        />
      </header>

      <div className="overflow-x-auto rounded-lg border dark:border-zinc-800">
        <table className="min-w-full divide-y divide-zinc-200 text-sm dark:divide-zinc-800">
          <thead className="bg-zinc-50 text-left dark:bg-zinc-900">
            <tr>
              <th className="px-4 py-3">Asset</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Tags</th>
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3">Findings</th>
              <th className="px-4 py-3">Last Scan</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
            {filtered.map((a) => (
              <tr key={a.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-900">
                <td className="px-4 py-3">
                  <div className="font-semibold">{a.name}</div>
                  <div className="font-mono text-xs text-zinc-500">{a.url}</div>
                </td>
                <td className="px-4 py-3 uppercase text-xs">{a.type}</td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {a.tags.map((t) => (
                      <span key={t} className="rounded bg-zinc-100 px-1.5 py-0.5 text-xs dark:bg-zinc-800">{t}</span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="h-2 w-24 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800">
                      <div
                        className={`h-full ${a.risk_score >= 70 ? 'bg-red-500' : a.risk_score >= 40 ? 'bg-orange-500' : 'bg-green-500'}`}
                        style={{ width: `${a.risk_score}%` }}
                      />
                    </div>
                    <span className="font-mono text-xs">{a.risk_score}</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-1 text-xs">
                    {a.vulnerabilities.critical > 0 && <span className="rounded bg-red-100 px-1.5 py-0.5 text-red-700 dark:bg-red-950 dark:text-red-300">{a.vulnerabilities.critical}C</span>}
                    {a.vulnerabilities.high > 0 && <span className="rounded bg-orange-100 px-1.5 py-0.5 text-orange-700 dark:bg-orange-950 dark:text-orange-300">{a.vulnerabilities.high}H</span>}
                    {a.vulnerabilities.medium > 0 && <span className="rounded bg-yellow-100 px-1.5 py-0.5 text-yellow-700 dark:bg-yellow-950 dark:text-yellow-300">{a.vulnerabilities.medium}M</span>}
                  </div>
                </td>
                <td className="px-4 py-3 text-zinc-500">{a.last_scan}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
