'use client'
import { authHeader } from '@/lib/api'

import { useState } from 'react'

type CVEInfo = {
  id: string
  description: string
  cvss_v3: number
  epss: number
  epss_percentile: number
  kev: boolean
  priority: number
}

export default function ThreatIntelPage() {
  const [query, setQuery] = useState('CVE-2021-44228')
  const [results, setResults] = useState<CVEInfo[]>([])
  const [loading, setLoading] = useState(false)

  async function lookup() {
    setLoading(true)
    try {
      const url = process.env.NEXT_PUBLIC_API_URL || '/api/v1'
      const ids = query.split(/[\s,]+/).filter(Boolean)
      const resp = await fetch(`${url}/intel/lookup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeader() },
        body: JSON.stringify({ ids }),
      })
      if (resp.ok) setResults(await resp.json())
      else setResults([])
    } catch {
      setResults([])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold">Threat Intelligence</h1>
        <p className="text-sm text-zinc-500">Enrich CVEs with NVD CVSS, EPSS exploit probability, and CISA Known-Exploited flags.</p>
      </header>

      <div className="flex gap-2">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="CVE-2024-3094, CVE-2023-44487"
          className="flex-1 rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-900"
        />
        <button
          onClick={lookup}
          disabled={loading}
          className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? 'Looking up…' : 'Lookup'}
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full border-collapse text-sm">
          <thead>
            <tr className="border-b text-left text-zinc-500">
              <th className="py-2 pr-4">CVE</th>
              <th className="py-2 pr-4">CVSS</th>
              <th className="py-2 pr-4">EPSS</th>
              <th className="py-2 pr-4">KEV</th>
              <th className="py-2 pr-4">Priority</th>
              <th className="py-2">Description</th>
            </tr>
          </thead>
          <tbody>
            {results.map((r) => (
              <tr key={r.id} className="border-b align-top dark:border-zinc-800">
                <td className="py-3 pr-4 font-mono">{r.id}</td>
                <td className="py-3 pr-4">{r.cvss_v3?.toFixed(1) ?? '—'}</td>
                <td className="py-3 pr-4">{(r.epss * 100).toFixed(1)}%</td>
                <td className="py-3 pr-4">
                  {r.kev ? (
                    <span className="rounded bg-red-100 px-2 py-0.5 text-xs font-semibold text-red-700 dark:bg-red-950 dark:text-red-300">KEV</span>
                  ) : (
                    <span className="text-zinc-400">—</span>
                  )}
                </td>
                <td className="py-3 pr-4">
                  <span className={`rounded px-2 py-0.5 text-xs font-semibold ${
                    r.priority >= 9
                      ? 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300'
                      : r.priority >= 7
                      ? 'bg-orange-100 text-orange-700 dark:bg-orange-950 dark:text-orange-300'
                      : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300'
                  }`}>{r.priority.toFixed(1)}</span>
                </td>
                <td className="py-3 text-zinc-600 dark:text-zinc-400">{r.description}</td>
              </tr>
            ))}
            {results.length === 0 && !loading && (
              <tr><td colSpan={6} className="py-6 text-center text-zinc-400">No results yet. Enter CVE IDs and press Lookup.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
