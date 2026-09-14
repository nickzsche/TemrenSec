'use client'
import { authHeader } from '@/lib/api'

import { useEffect, useState } from 'react'

type Component = { name: string; version: string; ecosystem: string; vulns: number; lockfile: string }

const DEMO: Component[] = [
  { name: 'lodash', version: '4.17.20', ecosystem: 'npm', vulns: 2, lockfile: 'package-lock.json' },
  { name: 'express', version: '4.17.1', ecosystem: 'npm', vulns: 1, lockfile: 'package-lock.json' },
  { name: 'requests', version: '2.25.1', ecosystem: 'PyPI', vulns: 0, lockfile: 'requirements.txt' },
  { name: 'github.com/gin-gonic/gin', version: 'v1.7.0', ecosystem: 'Go', vulns: 1, lockfile: 'go.sum' },
  { name: 'rails', version: '6.1.3', ecosystem: 'RubyGems', vulns: 3, lockfile: 'Gemfile.lock' },
]

export default function SBOMPage() {
  const [components, setComponents] = useState<Component[]>(DEMO)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    const url = process.env.NEXT_PUBLIC_API_URL || '/api/v1'
    fetch(`${url}/sbom`, { headers: authHeader() }).then(r => r.ok ? r.json() : null).then(d => d && setComponents(d)).catch(() => {})
  }, [])

  const filtered = components.filter(c =>
    !filter ||
    c.name.toLowerCase().includes(filter.toLowerCase()) ||
    c.ecosystem.toLowerCase().includes(filter.toLowerCase()),
  )

  return (
    <div className="space-y-6 p-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Software Bill of Materials</h1>
          <p className="text-sm text-zinc-500">CycloneDX 1.5 inventory across every lockfile in the project.</p>
        </div>
        <input
          placeholder="filter…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="rounded-md border px-3 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-900"
        />
      </header>

      <div className="grid gap-4 md:grid-cols-4">
        <Stat label="Components" value={components.length} />
        <Stat label="Ecosystems" value={new Set(components.map(c => c.ecosystem)).size} />
        <Stat label="Vulnerable" value={components.filter(c => c.vulns > 0).length} accent="text-red-600" />
        <Stat label="Lockfiles" value={new Set(components.map(c => c.lockfile)).size} />
      </div>

      <div className="overflow-x-auto rounded-lg border dark:border-zinc-800">
        <table className="min-w-full divide-y divide-zinc-200 text-sm dark:divide-zinc-800">
          <thead className="bg-zinc-50 text-left dark:bg-zinc-900">
            <tr>
              <th className="px-4 py-3">Component</th>
              <th className="px-4 py-3">Version</th>
              <th className="px-4 py-3">Ecosystem</th>
              <th className="px-4 py-3">Vulns</th>
              <th className="px-4 py-3">Lockfile</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
            {filtered.map((c, i) => (
              <tr key={i} className="hover:bg-zinc-50 dark:hover:bg-zinc-900">
                <td className="px-4 py-3 font-mono">{c.name}</td>
                <td className="px-4 py-3 font-mono">{c.version}</td>
                <td className="px-4 py-3"><span className="rounded bg-zinc-100 px-2 py-0.5 text-xs dark:bg-zinc-800">{c.ecosystem}</span></td>
                <td className="px-4 py-3">
                  {c.vulns > 0 ? (
                    <span className="rounded bg-red-100 px-2 py-0.5 text-xs text-red-700 dark:bg-red-950 dark:text-red-300">{c.vulns} CVE</span>
                  ) : (
                    <span className="text-zinc-400">—</span>
                  )}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-500">{c.lockfile}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Stat({ label, value, accent }: { label: string; value: number | string; accent?: string }) {
  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
      <div className="text-xs uppercase text-zinc-500">{label}</div>
      <div className={`mt-2 text-3xl font-bold ${accent ?? ''}`}>{value}</div>
    </div>
  )
}
