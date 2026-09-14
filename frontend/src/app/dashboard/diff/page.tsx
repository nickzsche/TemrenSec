'use client'

import { useEffect, useState } from 'react'

type Finding = { id: string; title: string; severity: string; url: string }

const BASELINE: Finding[] = [
  { id: 'a', title: 'Missing HSTS', severity: 'MEDIUM', url: 'https://x/' },
  { id: 'b', title: 'X-Frame-Options absent', severity: 'LOW', url: 'https://x/' },
  { id: 'c', title: 'SQL Injection /search', severity: 'CRITICAL', url: 'https://x/search?q=' },
]

const CURRENT: Finding[] = [
  { id: 'a', title: 'Missing HSTS', severity: 'MEDIUM', url: 'https://x/' },
  { id: 'd', title: 'SSRF /webhooks/callback', severity: 'HIGH', url: 'https://x/webhooks/callback' },
  { id: 'e', title: 'Open Redirect /go/{u}', severity: 'MEDIUM', url: 'https://x/go/' },
]

export default function DiffPage() {
  const [baseline, setBaseline] = useState<Finding[]>(BASELINE)
  const [current, setCurrent] = useState<Finding[]>(CURRENT)

  useEffect(() => {
    const url = process.env.NEXT_PUBLIC_API_URL || '/api/v1'
    Promise.all([
      fetch(`${url}/scans/baseline/findings`).then(r => r.ok ? r.json() : null),
      fetch(`${url}/scans/latest/findings`).then(r => r.ok ? r.json() : null),
    ]).then(([b, c]) => {
      if (b) setBaseline(b)
      if (c) setCurrent(c)
    }).catch(() => {})
  }, [])

  const baselineIds = new Set(baseline.map(f => f.id))
  const currentIds = new Set(current.map(f => f.id))
  const added = current.filter(f => !baselineIds.has(f.id))
  const fixed = baseline.filter(f => !currentIds.has(f.id))
  const unchanged = current.filter(f => baselineIds.has(f.id))

  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold">Scan Diff</h1>
        <p className="text-sm text-zinc-500">Comparing baseline ↔ latest scan.</p>
      </header>

      <div className="grid gap-4 md:grid-cols-3">
        <Card title="Added" count={added.length} accent="bg-red-50 dark:bg-red-950">
          {added.map(f => <Row key={f.id} f={f} sign="+" />)}
        </Card>
        <Card title="Fixed" count={fixed.length} accent="bg-green-50 dark:bg-green-950">
          {fixed.map(f => <Row key={f.id} f={f} sign="−" />)}
        </Card>
        <Card title="Unchanged" count={unchanged.length} accent="bg-zinc-50 dark:bg-zinc-900">
          {unchanged.map(f => <Row key={f.id} f={f} sign="=" />)}
        </Card>
      </div>
    </div>
  )
}

function Card({ title, count, children, accent }: { title: string; count: number; children: React.ReactNode; accent: string }) {
  return (
    <section className={`rounded-lg border p-4 dark:border-zinc-800 ${accent}`}>
      <h2 className="text-sm font-semibold">{title} ({count})</h2>
      <ul className="mt-3 space-y-2">{children}</ul>
    </section>
  )
}

const sevColor: Record<string, string> = {
  CRITICAL: 'text-red-600', HIGH: 'text-orange-600', MEDIUM: 'text-yellow-600', LOW: 'text-blue-600', INFO: 'text-zinc-500',
}

function Row({ f, sign }: { f: Finding; sign: string }) {
  return (
    <li className="text-sm">
      <span className="mr-2 font-mono text-zinc-500">{sign}</span>
      <span className={`font-semibold ${sevColor[f.severity] ?? ''}`}>[{f.severity}]</span>{' '}
      {f.title}
      <div className="ml-6 font-mono text-xs text-zinc-500">{f.url}</div>
    </li>
  )
}
