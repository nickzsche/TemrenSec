'use client'
import { authHeader } from '@/lib/api'

import { useEffect, useState } from 'react'

type FrameworkStatus = {
  framework: string
  controls_hit: number
  unique_controls: string[]
  findings: number
  critical_count: number
  high_count: number
}

const DEMO: FrameworkStatus[] = [
  { framework: 'PCI-DSS-4.0', controls_hit: 6, unique_controls: ['2.2', '3.5', '4.2', '6.2.4', '7.2', '10.2'], findings: 14, critical_count: 2, high_count: 5 },
  { framework: 'HIPAA', controls_hit: 3, unique_controls: ['164.308(a)(4)', '164.312(a)(2)(iv)', '164.312(b)'], findings: 9, critical_count: 1, high_count: 4 },
  { framework: 'GDPR', controls_hit: 2, unique_controls: ['Art.32', 'Art.32(1)(a)'], findings: 8, critical_count: 1, high_count: 3 },
  { framework: 'ISO-27001:2022', controls_hit: 7, unique_controls: ['A.5.15', 'A.5.17', 'A.8.8', 'A.8.9', 'A.8.15', 'A.8.24', 'A.8.28'], findings: 17, critical_count: 3, high_count: 6 },
  { framework: 'SOC-2', controls_hit: 4, unique_controls: ['CC6.1', 'CC7.1', 'CC7.2', 'CC8.1'], findings: 12, critical_count: 2, high_count: 5 },
  { framework: 'NIST-CSF-2.0', controls_hit: 5, unique_controls: ['DE.CM', 'ID.RA-1', 'PR.AC', 'PR.DS-1', 'PR.IP-1'], findings: 13, critical_count: 2, high_count: 4 },
  { framework: 'CIS-Controls-v8', controls_hit: 4, unique_controls: ['4', '6', '7', '16'], findings: 11, critical_count: 2, high_count: 4 },
  { framework: 'OWASP-ASVS-5.0', controls_hit: 6, unique_controls: ['V2', 'V4', 'V5', 'V6', 'V7', 'V10'], findings: 16, critical_count: 3, high_count: 6 },
]

export default function CompliancePage() {
  const [rows, setRows] = useState<FrameworkStatus[]>(DEMO)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const url = process.env.NEXT_PUBLIC_API_URL || '/api/v1'
    setLoading(true)
    fetch(`${url}/compliance/summary`, { headers: authHeader() })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && Array.isArray(d) && setRows(d))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold">Compliance Posture</h1>
        <p className="text-sm text-zinc-500">Mapping of latest scan findings to regulatory frameworks.</p>
      </header>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {rows.map((r) => (
          <div key={r.framework} className="rounded-lg border border-zinc-200 bg-white p-4 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
            <div className="flex items-baseline justify-between">
              <h2 className="font-semibold">{r.framework}</h2>
              <span className="text-xs text-zinc-500">{r.controls_hit} controls</span>
            </div>
            <div className="mt-3 text-3xl font-bold">{r.findings}</div>
            <div className="text-xs text-zinc-500">findings</div>
            <div className="mt-3 flex gap-2 text-xs">
              <span className="rounded bg-red-100 px-2 py-0.5 text-red-700 dark:bg-red-950 dark:text-red-300">{r.critical_count} critical</span>
              <span className="rounded bg-orange-100 px-2 py-0.5 text-orange-700 dark:bg-orange-950 dark:text-orange-300">{r.high_count} high</span>
            </div>
            <details className="mt-3 text-xs text-zinc-600 dark:text-zinc-400">
              <summary className="cursor-pointer">Affected controls</summary>
              <ul className="mt-2 space-y-1">
                {r.unique_controls.map((c) => (
                  <li key={c} className="font-mono">• {c}</li>
                ))}
              </ul>
            </details>
          </div>
        ))}
      </div>
      {loading && <p className="text-sm text-zinc-500">Loading…</p>}
    </div>
  )
}
