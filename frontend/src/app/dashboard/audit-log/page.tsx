'use client'

import { useEffect, useState } from 'react'

type Entry = {
  ts: string
  actor: string
  action: string
  resource: string
  ip: string
  status: 'ok' | 'fail'
}

const DEMO: Entry[] = [
  { ts: '2026-05-16 00:51', actor: 'sahanhasret', action: 'scan.start', resource: 'https://api.example.com', ip: '10.0.0.4', status: 'ok' },
  { ts: '2026-05-16 00:44', actor: 'sahanhasret', action: 'integration.update', resource: 'jira', ip: '10.0.0.4', status: 'ok' },
  { ts: '2026-05-16 00:30', actor: 'system', action: 'schedule.run', resource: 'weekly-prod', ip: '-', status: 'ok' },
  { ts: '2026-05-16 00:12', actor: 'unknown', action: 'auth.login', resource: '-', ip: '203.0.113.7', status: 'fail' },
]

export default function AuditLogPage() {
  const [rows, setRows] = useState<Entry[]>(DEMO)
  useEffect(() => {
    const url = process.env.NEXT_PUBLIC_API_URL || '/api/v1'
    fetch(`${url}/audit`).then((r) => (r.ok ? r.json() : null)).then((d) => d && setRows(d)).catch(() => {})
  }, [])
  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold">Audit Log</h1>
        <p className="text-sm text-zinc-500">Every authenticated action, retained for 1 year.</p>
      </header>
      <table className="min-w-full text-sm">
        <thead className="text-left text-zinc-500">
          <tr><th className="py-2">When</th><th>Actor</th><th>Action</th><th>Resource</th><th>IP</th><th>Status</th></tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-b dark:border-zinc-800">
              <td className="py-2 font-mono text-xs">{r.ts}</td>
              <td>{r.actor}</td>
              <td className="font-mono text-xs">{r.action}</td>
              <td>{r.resource}</td>
              <td className="font-mono text-xs text-zinc-500">{r.ip}</td>
              <td>
                <span className={`rounded px-2 py-0.5 text-xs ${r.status === 'ok' ? 'bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300'}`}>
                  {r.status}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
