'use client'

import { useState } from 'react'

type Finding = { id: string; title: string; severity: string; column: 'open' | 'triaging' | 'fixing' | 'done' }

const INIT: Finding[] = [
  { id: '1', title: 'SQL Injection /api/users', severity: 'CRITICAL', column: 'open' },
  { id: '2', title: 'IDOR /api/users/{id}', severity: 'HIGH', column: 'triaging' },
  { id: '3', title: 'Reflected XSS /search', severity: 'HIGH', column: 'fixing' },
  { id: '4', title: 'Missing HSTS', severity: 'MEDIUM', column: 'fixing' },
  { id: '5', title: 'COOP missing', severity: 'LOW', column: 'open' },
  { id: '6', title: 'X-Frame-Options missing', severity: 'LOW', column: 'done' },
]

const COLUMNS: Finding['column'][] = ['open', 'triaging', 'fixing', 'done']
const COLUMN_LABELS = { open: 'Open', triaging: 'Triaging', fixing: 'Fixing', done: 'Done' } as const
const sevTone: Record<string, string> = {
  CRITICAL: 'border-l-red-500',
  HIGH: 'border-l-orange-500',
  MEDIUM: 'border-l-yellow-500',
  LOW: 'border-l-blue-500',
}

export default function KanbanPage() {
  const [items, setItems] = useState<Finding[]>(INIT)

  function move(id: string, dir: 1 | -1) {
    setItems(items.map(it => {
      if (it.id !== id) return it
      const idx = COLUMNS.indexOf(it.column)
      const next = COLUMNS[Math.min(COLUMNS.length - 1, Math.max(0, idx + dir))]
      return { ...it, column: next }
    }))
  }

  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold">Findings Kanban</h1>
        <p className="text-sm text-zinc-500">Drag-free remediation board — click the arrows to advance.</p>
      </header>
      <div className="grid gap-4 md:grid-cols-4">
        {COLUMNS.map(col => (
          <section key={col} className="rounded-lg border bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-950">
            <h2 className="mb-3 text-sm font-semibold uppercase text-zinc-500">{COLUMN_LABELS[col]} ({items.filter(i => i.column === col).length})</h2>
            <ul className="space-y-2">
              {items.filter(i => i.column === col).map(i => (
                <li key={i.id} className={`rounded-md border-l-4 bg-white p-3 text-sm shadow-sm dark:bg-zinc-900 ${sevTone[i.severity] ?? ''}`}>
                  <div className="font-semibold">{i.title}</div>
                  <div className="mt-2 flex justify-between text-xs text-zinc-500">
                    <span>{i.severity}</span>
                    <span className="flex gap-1">
                      <button onClick={() => move(i.id, -1)} className="rounded border px-1 dark:border-zinc-700">←</button>
                      <button onClick={() => move(i.id, 1)} className="rounded border px-1 dark:border-zinc-700">→</button>
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </div>
  )
}
