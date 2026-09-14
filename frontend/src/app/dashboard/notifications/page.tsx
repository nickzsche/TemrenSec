'use client'

import { useEffect, useState } from 'react'

type N = { id: string; ts: string; title: string; body: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'; read: boolean }

const DEMO: N[] = [
  { id: '1', ts: '00:51', title: 'New critical finding', body: 'SQL injection on /api/users — fix immediately.', severity: 'CRITICAL', read: false },
  { id: '2', ts: '00:30', title: 'Scheduled scan completed', body: 'weekly-prod: 17 findings (3 new).', severity: 'INFO', read: false },
  { id: '3', ts: 'yesterday', title: 'Integration token rotated', body: 'Jira integration renewed automatically.', severity: 'LOW', read: true },
]

const colors: Record<N['severity'], string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-yellow-500',
  LOW: 'bg-blue-500',
  INFO: 'bg-zinc-400',
}

export default function NotificationsPage() {
  const [items, setItems] = useState<N[]>(DEMO)
  useEffect(() => {
    const url = process.env.NEXT_PUBLIC_API_URL || '/api/v1'
    fetch(`${url}/notifications`).then((r) => (r.ok ? r.json() : null)).then((d) => d && setItems(d)).catch(() => {})
  }, [])

  function markRead(id: string) {
    setItems((m) => m.map((n) => (n.id === id ? { ...n, read: true } : n)))
  }

  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold">Notification Center</h1>
        <p className="text-sm text-zinc-500">In-app feed for every event delivered to configured channels.</p>
      </header>
      <ul className="space-y-2">
        {items.map((n) => (
          <li
            key={n.id}
            onClick={() => markRead(n.id)}
            className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 ${n.read ? 'opacity-60' : ''} dark:border-zinc-800`}
          >
            <span className={`mt-1 h-2 w-2 rounded-full ${colors[n.severity]}`} />
            <div className="flex-1">
              <div className="flex items-baseline justify-between">
                <p className="font-semibold">{n.title}</p>
                <span className="text-xs text-zinc-500">{n.ts}</span>
              </div>
              <p className="text-sm text-zinc-600 dark:text-zinc-400">{n.body}</p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}
