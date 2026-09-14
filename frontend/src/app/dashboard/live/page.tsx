'use client'

import { useEffect, useRef, useState } from 'react'

type LogLine = { ts: string; level: 'info' | 'warn' | 'finding'; text: string; severity?: string }

const SCRIPT: LogLine[] = [
  { ts: '00:00.04', level: 'info', text: 'temren 1.0.0 — starting scan against https://api.example.com' },
  { ts: '00:00.11', level: 'info', text: 'spider: 12 URLs queued (depth=2)' },
  { ts: '00:00.34', level: 'info', text: 'sqli: probing /api/users?id=' },
  { ts: '00:00.51', level: 'finding', severity: 'CRITICAL', text: 'SQL Injection on /api/users (param=id)' },
  { ts: '00:00.66', level: 'info', text: 'xss: probing 8 reflected sinks' },
  { ts: '00:00.79', level: 'finding', severity: 'HIGH', text: 'Reflected XSS on /search?q=' },
  { ts: '00:01.10', level: 'info', text: 'headers: GET /' },
  { ts: '00:01.12', level: 'finding', severity: 'MEDIUM', text: 'Missing HSTS' },
  { ts: '00:01.13', level: 'finding', severity: 'LOW', text: 'Permissions-Policy missing' },
  { ts: '00:01.42', level: 'info', text: 'oauth: discovering /.well-known/openid-configuration' },
  { ts: '00:01.55', level: 'finding', severity: 'MEDIUM', text: 'PKCE not advertised' },
  { ts: '00:02.07', level: 'info', text: 'dependency scan: 1 240 components, 6 OSV hits' },
  { ts: '00:02.12', level: 'finding', severity: 'HIGH', text: 'GHSA-xxxx — lodash 4.17.20' },
  { ts: '00:02.45', level: 'info', text: 'scan complete (17 findings · 3 CRITICAL · 5 HIGH)' },
]

const sevColor: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH:     'text-orange-400',
  MEDIUM:   'text-yellow-400',
  LOW:      'text-blue-400',
}

export default function LivePage() {
  const [lines, setLines] = useState<LogLine[]>([])
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let i = 0
    const id = setInterval(() => {
      if (i >= SCRIPT.length) {
        clearInterval(id)
        return
      }
      setLines(l => [...l, SCRIPT[i++]])
      ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: 'smooth' })
    }, 600)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="flex h-[calc(100vh-4rem)] flex-col p-6">
      <header className="mb-4">
        <h1 className="text-2xl font-bold">Live Scan Stream</h1>
        <p className="text-sm text-zinc-500">Real-time WebSocket feed of scanner activity.</p>
      </header>
      <div ref={ref} className="flex-1 overflow-y-auto rounded-lg bg-zinc-950 p-4 font-mono text-xs text-zinc-200">
        {lines.map((l, i) => (
          <div key={i} className="leading-relaxed">
            <span className="text-zinc-500">{l.ts}</span>{' '}
            {l.level === 'finding' ? (
              <span className={sevColor[l.severity ?? 'INFO'] ?? 'text-zinc-200'}>★ [{l.severity}]</span>
            ) : l.level === 'warn' ? (
              <span className="text-yellow-300">⚠</span>
            ) : (
              <span className="text-zinc-500">·</span>
            )}{' '}
            {l.text}
          </div>
        ))}
      </div>
    </div>
  )
}
