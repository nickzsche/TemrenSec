'use client'
import { authHeader } from '@/lib/api'

import { useState } from 'react'

type Msg = { role: 'user' | 'assistant'; text: string }

export default function AIChatPage() {
  const [input, setInput] = useState('')
  const [messages, setMessages] = useState<Msg[]>([
    { role: 'assistant', text: 'Hi — ask me about your scan findings, request an exploit-chain analysis, or describe what you want to scan in plain English.' },
  ])
  const [busy, setBusy] = useState(false)

  async function send() {
    if (!input.trim()) return
    const user: Msg = { role: 'user', text: input }
    setMessages((m) => [...m, user])
    setInput('')
    setBusy(true)
    try {
      const url = process.env.NEXT_PUBLIC_API_URL || '/api/v1'
      const resp = await fetch(`${url}/ai/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeader() },
        body: JSON.stringify({ prompt: user.text }),
      })
      const data = resp.ok ? await resp.json() : { reply: 'AI provider not configured. Set ANTHROPIC_API_KEY / OPENAI_API_KEY in the server env.' }
      setMessages((m) => [...m, { role: 'assistant', text: data.reply }])
    } catch (e) {
      setMessages((m) => [...m, { role: 'assistant', text: `Error: ${e}` }])
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex h-[calc(100vh-4rem)] flex-col p-6">
      <header className="mb-4">
        <h1 className="text-2xl font-bold">AI Security Advisor</h1>
        <p className="text-sm text-zinc-500">Triage findings, propose exploit chains, write remediation plans, convert NL → scan config.</p>
      </header>

      <div className="flex-1 space-y-4 overflow-y-auto rounded-lg border bg-zinc-50 p-4 dark:border-zinc-800 dark:bg-zinc-950">
        {messages.map((m, i) => (
          <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`max-w-2xl rounded-lg px-4 py-2 text-sm whitespace-pre-wrap ${
              m.role === 'user'
                ? 'bg-blue-600 text-white'
                : 'bg-white text-zinc-800 shadow-sm dark:bg-zinc-900 dark:text-zinc-200'
            }`}>{m.text}</div>
          </div>
        ))}
        {busy && <div className="text-sm text-zinc-500">…thinking</div>}
      </div>

      <div className="mt-4 flex gap-2">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && send()}
          placeholder='e.g. "scan my staging API for OWASP top 10"'
          className="flex-1 rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-900"
        />
        <button onClick={send} disabled={busy} className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
          Send
        </button>
      </div>
    </div>
  )
}
