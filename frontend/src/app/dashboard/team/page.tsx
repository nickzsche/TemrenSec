'use client'

import { useState } from 'react'

type Member = { id: string; email: string; role: 'admin' | 'editor' | 'viewer'; invited: string }

const DEMO: Member[] = [
  { id: '1', email: 'sahan@zerosixlab.com', role: 'admin', invited: '2026-01-12' },
  { id: '2', email: 'red@example.com', role: 'editor', invited: '2026-02-04' },
  { id: '3', email: 'audit@example.com', role: 'viewer', invited: '2026-03-21' },
]

export default function TeamPage() {
  const [members, setMembers] = useState<Member[]>(DEMO)
  const [email, setEmail] = useState('')
  const [role, setRole] = useState<Member['role']>('viewer')

  function invite() {
    if (!email.trim()) return
    setMembers((m) => [...m, { id: String(Date.now()), email, role, invited: new Date().toISOString().slice(0, 10) }])
    setEmail('')
  }
  function remove(id: string) {
    setMembers((m) => m.filter((x) => x.id !== id))
  }

  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold">Team</h1>
        <p className="text-sm text-zinc-500">Invite collaborators and manage their access.</p>
      </header>

      <div className="flex gap-2">
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="teammate@company.com" className="flex-1 rounded-md border px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-900" />
        <select value={role} onChange={(e) => setRole(e.target.value as Member['role'])} className="rounded-md border px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-900">
          <option value="viewer">Viewer</option>
          <option value="editor">Editor</option>
          <option value="admin">Admin</option>
        </select>
        <button onClick={invite} className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">Invite</button>
      </div>

      <table className="min-w-full text-sm">
        <thead className="text-left text-zinc-500"><tr><th className="py-2">Email</th><th>Role</th><th>Invited</th><th></th></tr></thead>
        <tbody>
          {members.map((m) => (
            <tr key={m.id} className="border-b dark:border-zinc-800">
              <td className="py-2">{m.email}</td>
              <td className="capitalize">{m.role}</td>
              <td className="font-mono text-xs text-zinc-500">{m.invited}</td>
              <td><button onClick={() => remove(m.id)} className="text-xs text-red-600 hover:underline">remove</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
