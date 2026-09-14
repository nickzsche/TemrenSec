'use client'

import { useState } from 'react'

type ApiKey = { id: string; name: string; prefix: string; created: string }

export default function SettingsPage() {
  const [keys, setKeys] = useState<ApiKey[]>([
    { id: '1', name: 'CI runner', prefix: 'aeg_a1b2', created: '2026-03-12' },
  ])
  const [keyName, setKeyName] = useState('')
  const [tab, setTab] = useState<'apikeys' | 'integrations' | 'profile'>('apikeys')

  function create() {
    if (!keyName.trim()) return
    const id = String(Date.now())
    setKeys((k) => [...k, { id, name: keyName, prefix: 'aeg_' + Math.random().toString(36).slice(2, 6), created: new Date().toISOString().slice(0, 10) }])
    setKeyName('')
  }

  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold">Settings</h1>
      </header>

      <nav className="flex gap-2 border-b dark:border-zinc-800">
        {(['apikeys', 'integrations', 'profile'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium ${tab === t ? 'border-b-2 border-blue-600 text-blue-700 dark:text-blue-400' : 'text-zinc-500'}`}
          >
            {t === 'apikeys' ? 'API Keys' : t === 'integrations' ? 'Integrations' : 'Profile'}
          </button>
        ))}
      </nav>

      {tab === 'apikeys' && (
        <section className="space-y-4">
          <div className="flex gap-2">
            <input value={keyName} onChange={(e) => setKeyName(e.target.value)} placeholder="Key name (e.g. ci-runner)" className="flex-1 rounded-md border px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-900" />
            <button onClick={create} className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">Generate</button>
          </div>
          <table className="min-w-full text-sm">
            <thead className="text-left text-zinc-500"><tr><th className="py-2">Name</th><th>Prefix</th><th>Created</th></tr></thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id} className="border-b dark:border-zinc-800">
                  <td className="py-2">{k.name}</td>
                  <td className="font-mono text-xs">{k.prefix}…</td>
                  <td className="text-xs text-zinc-500">{k.created}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {tab === 'integrations' && (
        <section className="grid gap-4 md:grid-cols-2">
          {['Jira', 'GitHub', 'GitLab', 'Slack', 'Discord', 'Teams', 'ntfy', 'PagerDuty', 'OpsGenie', 'Mattermost', 'Telegram', 'Pushover'].map((p) => (
            <div key={p} className="rounded-md border p-4 dark:border-zinc-800">
              <div className="flex items-center justify-between">
                <span className="font-semibold">{p}</span>
                <button className="rounded-md border px-3 py-1 text-xs hover:bg-zinc-50 dark:border-zinc-700 dark:hover:bg-zinc-800">Configure</button>
              </div>
            </div>
          ))}
        </section>
      )}

      {tab === 'profile' && (
        <section className="space-y-4">
          <div>
            <label className="block text-sm font-medium">Email</label>
            <input className="mt-1 w-full rounded-md border px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-900" defaultValue="sahan@zerosixlab.com" />
          </div>
          <div>
            <label className="block text-sm font-medium">Default scan profile</label>
            <select className="mt-1 w-full rounded-md border px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-900">
              <option>Quick</option><option>Standard</option><option>Deep</option><option>Compliance</option>
            </select>
          </div>
        </section>
      )}
    </div>
  )
}
