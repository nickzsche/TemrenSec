'use client'

import { useEffect, useState } from 'react'
import { api } from '@/lib/api'

type ApiKey = { id: string; name: string; prefix: string; created_at: string; last_used_at: string | null }

export default function SettingsPage() {
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [keyName, setKeyName] = useState('')
  const [newKey, setNewKey] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')
  const [tab, setTab] = useState<'apikeys' | 'integrations' | 'profile'>('apikeys')

  useEffect(() => {
    api.listApiKeys().then(setKeys).catch((e) => setError(e.message))
  }, [])

  async function create() {
    if (!keyName.trim()) return
    setError('')
    try {
      const k = await api.createApiKey(keyName.trim())
      setNewKey(k.key)
      setCopied(false)
      setKeys((prev) => [{ id: k.id, name: k.name, prefix: k.prefix, created_at: k.created_at, last_used_at: null }, ...prev])
      setKeyName('')
    } catch (e) {
      setError((e as Error).message)
    }
  }

  async function revoke(id: string) {
    setError('')
    try {
      await api.revokeApiKey(id)
      setKeys((prev) => prev.filter((k) => k.id !== id))
    } catch (e) {
      setError((e as Error).message)
    }
  }

  async function copyKey() {
    if (!newKey) return
    try {
      await navigator.clipboard.writeText(newKey)
      setCopied(true)
    } catch {
      setError('Copy failed. Select the key and copy it manually.')
    }
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
          <p className="text-sm text-zinc-500">
            Use a key to upload CLI or CI scans: <code className="font-mono text-xs">temren scan -t URL --upload --api-url URL --api-key tsk_… --target-id ID</code>
          </p>
          <div className="flex gap-2">
            <label htmlFor="key-name" className="sr-only">Key name</label>
            <input id="key-name" value={keyName} onChange={(e) => setKeyName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && create()} placeholder="Key name (e.g. ci-runner)" maxLength={255} className="flex-1 rounded-md border px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-900" />
            <button onClick={create} disabled={!keyName.trim()} className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50">Generate</button>
          </div>
          {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
          {newKey && (
            <div role="status" className="space-y-2 rounded-md border border-amber-300 bg-amber-50 p-3 dark:border-amber-700 dark:bg-amber-950">
              <p className="text-sm font-medium">Copy this key now. You won&apos;t be able to see it again.</p>
              <div className="flex gap-2">
                <code className="flex-1 break-all rounded bg-white px-2 py-1 font-mono text-xs dark:bg-zinc-900">{newKey}</code>
                <button onClick={copyKey} className="rounded-md border px-3 py-1 text-xs hover:bg-zinc-50 dark:border-zinc-700 dark:hover:bg-zinc-800">{copied ? 'Copied' : 'Copy'}</button>
                <button onClick={() => setNewKey(null)} className="rounded-md border px-3 py-1 text-xs hover:bg-zinc-50 dark:border-zinc-700 dark:hover:bg-zinc-800">Done</button>
              </div>
            </div>
          )}
          <table className="min-w-full text-sm">
            <thead className="text-left text-zinc-500"><tr><th className="py-2">Name</th><th>Prefix</th><th>Created</th><th>Last used</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {keys.length === 0 && (
                <tr><td colSpan={5} className="py-4 text-center text-xs text-zinc-500">No API keys yet.</td></tr>
              )}
              {keys.map((k) => (
                <tr key={k.id} className="border-b dark:border-zinc-800">
                  <td className="py-2">{k.name}</td>
                  <td className="font-mono text-xs">{k.prefix}…</td>
                  <td className="text-xs text-zinc-500">{k.created_at.slice(0, 10)}</td>
                  <td className="text-xs text-zinc-500">{k.last_used_at ? k.last_used_at.slice(0, 10) : 'Never'}</td>
                  <td className="text-right">
                    <button onClick={() => revoke(k.id)} className="rounded-md border px-3 py-1 text-xs text-red-600 hover:bg-red-50 dark:border-zinc-700 dark:hover:bg-red-950">Revoke</button>
                  </td>
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
