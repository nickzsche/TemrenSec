'use client'

import { useState } from 'react'

type Plugin = { id: string; name: string; author: string; description: string; installed: boolean; downloads: number; rating: number }

const CATALOG: Plugin[] = [
  { id: 'aws-iam', name: 'AWS IAM Audit', author: 'temren-core', description: 'Detects over-privileged IAM roles and dangling access keys.', installed: true, downloads: 12_400, rating: 4.7 },
  { id: 'cve-watch', name: 'CVE Watch', author: 'temren-core', description: 'Continuously re-scores findings as CVEs are published / EPSS changes.', installed: true, downloads: 9_320, rating: 4.6 },
  { id: 'graphql-armor', name: 'GraphQL Armor probes', author: 'communiy', description: 'Mirror GraphQL-Armor checks: depth, complexity, alias overload.', installed: false, downloads: 5_410, rating: 4.4 },
  { id: 'kube-trace', name: 'Kubernetes RBAC tracer', author: 'community', description: 'Pulls live RBAC bindings and reports cluster-admin lateral paths.', installed: false, downloads: 3_220, rating: 4.5 },
  { id: 'kafka-sniff', name: 'Kafka topic enumerator', author: 'community', description: 'Lists topics, ACLs and detects open consumer groups.', installed: false, downloads: 2_180, rating: 4.1 },
  { id: 'web3', name: 'Web3 / EVM auditor', author: 'community', description: 'Probes deployed contracts via JSON-RPC for known-vulnerable selectors.', installed: false, downloads: 1_640, rating: 4.0 },
]

export default function PluginsPage() {
  const [plugins, setPlugins] = useState<Plugin[]>(CATALOG)
  function toggle(id: string) {
    setPlugins(p => p.map(x => x.id === id ? { ...x, installed: !x.installed } : x))
  }
  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold">Plugin Marketplace</h1>
        <p className="text-sm text-zinc-500">Drop-in scanners. Plugins are Lua scripts loaded by Temren' plugin engine.</p>
      </header>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {plugins.map(p => (
          <div key={p.id} className="rounded-lg border bg-white p-4 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
            <div className="flex items-start justify-between">
              <div>
                <h2 className="font-semibold">{p.name}</h2>
                <p className="text-xs text-zinc-500">by {p.author} · ⭐ {p.rating} · {p.downloads.toLocaleString()} installs</p>
              </div>
              <button
                onClick={() => toggle(p.id)}
                className={`rounded-md px-3 py-1 text-xs font-semibold ${p.installed ? 'border border-zinc-300 dark:border-zinc-700' : 'bg-blue-600 text-white hover:bg-blue-700'}`}
              >
                {p.installed ? 'Installed' : 'Install'}
              </button>
            </div>
            <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">{p.description}</p>
          </div>
        ))}
      </div>
    </div>
  )
}
