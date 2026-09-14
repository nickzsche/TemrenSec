'use client'

import { useState } from 'react'

const SAMPLE = `rules:
  - name: block-prod-criticals
    when: severity == "CRITICAL" && asset.tag contains "prod"
    action: fail
    message: "Critical finding on a production asset — blocking deploy."

  - name: notify-on-high-injection
    when: severity == "HIGH" && owasp contains "Injection"
    action: notify

  - name: tag-public-leaks
    when: scanner == "Telemetry DSN / Public Key Leak"
    action: tag
    tag: "public-leak"
`

export default function PoliciesPage() {
  const [yaml, setYaml] = useState(SAMPLE)
  const [last, setLast] = useState<string>('')

  function save() {
    setLast(new Date().toISOString())
    // wire up to API: POST /policies
    const url = process.env.NEXT_PUBLIC_API_URL || '/api/v1'
    fetch(`${url}/policies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/yaml' },
      body: yaml,
    }).catch(() => {})
  }

  return (
    <div className="space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold">Policy Editor</h1>
        <p className="text-sm text-zinc-500">
          Gate findings with a small expression language. Saved policies are evaluated on every scan and on demand from CI via{' '}
          <code className="rounded bg-zinc-100 px-1 dark:bg-zinc-800">temren policy --policy …</code>.
        </p>
      </header>

      <textarea
        value={yaml}
        onChange={(e) => setYaml(e.target.value)}
        spellCheck={false}
        className="h-96 w-full rounded-md border bg-zinc-50 p-4 font-mono text-sm dark:border-zinc-800 dark:bg-zinc-950"
      />

      <div className="flex items-center gap-3">
        <button
          onClick={save}
          className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
        >
          Save & activate
        </button>
        {last && <span className="text-xs text-zinc-500">Saved at {last}</span>}
      </div>

      <section className="rounded-md border bg-zinc-50 p-4 text-sm dark:border-zinc-800 dark:bg-zinc-950">
        <h2 className="font-semibold">Expression cheatsheet</h2>
        <ul className="ml-6 mt-2 list-disc space-y-1 text-zinc-600 dark:text-zinc-400">
          <li>
            Identifiers: <code>severity</code>, <code>scanner</code>, <code>url</code>, <code>owasp</code>,{' '}
            <code>cvss</code>, <code>confidence</code>, <code>asset.tag</code>
          </li>
          <li>
            Operators: <code>== != &gt; &lt; &gt;= &lt;= &amp;&amp; || !</code>, <code>contains</code>,{' '}
            <code>startswith</code>, <code>endswith</code>
          </li>
          <li>
            Actions: <code>fail</code>, <code>warn</code>, <code>notify</code>, <code>tag</code>
          </li>
        </ul>
      </section>
    </div>
  )
}
