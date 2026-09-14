'use client'

import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { ExportButton } from '@/components/export-button'

export default function VulnerabilitiesPage() {
  const [vulns, setVulns] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [severityFilter, setSeverityFilter] = useState('')

  useEffect(() => {
    setLoading(true)
    api.getDashboard().then(async (dash: any) => {
      const allVulns: any[] = []
      for (const scan of dash.recent_scans || []) {
        if (scan.status === 'completed') {
          try {
            const data = await api.getScanVulns(scan.id, severityFilter || undefined)
            allVulns.push(...(data.vulnerabilities || []))
          } catch {}
        }
      }
      setVulns(allVulns)
    }).catch(console.error).finally(() => setLoading(false))
  }, [severityFilter])

  const severityColor = (s: string) => {
    switch (s?.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-500/10 text-red-400 border-red-500/20'
      case 'HIGH': return 'bg-orange-500/10 text-orange-400 border-orange-500/20'
      case 'MEDIUM': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
      case 'LOW': return 'bg-blue-500/10 text-blue-400 border-blue-500/20'
      default: return 'bg-gray-500/10 text-gray-400 border-gray-500/20'
    }
  }

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-2xl font-bold text-white">Vulnerabilities</h1>
        <div className="flex items-center gap-3">
          <ExportButton findings={vulns} />
          <div className="flex gap-2">
            {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s => (
              <button key={s} onClick={() => setSeverityFilter(s)}
                className={`px-3 py-1 rounded text-xs font-medium transition ${
                  severityFilter === s ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-white'
                }`}>{s || 'All'}</button>
            ))}
          </div>
        </div>
      </div>

      {loading ? <p className="text-gray-400">Loading...</p> : (
        <div className="space-y-3">
          {vulns.map((v) => (
            <div key={v.id} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${severityColor(v.severity)}`}>
                    {v.severity}
                  </span>
                  <h3 className="text-white font-medium mt-2">{v.title}</h3>
                </div>
                {v.owasp_category && (
                  <span className="text-xs text-gray-500 bg-gray-800 px-2 py-1 rounded">{v.owasp_category}</span>
                )}
              </div>
              {v.url && <p className="text-sm text-gray-400 mb-1 truncate">URL: {v.url}</p>}
              {v.description && <p className="text-sm text-gray-400 mb-2">{v.description}</p>}
              {v.fix_recommendation && (
                <div className="mt-2 p-3 bg-green-500/5 border border-green-500/10 rounded-lg">
                  <p className="text-sm text-green-400"><span className="font-medium">Fix:</span> {v.fix_recommendation}</p>
                </div>
              )}
              {v.payload && (
                <details className="mt-2">
                  <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-300">Proof of Concept</summary>
                  <pre className="mt-1 p-2 bg-gray-800 rounded text-xs text-gray-300 overflow-x-auto">{v.payload}</pre>
                </details>
              )}
            </div>
          ))}
          {vulns.length === 0 && <p className="text-gray-500 text-center py-8">No vulnerabilities found.</p>}
        </div>
      )}
    </div>
  )
}
