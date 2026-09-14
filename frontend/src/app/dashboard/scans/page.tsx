'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { Plus } from 'lucide-react'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'

export default function ScansPage() {
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getDashboard().then((data: any) => {
      setScans(data.recent_scans || [])
    }).catch(console.error).finally(() => setLoading(false))
  }, [])

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-2xl font-bold text-white">Scan History</h1>
        <Link href="/dashboard/scans/new">
          <Button variant="primary" size="sm">
            <Plus className="w-4 h-4" />
            New Scan
          </Button>
        </Link>
      </div>

      {loading ? <p className="text-gray-400">Loading...</p> : (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 border-b border-gray-800">
                <th className="text-left py-3 px-4">ID</th>
                <th className="text-left py-3 px-4">Status</th>
                <th className="text-left py-3 px-4">Duration</th>
                <th className="text-left py-3 px-4">Pages</th>
                <th className="text-left py-3 px-4">Findings</th>
                <th className="text-left py-3 px-4">Critical</th>
                <th className="text-left py-3 px-4">High</th>
                <th className="text-left py-3 px-4">Date</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="py-3 px-4">
                    <Link href={`/dashboard/scans?id=${scan.id}`} className="text-blue-400 hover:text-blue-300 font-mono text-xs">
                      {scan.id.substring(0, 8)}...
                    </Link>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                      scan.status === 'completed' ? 'bg-green-500/10 text-green-400' :
                      scan.status === 'running' ? 'bg-blue-500/10 text-blue-400' :
                      scan.status === 'failed' ? 'bg-red-500/10 text-red-400' :
                      'bg-yellow-500/10 text-yellow-400'
                    }`}>{scan.status}</span>
                  </td>
                  <td className="py-3 px-4 text-gray-300">{scan.duration_seconds}s</td>
                  <td className="py-3 px-4 text-gray-300">{scan.pages_crawled}</td>
                  <td className="py-3 px-4 text-white font-medium">{scan.total_findings}</td>
                  <td className="py-3 px-4 text-red-400">{scan.critical_count}</td>
                  <td className="py-3 px-4 text-orange-400">{scan.high_count}</td>
                  <td className="py-3 px-4 text-gray-400">{new Date(scan.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {scans.length === 0 && <p className="text-gray-500 text-center py-8">No scans yet.</p>}
        </div>
      )}
    </div>
  )
}
