'use client'

import { Suspense, useEffect, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts'
import { api } from '@/lib/api'

const COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
}

export default function ScanAnalyticsPage() {
  return (
    <Suspense fallback={<div className="p-8 text-gray-400">Loading analytics...</div>}>
      <ScanAnalyticsContent />
    </Suspense>
  )
}

function ScanAnalyticsContent() {
  const searchParams = useSearchParams()
  const scanId = searchParams.get('scanId')
  const [data, setData] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!scanId) return
    api.getScan(scanId).then((scan: any) => {
      api.getScanVulns(scanId).then((vulns: any) => {
        const severityData = [
          { name: 'Critical', value: scan.critical_count || 0, color: COLORS.CRITICAL },
          { name: 'High', value: scan.high_count || 0, color: COLORS.HIGH },
          { name: 'Medium', value: scan.medium_count || 0, color: COLORS.MEDIUM },
          { name: 'Low', value: scan.low_count || 0, color: COLORS.LOW },
          { name: 'Info', value: scan.info_count || 0, color: COLORS.INFO },
        ].filter(d => d.value > 0)

        const owaspMap: Record<string, number> = {}
        ;(vulns.vulnerabilities || []).forEach((v: any) => {
          const cat = v.owasp_category || 'Unknown'
          owaspMap[cat] = (owaspMap[cat] || 0) + 1
        })

        const owaspData = Object.entries(owaspMap)
          .map(([name, value]) => ({ name, value }))
          .sort((a, b) => b.value - a.value)
          .slice(0, 10)

        setData({
          scan,
          severityData,
          owaspData,
          totalVulns: scan.total_findings || 0,
        })
        setLoading(false)
      })
    }).catch(() => setLoading(false))
  }, [scanId])

  if (loading) return <div className="p-8 text-gray-400">Loading analytics...</div>
  if (!data) return <div className="p-8 text-gray-400">No data available.</div>

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold text-white mb-2">Scan Analytics</h1>
      <p className="text-gray-400 mb-8">Scan ID: {scanId?.substring(0, 8)}...</p>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center">
          <p className="text-sm text-gray-400 mb-1">Total Findings</p>
          <p className="text-4xl font-bold text-white">{data.totalVulns}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center">
          <p className="text-sm text-gray-400 mb-1">Security Score</p>
          <p className="text-4xl font-bold text-blue-400">{data.scan.target?.security_score || 'N/A'}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center">
          <p className="text-sm text-gray-400 mb-1">Duration</p>
          <p className="text-4xl font-bold text-green-400">{data.scan.duration_seconds}s</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={data.severityData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={100}
                paddingAngle={5}
                dataKey="value"
              >
                {data.severityData.map((entry: any, index: number) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                itemStyle={{ color: '#e5e7eb' }}
              />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4">OWASP Categories</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={data.owaspData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis type="number" stroke="#9ca3af" />
              <YAxis dataKey="name" type="category" width={120} stroke="#9ca3af" tick={{ fontSize: 12 }} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                itemStyle={{ color: '#e5e7eb' }}
              />
              <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}
