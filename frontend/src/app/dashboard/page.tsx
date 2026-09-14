'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts'
import { Shield, Sparkles, Plus, X } from 'lucide-react'
import { api } from '@/lib/api'
import { OnboardingWizard } from '@/components/onboarding-wizard'

const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
}

interface DashboardData {
  total_targets: number
  total_scans: number
  total_vulnerabilities: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  avg_security_score: number
  recent_scans: any[]
  severity_timeline?: any[]
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)

  const [showOnboarding, setShowOnboarding] = useState(false)
  const [showTipBanner, setShowTipBanner] = useState(false)

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const dismissed = localStorage.getItem('temren_tip_dismissed')
      if (!dismissed) setShowTipBanner(true)
    }
  }, [])

  useEffect(() => {
    api.getDashboard()
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="p-8">
        <div className="h-8 w-40 bg-gray-800 rounded-lg animate-pulse mb-8" />
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="bg-gray-800/50 border border-gray-800 rounded-xl p-4">
              <div className="h-4 w-16 bg-gray-700 rounded animate-pulse mb-2" />
              <div className="h-8 w-12 bg-gray-700 rounded animate-pulse" />
            </div>
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <div className="h-6 w-48 bg-gray-800 rounded animate-pulse mb-4" />
            <div className="h-[250px] bg-gray-800/50 rounded-lg animate-pulse" />
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <div className="h-6 w-48 bg-gray-800 rounded animate-pulse mb-4" />
            <div className="h-[250px] bg-gray-800/50 rounded-lg animate-pulse" />
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="h-6 w-32 bg-gray-800 rounded animate-pulse mb-4" />
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="h-10 bg-gray-800/50 rounded animate-pulse" />
            ))}
          </div>
        </div>
      </div>
    )
  }

  if (!data) return <div className="p-8 text-red-400">Failed to load dashboard</div>

  if (data.total_targets === 0) {
    return (
      <div className="p-8">
        <h1 className="text-2xl font-bold text-white mb-8">Dashboard</h1>
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <div className="w-16 h-16 bg-gray-800 rounded-2xl flex items-center justify-center mb-6">
            <Shield className="w-8 h-8 text-gray-500" />
          </div>
          <h2 className="text-xl font-semibold text-white mb-2">No targets yet</h2>
          <p className="text-gray-400 mb-6 max-w-md">Add your first target to start scanning for security vulnerabilities.</p>
          <div className="flex gap-3">
            <button
              onClick={() => setShowOnboarding(true)}
              className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2.5 rounded-lg font-medium transition focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
            >
              Quick Start Wizard
            </button>
            <Link href="/dashboard/scans/new" className="bg-gray-800 hover:bg-gray-700 text-gray-300 px-6 py-2.5 rounded-lg font-medium transition border border-gray-700 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none">
              Manual Setup
            </Link>
          </div>
        </div>
        <OnboardingWizard isOpen={showOnboarding} onClose={() => setShowOnboarding(false)} />
      </div>
    )
  }

  const stats = [
    { label: 'Targets', value: data.total_targets, color: 'text-blue-400', bg: 'bg-blue-500/10' },
    { label: 'Total Scans', value: data.total_scans, color: 'text-green-400', bg: 'bg-green-500/10' },
    { label: 'Critical', value: data.critical_count, color: 'text-red-400', bg: 'bg-red-500/10' },
    { label: 'High', value: data.high_count, color: 'text-orange-400', bg: 'bg-orange-500/10' },
    { label: 'Medium', value: data.medium_count, color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
    { label: 'Low', value: data.low_count, color: 'text-blue-300', bg: 'bg-blue-400/10' },
  ]

  const severityData = [
    { name: 'Critical', value: data.critical_count, color: SEVERITY_COLORS.CRITICAL },
    { name: 'High', value: data.high_count, color: SEVERITY_COLORS.HIGH },
    { name: 'Medium', value: data.medium_count, color: SEVERITY_COLORS.MEDIUM },
    { name: 'Low', value: data.low_count, color: SEVERITY_COLORS.LOW },
    { name: 'Info', value: data.info_count, color: SEVERITY_COLORS.INFO },
  ].filter(d => d.value > 0)

  const timelineData = data.severity_timeline || [
    { date: 'Mon', critical: 2, high: 5, medium: 8 },
    { date: 'Tue', critical: 1, high: 3, medium: 6 },
    { date: 'Wed', critical: 3, high: 7, medium: 4 },
    { date: 'Thu', critical: 0, high: 2, medium: 5 },
    { date: 'Fri', critical: 1, high: 4, medium: 3 },
    { date: 'Sat', critical: 0, high: 1, medium: 2 },
    { date: 'Sun', critical: 2, high: 6, medium: 7 },
  ]

  return (
    <div className="p-4 sm:p-6 md:p-8">
      {showTipBanner && (
        <div className="mb-6 flex items-center justify-between px-4 py-3 bg-blue-600/10 border border-blue-500/20 rounded-xl">
          <div className="flex items-center gap-3">
            <Shield className="w-4 h-4 text-blue-400 flex-shrink-0" />
            <span className="text-sm text-blue-300">
              Welcome! Start by adding your first target{' '}
              <Link href="/dashboard/scans/new" className="underline underline-offset-2 hover:text-blue-200 transition focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none rounded">
                here &rarr;
              </Link>
            </span>
          </div>
          <button
            onClick={() => {
              setShowTipBanner(false)
              localStorage.setItem('temren_tip_dismissed', 'true')
            }}
            className="p-1 rounded text-blue-400/60 hover:text-blue-300 transition focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-8">
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        {data.avg_security_score > 0 && (
          <div className="flex items-center gap-2 px-4 py-2 bg-gray-900 border border-gray-800 rounded-lg">
            <span className="text-sm text-gray-400">Security Score</span>
            <span className={`text-lg font-bold ${
              data.avg_security_score >= 80 ? 'text-green-400' :
              data.avg_security_score >= 60 ? 'text-yellow-400' :
              data.avg_security_score >= 40 ? 'text-orange-400' :
              'text-red-400'
            }`}>
              {data.avg_security_score}/100
            </span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
        {stats.map((s, i) => (
          <div key={i} className={`${s.bg} border border-gray-800 rounded-xl p-4`}>
            <p className="text-sm text-gray-400">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      <Link href="/dashboard/scans/new" className="block mb-8 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none rounded-xl">
        <div className="bg-blue-600/10 border border-blue-500/20 rounded-xl p-4 flex items-center justify-between hover:bg-blue-600/15 transition group">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-600/20 flex items-center justify-center">
              <Plus className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-white">Start New Scan</p>
              <p className="text-xs text-gray-400">Configure and launch a security scan</p>
            </div>
          </div>
          <span className="text-blue-400 group-hover:translate-x-1 transition-transform">&rarr;</span>
        </div>
      </Link>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        {severityData.length > 0 && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Vulnerability Distribution</h2>
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
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
        )}

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Severity Trend (7 Days)</h2>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="date" stroke="#9ca3af" fontSize={12} />
              <YAxis stroke="#9ca3af" fontSize={12} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                itemStyle={{ color: '#e5e7eb' }}
              />
              <Legend />
              <Bar dataKey="critical" fill={SEVERITY_COLORS.CRITICAL} radius={[4, 4, 0, 0]} />
              <Bar dataKey="high" fill={SEVERITY_COLORS.HIGH} radius={[4, 4, 0, 0]} />
              <Bar dataKey="medium" fill={SEVERITY_COLORS.MEDIUM} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Recent Scans</h2>
        {data.recent_scans?.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-400 border-b border-gray-800">
                  <th className="text-left py-2 px-3">Status</th>
                  <th className="text-left py-2 px-3">Findings</th>
                  <th className="text-left py-2 px-3">Critical</th>
                  <th className="text-left py-2 px-3">High</th>
                  <th className="text-left py-2 px-3">Date</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_scans.map((scan: any) => (
                  <tr key={scan.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="py-2 px-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                        scan.status === 'completed' ? 'bg-green-500/10 text-green-400' :
                        scan.status === 'running' ? 'bg-blue-500/10 text-blue-400' :
                        scan.status === 'failed' ? 'bg-red-500/10 text-red-400' :
                        'bg-gray-500/10 text-gray-400'
                      }`}>{scan.status}</span>
                    </td>
                    <td className="py-2 px-3 text-white">{scan.total_findings}</td>
                    <td className="py-2 px-3 text-red-400">{scan.critical_count}</td>
                    <td className="py-2 px-3 text-orange-400">{scan.high_count}</td>
                    <td className="py-2 px-3 text-gray-400">{new Date(scan.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-gray-500">No scans yet. Add a target and start your first scan.</p>
        )}
      </div>

      {/* Recent Remediations */}
      <div className="mt-8 bg-gray-900 border border-gray-800 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-8 h-8 bg-purple-500/10 rounded-lg flex items-center justify-center">
            <Sparkles className="w-4 h-4 text-purple-400" />
          </div>
          <h2 className="text-lg font-semibold text-white">AI Remediation</h2>
        </div>
        <p className="text-gray-400 mb-4">Connect your LLM API key to get fix suggestions for every finding.</p>
        <Link href="/dashboard/settings" className="inline-flex items-center gap-2 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none">
          <Sparkles className="w-4 h-4" />
          Configure LLM API Key
        </Link>
      </div>
    </div>
  )
}
