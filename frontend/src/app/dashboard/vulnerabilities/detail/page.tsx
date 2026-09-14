'use client'

import { Suspense, useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import {
  ArrowLeft,
  ChevronLeft,
  ChevronRight,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  ExternalLink,
} from 'lucide-react'
import { api } from '@/lib/api'
import { clsx } from 'clsx'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/ui/empty-state'
import { ExportButton } from '@/components/export-button'

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

const severityIcon = (s: string) => {
  switch (s?.toUpperCase()) {
    case 'CRITICAL':
      return ShieldAlert
    case 'HIGH':
      return AlertTriangle
    case 'MEDIUM':
      return Shield
    case 'LOW':
      return ShieldCheck
    default:
      return Info
  }
}

export default function VulnerabilityDetailPage() {
  return (
    <Suspense
      fallback={
        <div className="p-8">
          <Skeleton variant="line" count={3} />
        </div>
      }
    >
      <VulnerabilityDetailContent />
    </Suspense>
  )
}

function VulnerabilityDetailContent() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const scanId = searchParams.get('scanId')

  const [vulns, setVulns] = useState<any[]>([])
  const [scanInfo, setScanInfo] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [selectedIdx, setSelectedIdx] = useState(0)
  const [activeSeverity, setActiveSeverity] = useState<string>('')

  useEffect(() => {
    if (!scanId) {
      setLoading(false)
      return
    }

    Promise.all([
      api.getScanVulns(scanId).catch(() => ({ vulnerabilities: [] })),
      api.getScan(scanId).catch(() => null),
    ])
      .then(([vulnData, scan]) => {
        setVulns(vulnData.vulnerabilities || [])
        setScanInfo(scan)
      })
      .finally(() => setLoading(false))
  }, [scanId])

  const filtered = useMemo(() => {
    if (!activeSeverity) return vulns
    return vulns.filter(
      (v) => (v.severity ?? '').toUpperCase() === activeSeverity,
    )
  }, [vulns, activeSeverity])

  const counts = useMemo(() => {
    const m: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    vulns.forEach((v) => {
      const key = (v.severity ?? 'INFO').toUpperCase()
      m[key] = (m[key] || 0) + 1
    })
    return m
  }, [vulns])

  const selected = filtered[selectedIdx] ?? null

  useEffect(() => {
    setSelectedIdx(0)
  }, [activeSeverity])

  const goPrev = useCallback(() => setSelectedIdx((i) => Math.max(0, i - 1)), [])
  const goNext = useCallback(
    () => setSelectedIdx((i) => Math.min(filtered.length - 1, i + 1)),
    [filtered.length],
  )

  // ── Loading state ──
  if (loading) {
    return (
      <div className="p-8 space-y-4">
        <Skeleton variant="line" count={2} />
        <div className="grid grid-cols-[280px_1fr] gap-6 mt-6">
          <Skeleton variant="card" />
          <Skeleton variant="card" />
        </div>
      </div>
    )
  }

  // ── No scan ID ──
  if (!scanId) {
    return (
      <EmptyState
        icon={Shield}
        title="No scan selected"
        description="Go back to vulnerabilities and select a scan to view details."
        actionLabel="Go to Vulnerabilities"
        onAction={() => router.push('/dashboard/vulnerabilities')}
      />
    )
  }

  // ── No findings ──
  if (vulns.length === 0) {
    return (
      <div className="p-8">
        <button
          onClick={() => router.push('/dashboard/vulnerabilities')}
          className="flex items-center gap-2 text-gray-400 hover:text-white transition mb-6 text-sm"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Vulnerabilities
        </button>
        <EmptyState
          icon={ShieldCheck}
          title="No vulnerabilities found"
          description="This scan completed without detecting any security issues."
          actionLabel="Run a New Scan"
          onAction={() => router.push('/dashboard/scans')}
        />
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      {/* ── Header ── */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-900/50">
        <button
          onClick={() => router.push('/dashboard/vulnerabilities')}
          className="flex items-center gap-2 text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition text-sm"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Vulnerabilities
        </button>

        <div className="flex items-center gap-2">
          <ExportButton scanId={scanId ?? undefined} findings={filtered} />
        </div>
      </div>

      {/* ── Severity tabs ── */}
      <div className="flex items-center gap-1 px-6 py-2 border-b border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950">
        <button
          onClick={() => setActiveSeverity('')}
          className={clsx(
            'px-3 py-1 rounded text-xs font-medium transition',
            !activeSeverity
              ? 'bg-blue-600 text-white'
              : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white',
          )}
        >
          All ({vulns.length})
        </button>
        {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
          <button
            key={s}
            onClick={() => setActiveSeverity(activeSeverity === s ? '' : s)}
            className={clsx(
              'px-3 py-1 rounded text-xs font-medium transition',
              activeSeverity === s
                ? 'bg-blue-600 text-white'
                : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white',
            )}
          >
            {s} ({counts[s]})
          </button>
        ))}
      </div>

      {/* ── Main content: sidebar + detail ── */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left sidebar: findings list */}
        <div className="w-72 border-r border-gray-200 dark:border-gray-800 overflow-y-auto flex-shrink-0 bg-gray-50 dark:bg-gray-900/30">
          <div className="p-3 border-b border-gray-200 dark:border-gray-800">
            <h2 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Findings ({filtered.length})
            </h2>
          </div>
          <div className="p-2 space-y-1">
            {filtered.map((v, i) => {
              const Icon = severityIcon(v.severity)
              return (
                <button
                  key={v.id ?? i}
                  onClick={() => setSelectedIdx(i)}
                  className={clsx(
                    'w-full text-left px-3 py-2.5 rounded-lg transition group',
                    i === selectedIdx
                      ? 'bg-blue-600/10 dark:bg-blue-600/10 ring-1 ring-blue-500/30'
                      : 'hover:bg-gray-100 dark:hover:bg-gray-800/50',
                  )}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Badge severity={v.severity?.toUpperCase() as any} />
                    {v.confidence && (
                      <Badge confidence={v.confidence?.toUpperCase() as any} />
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <Icon
                      className={clsx(
                        'w-3.5 h-3.5 flex-shrink-0',
                        v.severity === 'CRITICAL'
                          ? 'text-red-400'
                          : v.severity === 'HIGH'
                            ? 'text-orange-400'
                            : v.severity === 'MEDIUM'
                              ? 'text-yellow-400'
                              : v.severity === 'LOW'
                                ? 'text-blue-400'
                                : 'text-gray-400',
                      )}
                    />
                    <span
                      className={clsx(
                        'text-sm font-medium truncate',
                        i === selectedIdx
                          ? 'text-gray-900 dark:text-white'
                          : 'text-gray-600 dark:text-gray-300',
                      )}
                    >
                      {v.title}
                    </span>
                  </div>
                </button>
              )
            })}
            {filtered.length === 0 && (
              <p className="text-xs text-gray-500 text-center py-4">
                No findings for this filter.
              </p>
            )}
          </div>
        </div>

        {/* Right: detail view */}
        <div className="flex-1 overflow-y-auto">
          {selected ? (
            <div className="p-6 max-w-4xl">
              {/* Title area */}
              <div className="mb-6">
                <div className="flex items-center gap-2 mb-3 flex-wrap">
                  <Badge severity={selected.severity?.toUpperCase() as any} />
                  {selected.confidence && (
                    <Badge
                      confidence={selected.confidence?.toUpperCase() as any}
                    />
                  )}
                  {selected.owasp_category && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
                      <ExternalLink className="w-3 h-3" />
                      {selected.owasp_category}
                    </span>
                  )}
                </div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                  {selected.title}
                </h1>
              </div>

              {/* URL & Parameter */}
              <div className="space-y-3 mb-6">
                {selected.url && (
                  <Card title="Affected URL">
                    <code className="text-blue-600 dark:text-blue-400 text-sm break-all">
                      {selected.url}
                    </code>
                  </Card>
                )}
                {selected.parameter && (
                  <Card title="Parameter">
                    <code className="text-yellow-600 dark:text-yellow-400 text-sm">
                      {selected.parameter}
                    </code>
                  </Card>
                )}
              </div>

              {/* Description */}
              {selected.description && (
                <Card title="Description" className="mb-6">
                  <p className="text-gray-700 dark:text-gray-300 text-sm leading-relaxed">
                    {selected.description}
                  </p>
                </Card>
              )}

              {/* Evidence */}
              {selected.evidence && (
                <Card title="Evidence" className="mb-6">
                  <pre className="bg-gray-100 dark:bg-gray-800 rounded-lg p-3 text-sm text-gray-800 dark:text-gray-300 overflow-x-auto whitespace-pre-wrap">
                    {selected.evidence}
                  </pre>
                </Card>
              )}

              {/* Payload */}
              {selected.payload && (
                <Card title="Payload" className="mb-6">
                  <pre className="bg-gray-100 dark:bg-gray-800 rounded-lg p-3 text-sm text-gray-800 dark:text-gray-300 overflow-x-auto whitespace-pre-wrap">
                    {selected.payload}
                  </pre>
                </Card>
              )}

              {/* Remediation */}
              {selected.fix_recommendation && (
                <Card
                  title="Remediation"
                  className="mb-6 bg-green-50 dark:bg-green-500/5 border-green-300 dark:border-green-500/20"
                >
                  <p className="text-gray-700 dark:text-gray-300 text-sm leading-relaxed">
                    {selected.fix_recommendation}
                  </p>
                </Card>
              )}

              {/* CVSS */}
              {selected.cvss_score > 0 && (
                <Card title="CVSS Score" className="mb-6">
                  <div className="flex items-center gap-4">
                    <div className="relative w-full h-3 bg-gray-200 dark:bg-gray-800 rounded-full overflow-hidden">
                      <div
                        className={clsx(
                          'absolute left-0 top-0 h-full rounded-full transition-all',
                          selected.cvss_score >= 9
                            ? 'bg-red-500'
                            : selected.cvss_score >= 7
                              ? 'bg-orange-500'
                              : selected.cvss_score >= 4
                                ? 'bg-yellow-500'
                                : 'bg-green-500',
                        )}
                        style={{
                          width: `${(selected.cvss_score / 10) * 100}%`,
                        }}
                      />
                    </div>
                    <span className="text-gray-900 dark:text-white font-bold text-lg">
                      {selected.cvss_score}
                    </span>
                  </div>
                </Card>
              )}

              {/* Navigation */}
              <div className="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-gray-800 mt-6">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={goPrev}
                  disabled={selectedIdx === 0}
                >
                  <ChevronLeft className="w-4 h-4" />
                  Previous
                </Button>

                <span className="text-xs text-gray-500">
                  Finding {selectedIdx + 1} of {filtered.length}
                </span>

                <Button
                  variant="ghost"
                  size="sm"
                  onClick={goNext}
                  disabled={selectedIdx >= filtered.length - 1}
                >
                  Next
                  <ChevronRight className="w-4 h-4" />
                </Button>
              </div>
            </div>
          ) : (
            <EmptyState
              icon={Info}
              title="Select a finding"
              description="Choose a vulnerability from the list to view details."
            />
          )}
        </div>
      </div>

      {/* ── Footer: scan info ── */}
      {scanInfo && (
        <div className="px-6 py-3 border-t border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-900/50 text-xs text-gray-500 dark:text-gray-400 flex items-center gap-2">
          <Shield className="w-3.5 h-3.5" />
          <span>
            Scan: {scanInfo.target_name ?? scanInfo.target_id ?? scanId}
            {scanInfo.created_at &&
              ` — ${new Date(scanInfo.created_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })}`}
          </span>
        </div>
      )}
    </div>
  )
}
