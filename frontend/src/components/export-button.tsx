'use client'

import { useCallback, useRef, useState } from 'react'
import {
  Download,
  ChevronDown,
  FileJson,
  FileText,
  FileSpreadsheet,
  ClipboardCopy,
  CheckCircle2,
  Code,
} from 'lucide-react'
import { clsx } from 'clsx'

interface Finding {
  id?: string
  title?: string
  severity?: string
  confidence?: string
  url?: string
  parameter?: string
  description?: string
  evidence?: string
  payload?: string
  fix_recommendation?: string
  owasp_category?: string
  cvss_score?: number
  status?: string
  [key: string]: unknown
}

interface ExportButtonProps {
  scanId?: string
  findings: Finding[]
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function toJSON(findings: Finding[], scanId?: string): string {
  return JSON.stringify(
    {
      scan_id: scanId,
      exported_at: new Date().toISOString(),
      total_findings: findings.length,
      severity_summary: {
        critical: findings.filter((f) => f.severity?.toUpperCase() === 'CRITICAL').length,
        high: findings.filter((f) => f.severity?.toUpperCase() === 'HIGH').length,
        medium: findings.filter((f) => f.severity?.toUpperCase() === 'MEDIUM').length,
        low: findings.filter((f) => f.severity?.toUpperCase() === 'LOW').length,
        info: findings.filter((f) => f.severity?.toUpperCase() === 'INFO').length,
      },
      findings,
    },
    null,
    2,
  )
}

function toSARIF(findings: Finding[], scanId?: string): string {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'TemrenSec',
            version: '1.0.0',
            informationUri: 'https://github.com/nickzsche/TemrenSec',
          },
        },
        results: findings.map((f) => ({
          ruleId: f.owasp_category || 'unknown',
          level:
            f.severity?.toUpperCase() === 'CRITICAL'
              ? 'error'
              : f.severity?.toUpperCase() === 'HIGH'
                ? 'error'
                : f.severity?.toUpperCase() === 'MEDIUM'
                  ? 'warning'
                  : 'note',
          message: {
            text: f.description || f.title || 'Security vulnerability detected',
          },
          locations: f.url
            ? [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.url },
                  },
                },
              ]
            : [],
          properties: {
            severity: f.severity,
            confidence: f.confidence,
            cvss_score: f.cvss_score,
            parameter: f.parameter,
            fix_recommendation: f.fix_recommendation,
          },
        })),
      },
    ],
  }
  return JSON.stringify(sarif, null, 2)
}

function toCSV(findings: Finding[]): string {
  const headers = ['Title', 'Severity', 'Confidence', 'URL', 'Parameter', 'OWASP Category', 'CVSS Score', 'Status', 'Description']
  const rows = findings.map((f) =>
    [
      `"${(f.title || '').replace(/"/g, '""')}"`,
      f.severity || '',
      f.confidence || '',
      `"${(f.url || '').replace(/"/g, '""')}"`,
      f.parameter || '',
      f.owasp_category || '',
      f.cvss_score?.toString() || '',
      f.status || '',
      `"${(f.description || '').replace(/"/g, '""')}"`,
    ].join(','),
  )
  return [headers.join(','), ...rows].join('\n')
}

function toJUnit(findings: Finding[], scanId?: string): string {
  const failures = findings
    .filter((f) => ['CRITICAL', 'HIGH', 'MEDIUM'].includes(f.severity?.toUpperCase() || ''))
    .map(
      (f, i) =>
        `    <testcase name="${(f.title || `Finding ${i + 1}`).replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}" classname="temren.vulnerabilities">
      <failure message="${(f.severity || 'UNKNOWN').toUpperCase()}: ${(f.title || '').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}">${(f.description || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</failure>
    </testcase>`,
    )
    .join('\n')

  const passed = findings.filter(
    (f) => !['CRITICAL', 'HIGH', 'MEDIUM'].includes(f.severity?.toUpperCase() || ''),
  ).length

  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="Temren Security Scan${scanId ? ` - ${scanId.substring(0, 8)}` : ''}" tests="${findings.length}" failures="${findings.length - passed}" errors="0">
${failures}
  </testsuite>
</testsuites>`
}

function toMarkdown(findings: Finding[]): string {
  const lines = [
    '# Temren Security Scan Findings',
    '',
    `**Total Findings:** ${findings.length}`,
    `**Generated:** ${new Date().toISOString()}`,
    '',
    '| # | Severity | Title | URL | OWASP | CVSS |',
    '|---|----------|-------|-----|-------|------|',
    ...findings.map(
      (f, i) =>
        `| ${i + 1} | ${f.severity || 'N/A'} | ${f.title || 'Untitled'} | ${f.url || 'N/A'} | ${f.owasp_category || 'N/A'} | ${f.cvss_score || 'N/A'} |`,
    ),
    '',
  ]

  findings.forEach((f, i) => {
    lines.push(`## ${i + 1}. ${f.title || 'Untitled'}`)
    lines.push('')
    lines.push(`- **Severity:** ${f.severity || 'N/A'}`)
    if (f.confidence) lines.push(`- **Confidence:** ${f.confidence}`)
    if (f.owasp_category) lines.push(`- **OWASP:** ${f.owasp_category}`)
    if (f.url) lines.push(`- **URL:** ${f.url}`)
    if (f.parameter) lines.push(`- **Parameter:** ${f.parameter}`)
    if (f.cvss_score) lines.push(`- **CVSS:** ${f.cvss_score}/10`)
    lines.push('')
    if (f.description) {
      lines.push(f.description)
      lines.push('')
    }
    if (f.fix_recommendation) {
      lines.push(`**Remediation:** ${f.fix_recommendation}`)
      lines.push('')
    }
  })

  return lines.join('\n')
}

export function ExportButton({ scanId, findings }: ExportButtonProps) {
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  const baseName = `temren-findings${scanId ? `-${scanId.substring(0, 8)}` : ''}`

  const handleExport = useCallback(
    (format: string) => {
      setOpen(false)

      switch (format) {
        case 'json':
          downloadBlob(
            new Blob([toJSON(findings, scanId)], { type: 'application/json' }),
            `${baseName}.json`,
          )
          break
        case 'sarif':
          downloadBlob(
            new Blob([toSARIF(findings, scanId)], { type: 'application/json' }),
            `${baseName}.sarif`,
          )
          break
        case 'csv':
          downloadBlob(
            new Blob([toCSV(findings)], { type: 'text/csv' }),
            `${baseName}.csv`,
          )
          break
        case 'junit':
          downloadBlob(
            new Blob([toJUnit(findings, scanId)], { type: 'application/xml' }),
            `${baseName}-junit.xml`,
          )
          break
        case 'markdown':
          navigator.clipboard.writeText(toMarkdown(findings)).then(() => {
            setCopied(true)
            setTimeout(() => setCopied(false), 2000)
          })
          break
      }
    },
    [findings, scanId, baseName],
  )

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setOpen(!open)}
        className={clsx(
          'inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition',
          'bg-gray-800 border border-gray-700 text-gray-300 hover:text-white hover:bg-gray-700',
        )}
      >
        <Download className="w-3.5 h-3.5" />
        Export
        <ChevronDown className="w-3.5 h-3.5" />
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full mt-1 z-50 w-52 bg-gray-900 border border-gray-800 rounded-xl shadow-xl py-1">
            <button
              onClick={() => handleExport('json')}
              className="flex items-center gap-3 w-full px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 transition"
            >
              <FileJson className="w-4 h-4 text-blue-400" />
              Export as JSON
            </button>
            <button
              onClick={() => handleExport('sarif')}
              className="flex items-center gap-3 w-full px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 transition"
            >
              <Code className="w-4 h-4 text-purple-400" />
              Export as SARIF
            </button>
            <button
              onClick={() => handleExport('csv')}
              className="flex items-center gap-3 w-full px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 transition"
            >
              <FileSpreadsheet className="w-4 h-4 text-green-400" />
              Export as CSV
            </button>
            <button
              onClick={() => handleExport('junit')}
              className="flex items-center gap-3 w-full px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 transition"
            >
              <FileText className="w-4 h-4 text-orange-400" />
              Export as JUnit XML
            </button>

            <div className="my-1 border-t border-gray-800" />

            <button
              onClick={() => handleExport('markdown')}
              className="flex items-center gap-3 w-full px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 transition"
            >
              {copied ? (
                <CheckCircle2 className="w-4 h-4 text-green-400" />
              ) : (
                <ClipboardCopy className="w-4 h-4 text-gray-400" />
              )}
              {copied ? 'Copied!' : 'Copy as Markdown'}
            </button>
          </div>
        </>
      )}
    </div>
  )
}
