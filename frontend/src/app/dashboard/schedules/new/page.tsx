'use client'

import { useCallback, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  ArrowLeft,
  ChevronDown,
  Globe,
  Lock,
  Zap,
  Shield,
  Webhook,
} from 'lucide-react'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { clsx } from 'clsx'

type ScanType = 'active' | 'passive' | 'hybrid'
type AuthMethod = 'none' | 'bearer' | 'basic' | 'cookie' | 'header'
type Recurrence = 'hourly' | 'daily' | 'weekly' | 'monthly' | 'custom'

const SCAN_TYPES: { value: ScanType; label: string }[] = [
  { value: 'active', label: 'Active' },
  { value: 'passive', label: 'Passive' },
  { value: 'hybrid', label: 'Hybrid' },
]

const AUTH_METHODS: { value: AuthMethod; label: string }[] = [
  { value: 'none', label: 'None' },
  { value: 'bearer', label: 'Bearer Token' },
  { value: 'basic', label: 'Basic Auth' },
  { value: 'cookie', label: 'Cookie' },
  { value: 'header', label: 'Custom Header' },
]

const RECURRENCES: { value: Recurrence; label: string }[] = [
  { value: 'hourly', label: 'Hourly' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
  { value: 'custom', label: 'Custom Cron' },
]

const CRAWL_DEPTHS = [1, 2, 3, 5, 10]
const MAX_PAGES = [10, 25, 50, 100, 200, 500]
const CONCURRENCIES = [1, 3, 5, 10, 20]
const RATE_LIMITS = [5, 10, 20, 50, 100]
const TIMEOUTS = [10, 30, 60, 120, 300]

const RECURRENCE_CRON_MAP: Record<string, string> = {
  hourly: '0 * * * *',
  daily: '0 2 * * *',
  weekly: '0 2 * * 1',
  monthly: '0 2 1 * *',
}

function Select({
  value,
  onChange,
  options,
  className,
}: {
  value: string | number
  onChange: (v: string) => void
  options: { value: string | number; label: string }[]
  className?: string
}) {
  return (
    <div className={clsx('relative', className)}>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full appearance-none bg-gray-800 border border-gray-700 text-white px-3 py-2 pr-8 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 pointer-events-none" />
    </div>
  )
}

function SectionDivider({ icon: Icon, title }: { icon: React.ElementType; title: string }) {
  return (
    <div className="flex items-center gap-2 pt-6 pb-4">
      <Icon className="w-4 h-4 text-gray-500" />
      <span className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
        {title}
      </span>
      <div className="flex-1 h-px bg-gray-800" />
    </div>
  )
}

function Checkbox({
  checked,
  onChange,
  label,
  description,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
  description?: string
}) {
  return (
    <label className="flex items-start gap-3 cursor-pointer group">
      <div
        className={clsx(
          'mt-0.5 w-4 h-4 rounded border flex items-center justify-center flex-shrink-0 transition',
          checked
            ? 'bg-blue-600 border-blue-600'
            : 'border-gray-600 group-hover:border-gray-500',
        )}
        onClick={() => onChange(!checked)}
      >
        {checked && (
          <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        )}
      </div>
      <div>
        <span className="text-sm text-gray-300">{label}</span>
        {description && (
          <p className="text-xs text-gray-500 mt-0.5">{description}</p>
        )}
      </div>
    </label>
  )
}

export default function NewSchedulePage() {
  const router = useRouter()

  const [name, setName] = useState('')
  const [targetUrl, setTargetUrl] = useState('')
  const [urlError, setUrlError] = useState('')

  const [recurrence, setRecurrence] = useState<Recurrence>('daily')
  const [cronExpr, setCronExpr] = useState('0 2 * * *')

  const [scanType, setScanType] = useState<ScanType>('active')
  const [crawlDepth, setCrawlDepth] = useState('2')
  const [maxPages, setMaxPages] = useState('50')
  const [concurrency, setConcurrency] = useState('5')
  const [rateLimit, setRateLimit] = useState('10')
  const [timeout, setTimeout_] = useState('30')

  const [authMethod, setAuthMethod] = useState<AuthMethod>('none')
  const [authToken, setAuthToken] = useState('')
  const [authUsername, setAuthUsername] = useState('')
  const [authPassword, setAuthPassword] = useState('')
  const [authCookieName, setAuthCookieName] = useState('')
  const [authCookieValue, setAuthCookieValue] = useState('')
  const [authHeaderName, setAuthHeaderName] = useState('')
  const [authHeaderValue, setAuthHeaderValue] = useState('')

  const [wafBypass, setWafBypass] = useState(false)
  const [headless, setHeadless] = useState(false)
  const [torRouting, setTorRouting] = useState(false)
  const [proofBased, setProofBased] = useState(false)
  const [generateSbom, setGenerateSbom] = useState(false)

  const [reportFormats, setReportFormats] = useState({
    html: true,
    json: true,
    sarif: true,
    junit: false,
    csv: false,
  })

  const [slackWebhook, setSlackWebhook] = useState('')
  const [discordWebhook, setDiscordWebhook] = useState('')

  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  const handleRecurrenceChange = useCallback((v: string) => {
    const val = v as Recurrence
    setRecurrence(val)
    if (val !== 'custom') {
      setCronExpr(RECURRENCE_CRON_MAP[val] || '0 2 * * *')
    }
  }, [])

  const toggleReportFormat = useCallback((key: keyof typeof reportFormats) => {
    setReportFormats((prev) => ({ ...prev, [key]: !prev[key] }))
  }, [])

  const handleSubmit = useCallback(async () => {
    setError('')

    if (!name.trim()) {
      setError('Schedule name is required')
      return
    }

    if (!targetUrl.trim()) {
      setUrlError('Target URL is required')
      return
    }
    try {
      new URL(targetUrl)
      setUrlError('')
    } catch {
      setUrlError('Please enter a valid URL (e.g., https://example.com)')
      return
    }

    if (recurrence === 'custom' && !cronExpr.trim()) {
      setError('Cron expression is required for custom recurrence')
      return
    }

    setSubmitting(true)

    try {
      const scanConfig: Record<string, unknown> = {
        scan_type: scanType,
        depth: parseInt(crawlDepth, 10),
        max_pages: parseInt(maxPages, 10),
        concurrency: parseInt(concurrency, 10),
        rate_limit: parseInt(rateLimit, 10),
        timeout: parseInt(timeout, 10),
        waf_bypass: wafBypass,
        headless_browser: headless,
        tor_routing: torRouting,
        proof_based: proofBased,
        generate_sbom: generateSbom,
        report_formats: Object.entries(reportFormats)
          .filter(([, v]) => v)
          .map(([k]) => k),
      }

      if (authMethod !== 'none') {
        const auth: Record<string, unknown> = { method: authMethod }
        if (authMethod === 'bearer') auth.token = authToken
        if (authMethod === 'basic') {
          auth.username = authUsername
          auth.password = authPassword
        }
        if (authMethod === 'cookie') {
          auth.cookie_name = authCookieName
          auth.cookie_value = authCookieValue
        }
        if (authMethod === 'header') {
          auth.header_name = authHeaderName
          auth.header_value = authHeaderValue
        }
        scanConfig.auth = auth
      }

      if (slackWebhook.trim()) scanConfig.slack_webhook = slackWebhook.trim()
      if (discordWebhook.trim()) scanConfig.discord_webhook = discordWebhook.trim()

      await api.createSchedule({
        name: name.trim(),
        target_url: targetUrl.trim(),
        cron_expr: cronExpr.trim(),
        recurrence,
        scan_config: scanConfig,
      })

      router.push('/dashboard/schedules')
    } catch (err: any) {
      setError(err.message || 'Failed to create schedule')
      setSubmitting(false)
    }
  }, [
    name, targetUrl, cronExpr, recurrence, scanType, crawlDepth, maxPages, concurrency,
    rateLimit, timeout, authMethod, authToken, authUsername, authPassword, authCookieName,
    authCookieValue, authHeaderName, authHeaderValue, wafBypass, headless, torRouting,
    proofBased, generateSbom, reportFormats, slackWebhook, discordWebhook, router,
  ])

  return (
    <div className="max-w-3xl mx-auto p-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <button
          onClick={() => router.push('/dashboard/schedules')}
          className="flex items-center gap-2 text-gray-400 hover:text-white transition text-sm"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Schedules
        </button>
        <h1 className="text-xl font-bold text-white">New Schedule</h1>
      </div>

      {/* Schedule Details */}
      <Card className="mb-6">
        <SectionDivider icon={Globe} title="Schedule Details" />

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1.5">
              Schedule Name <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Daily API Scan"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1.5">
              Target URL <span className="text-red-400">*</span>
            </label>
            <div className="relative">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="url"
                value={targetUrl}
                onChange={(e) => {
                  setTargetUrl(e.target.value)
                  setUrlError('')
                }}
                placeholder="https://api.example.com"
                className={clsx(
                  'w-full bg-gray-800 border rounded-lg pl-10 pr-3 py-2 text-white text-sm focus:outline-none focus:ring-2 transition',
                  urlError ? 'border-red-500/50 focus:ring-red-500/40' : 'border-gray-700 focus:ring-blue-500',
                )}
              />
            </div>
            {urlError && <p className="text-xs text-red-400 mt-1">{urlError}</p>}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1.5">Recurrence</label>
              <Select
                value={recurrence}
                onChange={handleRecurrenceChange}
                options={RECURRENCES.map((r) => ({ value: r.value, label: r.label }))}
              />
            </div>
            {recurrence === 'custom' && (
              <div>
                <label className="block text-sm text-gray-400 mb-1.5">Cron Expression</label>
                <input
                  type="text"
                  value={cronExpr}
                  onChange={(e) => setCronExpr(e.target.value)}
                  placeholder="0 2 * * *"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
                />
              </div>
            )}
          </div>
        </div>
      </Card>

      {/* Scan Configuration */}
      <Card className="mb-6">
        <SectionDivider icon={Zap} title="Scan Configuration" />

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1.5">Scan Type</label>
            <Select
              value={scanType}
              onChange={(v) => setScanType(v as ScanType)}
              options={SCAN_TYPES.map((t) => ({ value: t.value, label: t.label }))}
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1.5">Crawl Depth</label>
            <Select
              value={crawlDepth}
              onChange={setCrawlDepth}
              options={CRAWL_DEPTHS.map((d) => ({ value: d, label: String(d) }))}
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1.5">Max Pages</label>
            <Select
              value={maxPages}
              onChange={setMaxPages}
              options={MAX_PAGES.map((p) => ({ value: p, label: String(p) }))}
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1.5">Concurrency</label>
            <Select
              value={concurrency}
              onChange={setConcurrency}
              options={CONCURRENCIES.map((c) => ({ value: c, label: String(c) }))}
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1.5">Rate Limit (req/s)</label>
            <Select
              value={rateLimit}
              onChange={setRateLimit}
              options={RATE_LIMITS.map((r) => ({ value: r, label: String(r) }))}
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1.5">Timeout (s)</label>
            <Select
              value={timeout}
              onChange={setTimeout_}
              options={TIMEOUTS.map((t) => ({ value: t, label: String(t) }))}
            />
          </div>
        </div>
      </Card>

      {/* Authentication */}
      <Card className="mb-6">
        <SectionDivider icon={Lock} title="Authentication (Optional)" />

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1.5">Auth Method</label>
            <Select
              value={authMethod}
              onChange={(v) => setAuthMethod(v as AuthMethod)}
              options={AUTH_METHODS.map((m) => ({ value: m.value, label: m.label }))}
            />
          </div>

          {authMethod === 'bearer' && (
            <div>
              <label className="block text-sm text-gray-400 mb-1.5">Bearer Token</label>
              <input
                type="text"
                value={authToken}
                onChange={(e) => setAuthToken(e.target.value)}
                placeholder="eyJhbGciOiJIUzI1NiIs..."
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
              />
            </div>
          )}

          {authMethod === 'basic' && (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1.5">Username</label>
                <input
                  type="text"
                  value={authUsername}
                  onChange={(e) => setAuthUsername(e.target.value)}
                  placeholder="admin"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1.5">Password</label>
                <input
                  type="password"
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
                />
              </div>
            </div>
          )}

          {authMethod === 'cookie' && (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1.5">Cookie Name</label>
                <input
                  type="text"
                  value={authCookieName}
                  onChange={(e) => setAuthCookieName(e.target.value)}
                  placeholder="session_id"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1.5">Cookie Value</label>
                <input
                  type="text"
                  value={authCookieValue}
                  onChange={(e) => setAuthCookieValue(e.target.value)}
                  placeholder="abc123..."
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
                />
              </div>
            </div>
          )}

          {authMethod === 'header' && (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1.5">Header Name</label>
                <input
                  type="text"
                  value={authHeaderName}
                  onChange={(e) => setAuthHeaderName(e.target.value)}
                  placeholder="X-API-Key"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1.5">Header Value</label>
                <input
                  type="text"
                  value={authHeaderValue}
                  onChange={(e) => setAuthHeaderValue(e.target.value)}
                  placeholder="your-api-key"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
                />
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Advanced Options */}
      <Card className="mb-6">
        <SectionDivider icon={Shield} title="Advanced Options" />

        <div className="space-y-3">
          <Checkbox checked={wafBypass} onChange={setWafBypass} label="Enable WAF Bypass" description="Evade Cloudflare, Akamai, Imperva, AWS WAF" />
          <Checkbox checked={headless} onChange={setHeadless} label="Enable Headless Browser" description="SPA/JavaScript rendering for Single Page Applications" />
          <Checkbox checked={torRouting} onChange={setTorRouting} label="Enable Tor Routing" description="Route scan traffic through Tor network" />
          <Checkbox checked={proofBased} onChange={setProofBased} label="Enable Proof-Based Verification" description="Verify findings with proof-of-concept payloads" />
          <Checkbox checked={generateSbom} onChange={setGenerateSbom} label="Generate SBOM" description="Software Bill of Materials generation" />
        </div>

        <div className="mt-5">
          <label className="block text-sm text-gray-400 mb-2">Report Formats</label>
          <div className="flex flex-wrap gap-2">
            {(Object.entries(reportFormats) as [keyof typeof reportFormats, boolean][]).map(
              ([key, checked]) => (
                <button
                  key={key}
                  onClick={() => toggleReportFormat(key)}
                  className={clsx(
                    'px-3 py-1.5 rounded-lg text-xs font-medium border transition',
                    checked
                      ? 'bg-blue-600/20 text-blue-400 border-blue-500/30'
                      : 'bg-gray-800 text-gray-400 border-gray-700 hover:border-gray-600',
                  )}
                >
                  {checked && <span className="mr-1.5">&#10003;</span>}
                  {key.toUpperCase()}
                </button>
              ),
            )}
          </div>
        </div>
      </Card>

      {/* Integrations */}
      <Card className="mb-6">
        <SectionDivider icon={Webhook} title="Integrations" />

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1.5">Slack Webhook URL</label>
            <input
              type="url"
              value={slackWebhook}
              onChange={(e) => setSlackWebhook(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1.5">Discord Webhook URL</label>
            <input
              type="url"
              value={discordWebhook}
              onChange={(e) => setDiscordWebhook(e.target.value)}
              placeholder="https://discord.com/api/webhooks/..."
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
            />
          </div>
        </div>
      </Card>

      {/* Error */}
      {error && (
        <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center justify-end gap-3">
        <Button variant="secondary" onClick={() => router.push('/dashboard/schedules')}>
          Cancel
        </Button>
        <Button variant="primary" onClick={handleSubmit} loading={submitting}>
          {submitting ? 'Saving...' : 'Save Schedule'}
        </Button>
      </div>
    </div>
  )
}
