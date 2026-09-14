'use client'

import { useCallback, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  ArrowLeft,
  ArrowRight,
  ChevronDown,
  Globe,
  Lock,
  Zap,
  Shield,
  FileText,
  Webhook,
  Search,
  ShieldCheck,
  KeyRound,
  ClipboardCheck,
  Eye,
} from 'lucide-react'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { clsx } from 'clsx'

type ScanType = 'active' | 'passive' | 'hybrid'
type AuthMethod = 'none' | 'bearer' | 'basic' | 'cookie' | 'header'

interface AdvisorPreset {
  id: string
  icon: React.ElementType
  label: string
  description: string
  emoji: string
  config: {
    scanType: ScanType
    crawlDepth: string
    maxPages: string
    concurrency: string
    rateLimit: string
    timeout: string
    wafBypass: boolean
    headless: boolean
    torRouting: boolean
    proofBased: boolean
    generateSbom: boolean
  }
  explanation: string
  estimatedScanners: number
  estimatedMinutes: number
}

const PRESETS: AdvisorPreset[] = [
  {
    id: 'api-security',
    icon: ShieldCheck,
    label: 'API Security',
    emoji: '\uD83D\uDD12',
    description: 'Scan my API endpoints for auth vulnerabilities, injection, and data exposure',
    config: {
      scanType: 'active',
      crawlDepth: '2',
      maxPages: '50',
      concurrency: '5',
      rateLimit: '10',
      timeout: '30',
      wafBypass: false,
      headless: false,
      torRouting: false,
      proofBased: true,
      generateSbom: false,
    },
    explanation:
      'API Security scan focuses on: Authentication testing, IDOR detection, CORS misconfiguration, OpenAPI spec discovery. These scanners are most relevant to API security.',
    estimatedScanners: 12,
    estimatedMinutes: 15,
  },
  {
    id: 'full-website',
    icon: Globe,
    label: 'Full Website Scan',
    emoji: '\uD83C\uDF10',
    description: 'Comprehensive scan of my entire website for OWASP Top 10',
    config: {
      scanType: 'hybrid',
      crawlDepth: '5',
      maxPages: '200',
      concurrency: '10',
      rateLimit: '20',
      timeout: '60',
      wafBypass: false,
      headless: true,
      torRouting: false,
      proofBased: true,
      generateSbom: true,
    },
    explanation:
      'Full Website Scan covers all OWASP Top 10 categories: injection flaws, broken authentication, sensitive data exposure, XML external entities, broken access control, misconfigurations, XSS, insecure deserialization, vulnerable components, and logging failures.',
    estimatedScanners: 26,
    estimatedMinutes: 45,
  },
  {
    id: 'quick-check',
    icon: Search,
    label: 'Quick Security Check',
    emoji: '\uD83D\uDD0D',
    description: 'Fast scan focusing on the most critical vulnerabilities',
    config: {
      scanType: 'active',
      crawlDepth: '1',
      maxPages: '25',
      concurrency: '10',
      rateLimit: '50',
      timeout: '10',
      wafBypass: false,
      headless: false,
      torRouting: false,
      proofBased: false,
      generateSbom: false,
    },
    explanation:
      'Quick Security Check targets the highest-impact vulnerabilities: SQL Injection, XSS, Command Injection, and Authentication bypass. Optimized for speed with shallow crawl depth.',
    estimatedScanners: 8,
    estimatedMinutes: 5,
  },
  {
    id: 'auth-testing',
    icon: KeyRound,
    label: 'Authentication Testing',
    emoji: '\uD83D\uDD11',
    description: 'Test login systems, session management, and access controls',
    config: {
      scanType: 'active',
      crawlDepth: '3',
      maxPages: '100',
      concurrency: '3',
      rateLimit: '5',
      timeout: '30',
      wafBypass: false,
      headless: true,
      torRouting: false,
      proofBased: true,
      generateSbom: false,
    },
    explanation:
      'Authentication Testing probes: login form brute force, session fixation, cookie security, JWT validation, OAuth misconfigurations, privilege escalation, and default credential detection.',
    estimatedScanners: 10,
    estimatedMinutes: 20,
  },
  {
    id: 'compliance-audit',
    icon: ClipboardCheck,
    label: 'Compliance Audit',
    emoji: '\uD83D\uDCCA',
    description: 'PCI-DSS, SOC2, and ISO 27001 compliance-focused scan',
    config: {
      scanType: 'hybrid',
      crawlDepth: '5',
      maxPages: '200',
      concurrency: '5',
      rateLimit: '10',
      timeout: '120',
      wafBypass: false,
      headless: true,
      torRouting: false,
      proofBased: true,
      generateSbom: true,
    },
    explanation:
      'Compliance Audit generates evidence-grade reports aligned with PCI-DSS requirement 6.5, SOC2 CC6.1, and ISO 27001 Annex A.14. Includes SBOM generation for supply chain verification.',
    estimatedScanners: 26,
    estimatedMinutes: 60,
  },
  {
    id: 'stealth-scan',
    icon: Eye,
    label: 'Stealth Scan',
    emoji: '\uD83D\uDD75\uFE0F',
    description: 'Low-profile scan with anti-detection and WAF bypass',
    config: {
      scanType: 'active',
      crawlDepth: '3',
      maxPages: '100',
      concurrency: '3',
      rateLimit: '5',
      timeout: '60',
      wafBypass: true,
      headless: false,
      torRouting: true,
      proofBased: false,
      generateSbom: false,
    },
    explanation:
      'Stealth Scan uses low concurrency, Tor routing, and WAF bypass techniques to avoid detection. Payloads are obfuscated to evade Cloudflare, Akamai, Imperva, and AWS WAF.',
    estimatedScanners: 14,
    estimatedMinutes: 30,
  },
]

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

const CRAWL_DEPTHS = [1, 2, 3, 5, 10]
const MAX_PAGES = [10, 25, 50, 100, 200, 500]
const CONCURRENCIES = [1, 3, 5, 10, 20]
const RATE_LIMITS = [5, 10, 20, 50, 100]
const TIMEOUTS = [10, 30, 60, 120, 300]

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

export default function AdvisorPage() {
  const router = useRouter()

  const [step, setStep] = useState<1 | 2 | 3>(1)
  const [naturalLanguage, setNaturalLanguage] = useState('')
  const [selectedPreset, setSelectedPreset] = useState<AdvisorPreset | null>(null)

  const [targetUrl, setTargetUrl] = useState('')
  const [targetName, setTargetName] = useState('')
  const [urlError, setUrlError] = useState('')

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

  const applyPreset = useCallback((preset: AdvisorPreset) => {
    setSelectedPreset(preset)
    const c = preset.config
    setScanType(c.scanType)
    setCrawlDepth(c.crawlDepth)
    setMaxPages(c.maxPages)
    setConcurrency(c.concurrency)
    setRateLimit(c.rateLimit)
    setTimeout_(c.timeout)
    setWafBypass(c.wafBypass)
    setHeadless(c.headless)
    setTorRouting(c.torRouting)
    setProofBased(c.proofBased)
    setGenerateSbom(c.generateSbom)
  }, [])

  const toggleReportFormat = useCallback((key: keyof typeof reportFormats) => {
    setReportFormats((prev) => ({ ...prev, [key]: !prev[key] }))
  }, [])

  const validateUrl = useCallback(() => {
    if (!targetUrl.trim()) {
      setUrlError('Target URL is required')
      return false
    }
    try {
      new URL(targetUrl)
      setUrlError('')
      return true
    } catch {
      setUrlError('Please enter a valid URL (e.g., https://example.com)')
      return false
    }
  }, [targetUrl])

  const goToStep2 = useCallback(() => {
    setError('')
    if (!selectedPreset && !naturalLanguage.trim()) {
      setError('Please select a scan type or describe what you want to scan.')
      return
    }
    if (!selectedPreset) {
      const defaultPreset = PRESETS.find((p) => p.id === 'full-website')!
      applyPreset(defaultPreset)
    }
    setStep(2)
  }, [selectedPreset, naturalLanguage, applyPreset])

  const goToStep3 = useCallback(() => {
    setError('')
    if (!validateUrl()) return
    try {
      const url = new URL(targetUrl)
      if (!targetName) setTargetName(url.hostname)
    } catch {}
    setStep(3)
  }, [targetUrl, targetName, validateUrl])

  const handleSubmit = useCallback(async () => {
    setError('')
    setSubmitting(true)

    try {
      if (!validateUrl()) {
        setSubmitting(false)
        return
      }

      let projectId = ''
      try {
        const projData: any = await api.getProjects()
        const projs = projData.projects || []
        if (projs.length > 0) {
          projectId = projs[0].id
        } else {
          const proj = await api.createProject('Default Project', 'Auto-created project')
          projectId = (proj as any).id || (proj as any).project?.id
        }
      } catch {
        const proj = await api.createProject('Default Project', 'Auto-created project')
        projectId = (proj as any).id || (proj as any).project?.id
      }

      const target = await api.createTarget({
        project_id: projectId,
        url: targetUrl.trim(),
        name: targetName.trim() || new URL(targetUrl).hostname,
      })
      const targetId = (target as any).id || (target as any).target?.id

      if (!targetId) {
        setError('Could not resolve target ID')
        setSubmitting(false)
        return
      }

      const config: Record<string, unknown> = {
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
        config.auth = auth
      }

      if (slackWebhook.trim()) config.slack_webhook = slackWebhook.trim()
      if (discordWebhook.trim()) config.discord_webhook = discordWebhook.trim()

      await api.startScan(targetId, config)
      router.push(`/dashboard/scans/progress?scanId=${targetId}`)
    } catch (err: any) {
      setError(err.message || 'Failed to start scan')
      setSubmitting(false)
    }
  }, [
    targetUrl, targetName, scanType, crawlDepth, maxPages, concurrency, rateLimit, timeout,
    authMethod, authToken, authUsername, authPassword, authCookieName, authCookieValue,
    authHeaderName, authHeaderValue, wafBypass, headless, torRouting, proofBased, generateSbom,
    reportFormats, slackWebhook, discordWebhook, validateUrl, router,
  ])

  const activePreset = selectedPreset

  return (
    <div className="max-w-3xl mx-auto p-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <button
          onClick={() => {
            if (step > 1) {
              setStep((step - 1) as 1 | 2 | 3)
            } else {
              router.push('/dashboard')
            }
          }}
          className="flex items-center gap-2 text-gray-400 hover:text-white transition text-sm"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Dashboard
        </button>
        <div className="flex items-center gap-3">
          {[1, 2, 3].map((s) => (
            <div key={s} className="flex items-center gap-1.5">
              <div
                className={clsx(
                  'w-7 h-7 rounded-full flex items-center justify-center text-xs font-medium transition',
                  s === step
                    ? 'bg-blue-600 text-white'
                    : s < step
                      ? 'bg-green-600 text-white'
                      : 'bg-gray-800 text-gray-500',
                )}
              >
                {s < step ? '\u2713' : s}
              </div>
              <span
                className={clsx(
                  'text-xs hidden sm:inline',
                  s === step ? 'text-white' : 'text-gray-500',
                )}
              >
                {s === 1 ? 'Describe' : s === 2 ? 'Configure' : 'Review'}
              </span>
              {s < 3 && <div className="w-6 h-px bg-gray-800 mx-1" />}
            </div>
          ))}
        </div>
      </div>

      <h1 className="text-xl font-bold text-white mb-6">
        Scan Advisor
      </h1>

      {/* STEP 1: What do you want to scan? */}
      {step === 1 && (
        <div className="space-y-6">
          {/* Natural language input */}
          <Card>
            <label className="block text-sm text-gray-400 mb-2">
              What would you like to scan?
            </label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="text"
                value={naturalLanguage}
                onChange={(e) => setNaturalLanguage(e.target.value)}
                placeholder="I want to scan my API for authentication vulnerabilities..."
                className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-10 pr-3 py-3 text-white text-sm placeholder:text-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
              />
            </div>
          </Card>

          {/* Quick suggestions */}
          <div>
            <h3 className="text-sm font-medium text-gray-400 mb-3">Quick suggestions</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {PRESETS.map((preset) => {
                const Icon = preset.icon
                const isSelected = selectedPreset?.id === preset.id
                return (
                  <button
                    key={preset.id}
                    onClick={() => applyPreset(preset)}
                    className={clsx(
                      'text-left p-4 rounded-xl border transition group',
                      isSelected
                        ? 'bg-blue-600/10 border-blue-500/40 ring-1 ring-blue-500/20'
                        : 'bg-gray-900 border-gray-800 hover:border-gray-700 hover:bg-gray-800/50',
                    )}
                  >
                    <div className="flex items-center gap-2.5 mb-2">
                      <span className="text-lg">{preset.emoji}</span>
                      <span
                        className={clsx(
                          'text-sm font-medium',
                          isSelected ? 'text-blue-400' : 'text-gray-300 group-hover:text-white',
                        )}
                      >
                        {preset.label}
                      </span>
                    </div>
                    <p className="text-xs text-gray-500 leading-relaxed">
                      {preset.description}
                    </p>
                    <div className="mt-2 flex items-center gap-2 text-xs text-gray-600">
                      <span>{preset.estimatedScanners} scanners</span>
                      <span>&middot;</span>
                      <span>~{preset.estimatedMinutes}min</span>
                    </div>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400">
              {error}
            </div>
          )}

          {/* Action */}
          <div className="flex justify-end">
            <Button
              variant="primary"
              onClick={goToStep2}
              className="gap-2"
            >
              Configure My Scan
              <ArrowRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
      )}

      {/* STEP 2: Scan Configuration */}
      {step === 2 && (
        <div className="space-y-6">
          {/* Why these settings banner */}
          {activePreset && (
            <div className="p-4 bg-blue-600/10 border border-blue-500/20 rounded-xl">
              <div className="flex items-start gap-3">
                <span className="text-lg mt-0.5">{activePreset.emoji}</span>
                <div>
                  <p className="text-sm text-blue-300 font-medium mb-1">
                    {activePreset.label} configuration
                  </p>
                  <p className="text-xs text-blue-400/70 leading-relaxed">
                    {activePreset.explanation}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Target URL */}
          <Card>
            <div className="space-y-4">
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
                    placeholder="https://example.com"
                    className={clsx(
                      'w-full bg-gray-800 border rounded-lg pl-10 pr-3 py-2 text-white text-sm focus:outline-none focus:ring-2 transition',
                      urlError ? 'border-red-500/50 focus:ring-red-500/40' : 'border-gray-700 focus:ring-blue-500',
                    )}
                  />
                </div>
                {urlError && <p className="text-xs text-red-400 mt-1">{urlError}</p>}
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1.5">Target Name</label>
                <input
                  type="text"
                  value={targetName}
                  onChange={(e) => setTargetName(e.target.value)}
                  placeholder="Auto-filled from URL"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
                />
              </div>
            </div>
          </Card>

          {/* Scan Configuration */}
          <Card>
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
          <Card>
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
          <Card>
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
          <Card>
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
            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400">
              {error}
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center justify-between">
            <Button variant="ghost" onClick={() => setStep(1)}>
              Back
            </Button>
            <Button variant="primary" onClick={goToStep3} className="gap-2">
              Review Scan
              <ArrowRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
      )}

      {/* STEP 3: Review & Start */}
      {step === 3 && (
        <div className="space-y-6">
          <Card>
            <h3 className="text-sm font-medium text-gray-400 mb-4">Scan Summary</h3>

            <div className="space-y-4">
              {/* Target */}
              <div className="flex items-start justify-between py-3 border-b border-gray-800">
                <span className="text-sm text-gray-500">Target URL</span>
                <span className="text-sm text-white font-medium">{targetUrl}</span>
              </div>

              {/* Scan type */}
              <div className="flex items-start justify-between py-3 border-b border-gray-800">
                <span className="text-sm text-gray-500">Scan Type</span>
                <span className="text-sm text-white capitalize">{scanType}</span>
              </div>

              {/* Preset */}
              {activePreset && (
                <div className="flex items-start justify-between py-3 border-b border-gray-800">
                  <span className="text-sm text-gray-500">Profile</span>
                  <span className="text-sm text-blue-400">
                    {activePreset.emoji} {activePreset.label}
                  </span>
                </div>
              )}

              {/* Configuration */}
              <div className="flex items-start justify-between py-3 border-b border-gray-800">
                <span className="text-sm text-gray-500">Crawl Depth</span>
                <span className="text-sm text-white">{crawlDepth}</span>
              </div>
              <div className="flex items-start justify-between py-3 border-b border-gray-800">
                <span className="text-sm text-gray-500">Max Pages</span>
                <span className="text-sm text-white">{maxPages}</span>
              </div>
              <div className="flex items-start justify-between py-3 border-b border-gray-800">
                <span className="text-sm text-gray-500">Concurrency</span>
                <span className="text-sm text-white">{concurrency}</span>
              </div>
              <div className="flex items-start justify-between py-3 border-b border-gray-800">
                <span className="text-sm text-gray-500">Rate Limit</span>
                <span className="text-sm text-white">{rateLimit} req/s</span>
              </div>

              {/* Advanced */}
              <div className="flex items-start justify-between py-3 border-b border-gray-800">
                <span className="text-sm text-gray-500">Advanced</span>
                <div className="flex flex-wrap gap-1.5 justify-end">
                  {wafBypass && <span className="px-2 py-0.5 bg-yellow-500/10 text-yellow-400 text-xs rounded border border-yellow-500/20">WAF Bypass</span>}
                  {headless && <span className="px-2 py-0.5 bg-blue-500/10 text-blue-400 text-xs rounded border border-blue-500/20">Headless</span>}
                  {torRouting && <span className="px-2 py-0.5 bg-purple-500/10 text-purple-400 text-xs rounded border border-purple-500/20">Tor</span>}
                  {proofBased && <span className="px-2 py-0.5 bg-green-500/10 text-green-400 text-xs rounded border border-green-500/20">Proof-Based</span>}
                  {generateSbom && <span className="px-2 py-0.5 bg-cyan-500/10 text-cyan-400 text-xs rounded border border-cyan-500/20">SBOM</span>}
                  {!wafBypass && !headless && !torRouting && !proofBased && !generateSbom && (
                    <span className="text-sm text-gray-600">None</span>
                  )}
                </div>
              </div>

              {/* Estimates */}
              <div className="flex items-start justify-between py-3 border-b border-gray-800">
                <span className="text-sm text-gray-500">Est. Scanners</span>
                <span className="text-sm text-white">{activePreset?.estimatedScanners ?? 26}</span>
              </div>
              <div className="flex items-start justify-between py-3">
                <span className="text-sm text-gray-500">Est. Duration</span>
                <span className="text-sm text-white">~{activePreset?.estimatedMinutes ?? 30} minutes</span>
              </div>
            </div>
          </Card>

          {/* Error */}
          {error && (
            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400">
              {error}
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center justify-between">
            <Button variant="ghost" onClick={() => setStep(2)}>
              Back
            </Button>
            <Button variant="primary" onClick={handleSubmit} loading={submitting}>
              {submitting ? 'Starting Scan...' : 'Start Scan'}
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
