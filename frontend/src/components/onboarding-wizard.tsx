'use client'

import { useCallback, useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Shield, ArrowRight, Globe, Zap, CheckCircle2, Loader2, X } from 'lucide-react'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { clsx } from 'clsx'

interface OnboardingWizardProps {
  isOpen: boolean
  onClose: () => void
}

type Step = 'welcome' | 'target' | 'configure'
type QuickScanType = 'quick' | 'full'
type QuickAuthMethod = 'none' | 'bearer' | 'basic'

export function OnboardingWizard({ isOpen, onClose }: OnboardingWizardProps) {
  const router = useRouter()
  const [step, setStep] = useState<Step>('welcome')
  const [targetUrl, setTargetUrl] = useState('')
  const [targetName, setTargetName] = useState('')
  const [urlError, setUrlError] = useState('')
  const [scanType, setScanType] = useState<QuickScanType>('quick')
  const [authMethod, setAuthMethod] = useState<QuickAuthMethod>('none')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (targetUrl) {
      try {
        const url = new URL(targetUrl)
        setTargetName(url.hostname)
      } catch {
      }
    }
  }, [targetUrl])

  const handleNext = useCallback(() => {
    if (step === 'welcome') {
      setStep('target')
    } else if (step === 'target') {
      if (!targetUrl.trim()) {
        setUrlError('Target URL is required')
        return
      }
      try {
        new URL(targetUrl)
        setUrlError('')
        setStep('configure')
      } catch {
        setUrlError('Please enter a valid URL (e.g., https://example.com)')
      }
    }
  }, [step, targetUrl])

  const handleStartScan = useCallback(async () => {
    setError('')
    setSubmitting(true)

    try {
      let projectId = ''

      const projData = await api.getProjects().catch(() => ({ projects: [] }))
      const projs = (projData as any).projects || []

      if (projs.length > 0) {
        projectId = projs[0].id
      } else {
        const created = await api.createProject('Default Project', 'Auto-created project')
        projectId = (created as any).id || (created as any).project?.id
      }

      if (!projectId) {
        setError('Could not create or find a project')
        setSubmitting(false)
        return
      }

      const target = await api.createTarget({
        project_id: projectId,
        url: targetUrl.trim(),
        name: targetName.trim() || new URL(targetUrl).hostname,
      })
      const targetId = (target as any).id || (target as any).target?.id

      if (!targetId) {
        setError('Could not create target')
        setSubmitting(false)
        return
      }

      const config: Record<string, unknown> = {
        scan_type: scanType === 'quick' ? 'active' : 'hybrid',
        depth: scanType === 'quick' ? 1 : 3,
        max_pages: scanType === 'quick' ? 25 : 100,
      }

      if (authMethod !== 'none') {
        config.auth = { method: authMethod }
      }

      await api.startScan(targetId, config)
      router.push(`/dashboard/scans/progress?scanId=${targetId}`)
    } catch (err: any) {
      setError(err.message || 'Failed to start scan')
      setSubmitting(false)
    }
  }, [targetUrl, targetName, scanType, authMethod, router])

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" role="dialog" aria-modal="true" aria-labelledby="onboarding-title">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />

      <div className="relative z-10 w-full max-w-md mx-4 bg-gray-900 border border-gray-800 rounded-2xl shadow-2xl overflow-hidden">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1 rounded-md text-gray-500 hover:text-white hover:bg-gray-800 transition z-10 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="p-8">
          {step === 'welcome' && (
            <div className="flex flex-col items-center text-center">
              <div className="w-16 h-16 rounded-2xl bg-blue-600/10 border border-blue-500/20 flex items-center justify-center mb-6">
                <Shield className="w-8 h-8 text-blue-400" />
              </div>
              <h2 id="onboarding-title" className="text-2xl font-bold text-white mb-2">Welcome to Temren</h2>
              <p className="text-gray-400 text-sm mb-8 max-w-xs">
                Your open-source security scanner. Let&apos;s set up your first scan.
              </p>

              <div className="w-full space-y-3 mb-8">
                {[
                  { icon: Globe, text: 'Add a target URL to scan' },
                  { icon: Zap, text: 'Choose scan configuration' },
                  { icon: CheckCircle2, text: 'Get vulnerability results' },
                ].map(({ icon: Icon, text }) => (
                  <div key={text} className="flex items-center gap-3 px-4 py-3 bg-gray-800/50 rounded-lg">
                    <Icon className="w-4 h-4 text-blue-400 flex-shrink-0" />
                    <span className="text-sm text-gray-300">{text}</span>
                  </div>
                ))}
              </div>

              <Button variant="primary" size="lg" className="w-full" onClick={handleNext}>
                Get Started
                <ArrowRight className="w-4 h-4" />
              </Button>
            </div>
          )}

          {step === 'target' && (
            <div>
              <h2 className="text-xl font-bold text-white mb-1">Add Your Target</h2>
              <p className="text-sm text-gray-400 mb-6">What would you like to scan?</p>

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
                      onChange={(e) => { setTargetUrl(e.target.value); setUrlError('') }}
                      placeholder="https://example.com"
                      autoFocus
                      className={clsx(
                        'w-full bg-gray-800 border rounded-lg pl-10 pr-3 py-2.5 text-white text-sm focus:outline-none focus:ring-2 transition',
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
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
                  />
                </div>
              </div>

              <div className="flex gap-3 mt-6">
                <Button variant="secondary" className="flex-1" onClick={() => setStep('welcome')}>
                  Back
                </Button>
                <Button variant="primary" className="flex-1" onClick={handleNext}>
                  Next
                  <ArrowRight className="w-4 h-4" />
                </Button>
              </div>
            </div>
          )}

          {step === 'configure' && (
            <div>
              <h2 className="text-xl font-bold text-white mb-1">Configure Scan</h2>
              <p className="text-sm text-gray-400 mb-6">Choose how to scan {targetName || 'your target'}</p>

              <div className="space-y-4 mb-6">
                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={() => setScanType('quick')}
                    className={clsx(
                      'p-4 rounded-xl border text-left transition focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none',
                      scanType === 'quick'
                        ? 'bg-blue-600/10 border-blue-500/30 ring-1 ring-blue-500/30'
                        : 'bg-gray-800/50 border-gray-700 hover:border-gray-600',
                    )}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Zap className={clsx('w-4 h-4', scanType === 'quick' ? 'text-blue-400' : 'text-gray-500')} />
                      <span className={clsx('text-sm font-medium', scanType === 'quick' ? 'text-white' : 'text-gray-300')}>
                        Quick Scan
                      </span>
                    </div>
                    <p className="text-xs text-gray-500">Fast, critical-only checks</p>
                  </button>

                  <button
                    onClick={() => setScanType('full')}
                    className={clsx(
                      'p-4 rounded-xl border text-left transition focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none',
                      scanType === 'full'
                        ? 'bg-blue-600/10 border-blue-500/30 ring-1 ring-blue-500/30'
                        : 'bg-gray-800/50 border-gray-700 hover:border-gray-600',
                    )}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Shield className={clsx('w-4 h-4', scanType === 'full' ? 'text-blue-400' : 'text-gray-500')} />
                      <span className={clsx('text-sm font-medium', scanType === 'full' ? 'text-white' : 'text-gray-300')}>
                        Full Scan
                      </span>
                    </div>
                    <p className="text-xs text-gray-500">All 26+ scanners enabled</p>
                  </button>
                </div>

                <div>
                  <label className="block text-sm text-gray-400 mb-1.5">Authentication</label>
                  <div className="flex gap-2">
                    {(['none', 'bearer', 'basic'] as const).map((m) => (
                      <button
                        key={m}
                        onClick={() => setAuthMethod(m)}
                        className={clsx(
                          'px-3 py-1.5 rounded-lg text-xs font-medium transition focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none',
                          authMethod === m
                            ? 'bg-blue-600 text-white'
                            : 'bg-gray-800 text-gray-400 hover:text-white',
                        )}
                      >
                        {m === 'none' ? 'None' : m === 'bearer' ? 'Bearer Token' : 'Basic Auth'}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {error && (
                <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-xs text-red-400">
                  {error}
                </div>
              )}

              <div className="flex gap-3">
                <Button variant="secondary" className="flex-1" onClick={() => setStep('target')}>
                  Back
                </Button>
                <Button variant="primary" className="flex-1" onClick={handleStartScan} loading={submitting}>
                  {submitting ? 'Starting...' : 'Start Scan'}
                </Button>
              </div>
            </div>
          )}
        </div>

        <div className="px-8 pb-4">
          <div className="flex items-center justify-center gap-1.5">
            {(['welcome', 'target', 'configure'] as const).map((s) => (
              <div
                key={s}
                className={clsx(
                  'h-1 rounded-full transition-all',
                  step === s ? 'w-6 bg-blue-500' : s === 'welcome' || (s === 'target' && step === 'configure') ? 'w-3 bg-gray-700' : 'w-3 bg-gray-700',
                )}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
