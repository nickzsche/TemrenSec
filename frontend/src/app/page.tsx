'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { Shield, Zap, Globe, Lock, BarChart3, Clock, Bell, Code, Sparkles, CheckCircle, FileCheck, GitBranch, FileText } from 'lucide-react'

const features = [
  { icon: Shield, title: '36+ Security Scanners', desc: 'Full OWASP Top 10 2025 coverage: SQL Injection, XSS, SSRF, IDOR, SSTI, NoSQL, CORS, Secret Scanning, Proof-Based Verification, and more.' },
  { icon: Globe, title: 'WAF Bypass & Anti-Detection', desc: 'Advanced evasion for Cloudflare, Akamai, Imperva, AWS WAF. Proxy rotation, Tor, jitter, and user-agent rotation built in.' },
  { icon: BarChart3, title: 'Real-time Dashboard', desc: 'Watch scans live with WebSocket-powered updates. Interactive charts, severity analytics, and vulnerability timeline.' },
  { icon: Zap, title: 'AI-Powered Remediation', desc: 'Get fix suggestions for every finding powered by OpenAI, Anthropic, or Ollama. Code examples included.' },
  { icon: Lock, title: 'Proof-Based Verification', desc: 'Automatically confirms vulnerabilities with safe exploitation proof. Drastically reduces false positives.' },
  { icon: Code, title: 'Source Code API Discovery', desc: 'Automatically discovers API endpoints from your codebase and generates OpenAPI specs.' },
  { icon: FileText, title: '8 Report Formats', desc: 'HTML, CSV, XML, SARIF, JUnit, PDF, Compliance (PCI-DSS/SOC2/ISO27001), and CycloneDX SBOM.' },
  { icon: Bell, title: '10+ Integrations', desc: 'GitHub, GitLab, Slack, Discord, Teams, DefectDojo, Jira, Email, and custom webhooks.' },
]

const stats = [
  { label: 'Scanners', value: '36+' },
  { label: 'Integrations', value: '10+' },
  { label: 'Report Formats', value: '8' },
  { label: 'CVE Coverage', value: 'OWASP Top 10' },
]

const testimonials = [
  { name: 'Alex Chen', role: 'Security Engineer', text: 'Temren replaced our expensive commercial scanner. Same coverage, fraction of the cost.', company: 'TechCorp' },
  { name: 'Sarah Miller', role: 'DevOps Lead', text: 'The WAF bypass features are insane. Found vulnerabilities our old tool missed completely.', company: 'StartupXYZ' },
  { name: 'James Wilson', role: 'CTO', text: 'Self-hosted was a must for us. Temren just works out of the box with Docker.', company: 'SecureBank' },
]

export default function LandingPage() {
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 50)
    window.addEventListener('scroll', onScroll)
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Navbar */}
      <nav className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${scrolled ? 'bg-gray-950/90 backdrop-blur-md border-b border-gray-800' : 'bg-transparent'}`}>
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center font-bold text-white">A</div>
            <span className="text-xl font-bold">Temren</span>
          </div>
          <div className="flex items-center gap-6">
            <a href="#features" className="text-gray-300 hover:text-white transition text-sm hidden md:block">Features</a>
            <a href="#demo" className="text-gray-300 hover:text-white transition text-sm hidden md:block">Demo</a>
            <a href="https://github.com/nickzsche/TemrenSec" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-white transition text-sm hidden md:block">GitHub</a>
            <Link href="/login" className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition">Get Started</Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative pt-32 pb-20 px-6 overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-blue-900/20 via-gray-950 to-gray-950" />
        <div className="max-w-5xl mx-auto text-center relative">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-medium mb-6">
            <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
            Now on Product Hunt
          </div>
          <h1 className="text-5xl md:text-7xl font-bold leading-tight mb-6">
            Find security vulnerabilities
            <span className="text-blue-500"> before hackers do</span>
          </h1>
          <p className="text-xl text-gray-400 max-w-2xl mx-auto mb-10">
            Self-hosted OWASP Top 10 security scanner. 26+ detectors, WAF bypass, real-time dashboard, and enterprise integrations — all open source.
          </p>
          <div className="flex items-center justify-center gap-4 flex-wrap">
            <Link href="/register" className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3 rounded-xl text-lg font-semibold transition shadow-lg shadow-blue-600/25">
              Start Free Scan
            </Link>
            <a href="https://github.com/nickzsche/TemrenSec" target="_blank" rel="noopener noreferrer" className="bg-gray-800 hover:bg-gray-700 text-white px-8 py-3 rounded-xl text-lg font-semibold transition border border-gray-700 flex items-center gap-2">
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
              View on GitHub
            </a>
          </div>

          {/* Stats */}
          <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-8 max-w-3xl mx-auto">
            {stats.map((stat, i) => (
              <div key={i} className="text-center">
                <div className="text-3xl md:text-4xl font-bold text-white">{stat.value}</div>
                <div className="text-sm text-gray-500 mt-1">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Demo Preview */}
      <section id="demo" className="py-20 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">See it in action</h2>
            <p className="text-gray-400 max-w-xl mx-auto">Real-time vulnerability detection with an intuitive dashboard. Watch scans progress live.</p>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden shadow-2xl shadow-blue-500/5">
            <div className="bg-gray-800 px-4 py-2 flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500" />
              <div className="w-3 h-3 rounded-full bg-yellow-500" />
              <div className="w-3 h-3 rounded-full bg-green-500" />
              <div className="flex-1 text-center text-xs text-gray-500">Temren Dashboard</div>
            </div>
            <div className="p-8 grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-gray-800/50 rounded-xl p-6 text-center border border-gray-700/50">
                <div className="text-4xl font-bold text-red-400 mb-2">12</div>
                <div className="text-sm text-gray-400">Critical Findings</div>
              </div>
              <div className="bg-gray-800/50 rounded-xl p-6 text-center border border-gray-700/50">
                <div className="text-4xl font-bold text-orange-400 mb-2">28</div>
                <div className="text-sm text-gray-400">High Severity</div>
              </div>
              <div className="bg-gray-800/50 rounded-xl p-6 text-center border border-gray-700/50">
                <div className="text-4xl font-bold text-green-400 mb-2">87</div>
                <div className="text-sm text-gray-400">Security Score</div>
              </div>
              <div className="md:col-span-3 bg-gray-800/30 rounded-xl p-6 border border-gray-700/50">
                <div className="flex items-center justify-between mb-4">
                  <span className="text-sm text-gray-400">Scan Progress</span>
                  <span className="text-sm text-blue-400 font-medium">78% Complete</span>
                </div>
                <div className="w-full h-2 bg-gray-700 rounded-full overflow-hidden">
                  <div className="w-3/4 h-full bg-blue-500 rounded-full" />
                </div>
                <div className="mt-4 flex items-center gap-2 text-xs text-gray-500">
                  <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
                  Currently scanning: /api/v1/users?id=...
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-20 px-6 bg-gray-900/50">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Everything you need</h2>
            <p className="text-gray-400 max-w-xl mx-auto">From vulnerability detection to team collaboration, Temren has you covered.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {features.map((feature, i) => (
              <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl p-6 hover:border-blue-500/30 transition group">
                <div className="w-10 h-10 bg-blue-500/10 rounded-lg flex items-center justify-center mb-4 group-hover:bg-blue-500/20 transition">
                  <feature.icon className="w-5 h-5 text-blue-400" />
                </div>
                <h3 className="font-semibold text-white mb-2">{feature.title}</h3>
                <p className="text-sm text-gray-400 leading-relaxed">{feature.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* What Makes Temren Different */}
      <section id="different" className="py-20 px-6">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-4">What Makes Temren Different</h2>
          <p className="text-gray-400 text-center mb-12 max-w-2xl mx-auto">
            Unlike expensive commercial tools, Temren is open-source, self-hosted, and built for developers.
          </p>
          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8">
              <div className="w-12 h-12 bg-purple-500/10 rounded-xl flex items-center justify-center mb-4">
                <Sparkles className="w-6 h-6 text-purple-400" />
              </div>
              <h3 className="text-xl font-bold text-white mb-2">AI That Fixes, Not Just Finds</h3>
              <p className="text-gray-400">Every finding comes with an AI-generated fix suggestion and code example. Choose from OpenAI, Anthropic, or run Ollama locally for complete privacy.</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8">
              <div className="w-12 h-12 bg-green-500/10 rounded-xl flex items-center justify-center mb-4">
                <CheckCircle className="w-6 h-6 text-green-400" />
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Proof-Based Verification</h3>
              <p className="text-gray-400">No more false positives. Temren verifies every vulnerability with safe exploitation proof before reporting. Confidence scores tell you what&apos;s real.</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8">
              <div className="w-12 h-12 bg-blue-500/10 rounded-xl flex items-center justify-center mb-4">
                <FileCheck className="w-6 h-6 text-blue-400" />
              </div>
              <h3 className="text-xl font-bold text-white mb-2">SBOM & Compliance Built In</h3>
              <p className="text-gray-400">Generate CycloneDX Software Bill of Materials and map findings to PCI-DSS, SOC2, and ISO27001 controls. EU Cyber Resilience Act ready.</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8">
              <div className="w-12 h-12 bg-orange-500/10 rounded-xl flex items-center justify-center mb-4">
                <GitBranch className="w-6 h-6 text-orange-400" />
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Shift-Left Security</h3>
              <p className="text-gray-400">GitHub and GitLab integration creates issues for critical findings. Post results directly in pull requests. Break the build on critical vulnerabilities.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Testimonials */}
      <section className="py-20 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Loved by developers</h2>
            <p className="text-gray-400 max-w-xl mx-auto">Join thousands of developers securing their applications.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {testimonials.map((t, i) => (
              <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl p-6">
                <p className="text-gray-300 mb-4 leading-relaxed">&ldquo;{t.text}&rdquo;</p>
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-blue-500/20 rounded-full flex items-center justify-center text-blue-400 font-semibold">{t.name[0]}</div>
                  <div>
                    <div className="text-sm font-medium text-white">{t.name}</div>
                    <div className="text-xs text-gray-500">{t.role} at {t.company}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section className="py-20 px-6 bg-gray-900/50">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Simple pricing</h2>
            <p className="text-gray-400 max-w-xl mx-auto">Self-hosted means no per-scan fees. Your data, your control.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              { plan: 'Free', price: '$0', targets: '1 target', scans: '5 scans/day', features: ['Manual scans', 'Basic reports', 'Community support'] },
              { plan: 'Pro', price: '$29', targets: '5 targets', scans: '50 scans/day', features: ['Scheduled scans', 'Email alerts', 'Priority support', 'WAF bypass'], popular: true },
              { plan: 'Team', price: '$99', targets: '20 targets', scans: '200 scans/day', features: ['Everything in Pro', 'SSO/SAML', 'Custom integrations', 'Dedicated support'] },
            ].map((p, i) => (
              <div key={i} className={`bg-gray-900 border rounded-xl p-8 ${p.popular ? 'border-blue-500 ring-1 ring-blue-500/50' : 'border-gray-800'}`}>
                {p.popular && <div className="text-xs font-medium text-blue-400 mb-2">Most Popular</div>}
                <h3 className="text-lg font-semibold text-gray-400">{p.plan}</h3>
                <div className="mt-4 mb-6">
                  <span className="text-4xl font-bold text-white">{p.price}</span>
                  <span className="text-gray-500">/month</span>
                </div>
                <ul className="space-y-2 text-gray-300 text-sm mb-8">
                  <li>{p.targets}</li>
                  <li>{p.scans}</li>
                  {p.features.map((f, fi) => (
                    <li key={fi} className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                      {f}
                    </li>
                  ))}
                </ul>
                <Link href="/register" className={`block text-center py-2 rounded-lg font-medium transition ${p.popular ? 'bg-blue-600 hover:bg-blue-700 text-white' : 'border border-gray-600 hover:border-gray-400 text-gray-300'}`}>
                  Get Started
                </Link>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 px-6">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Ready to secure your apps?</h2>
          <p className="text-gray-400 mb-8">Join thousands of developers using Temren to find vulnerabilities before hackers do.</p>
          <div className="flex items-center justify-center gap-4">
            <Link href="/register" className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3 rounded-xl text-lg font-semibold transition">
              Start Scanning — It&apos;s Free
            </Link>
            <a href="https://github.com/nickzsche/TemrenSec" className="text-gray-300 border border-gray-700 px-8 py-3 rounded-lg hover:bg-gray-800 transition">
              View on GitHub
            </a>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-12 px-6">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 bg-blue-600 rounded flex items-center justify-center font-bold text-white text-xs">A</div>
            <span className="text-sm font-semibold">TemrenSec</span>
          </div>
          <div className="flex items-center gap-6 text-sm text-gray-500">
            <a href="https://github.com/nickzsche/TemrenSec" className="hover:text-white transition">GitHub</a>
            <a href="https://twitter.com/nickzsche" className="hover:text-white transition">Twitter</a>
            <a href="LICENSE" className="hover:text-white transition">License</a>
          </div>
          <div className="text-sm text-gray-600">
            Built by <a href="https://github.com/nickzsche" className="text-gray-500 hover:text-white transition">nickzsche</a>
          </div>
        </div>
      </footer>
    </div>
  )
}
