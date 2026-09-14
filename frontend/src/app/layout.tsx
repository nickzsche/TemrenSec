import type { Metadata } from 'next'
import { ThemeProvider } from '@/components/theme-provider'
import './globals.css'

export const metadata: Metadata = {
  title: 'Temren - Open Source Security Scanner | OWASP Top 10',
  description: 'Self-hosted security vulnerability scanner. Detect OWASP Top 10 vulnerabilities with real-time monitoring, WAF bypass, and enterprise integrations.',
  keywords: ['security scanner', 'OWASP', 'vulnerability scanner', 'penetration testing', 'web security', 'open source'],
  authors: [{ name: 'nickzsche' }],
  creator: 'ZerosixLab',
  metadataBase: new URL('https://temren.com'),
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://temren.com',
    siteName: 'TemrenSec',
    title: 'Temren - Open Source Security Scanner',
    description: 'Find security vulnerabilities before hackers do. Automated OWASP Top 10 scanning with real-time dashboard.',
    images: [
      {
        url: '/og-image.png',
        width: 1200,
        height: 630,
        alt: 'Temren Security Scanner Dashboard',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Temren - Open Source Security Scanner',
    description: 'Self-hosted OWASP Top 10 vulnerability scanner with real-time monitoring.',
    creator: '@nickzsche',
    images: ['/og-image.png'],
  },
  icons: {
    icon: '/favicon.ico',
    apple: '/apple-touch-icon.png',
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased bg-white text-gray-900 dark:bg-gray-950 dark:text-white transition-colors">
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  )
}
