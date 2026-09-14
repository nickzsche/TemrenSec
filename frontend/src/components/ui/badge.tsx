'use client'

import { clsx } from 'clsx'

const severityStyles = {
  CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/20',
  HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  MEDIUM: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  LOW: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  INFO: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
} as const

const confidenceStyles = {
  HIGH: 'bg-green-500/10 text-green-400 border-green-500/20',
  MEDIUM: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  LOW: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
} as const

type Severity = keyof typeof severityStyles
type Confidence = keyof typeof confidenceStyles

interface BadgeProps {
  severity?: Severity
  confidence?: Confidence
  className?: string
}

export function Badge({ severity, confidence, className }: BadgeProps) {
  if (severity) {
    return (
      <span
        className={clsx(
          'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border',
          severityStyles[severity] ?? severityStyles.INFO,
          className,
        )}
      >
        {severity}
      </span>
    )
  }

  if (confidence) {
    return (
      <span
        className={clsx(
          'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border',
          confidenceStyles[confidence] ?? confidenceStyles.LOW,
          className,
        )}
      >
        {confidence}
      </span>
    )
  }

  return null
}
