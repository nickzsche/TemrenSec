'use client'

import { clsx } from 'clsx'
import type { ReactNode } from 'react'

const variantStyles = {
  default: 'bg-gray-900 border-gray-800 dark:bg-gray-900 dark:border-gray-800',
  success: 'bg-gray-900 border-green-500/30 dark:bg-gray-900 dark:border-green-500/30',
  warning: 'bg-gray-900 border-yellow-500/30 dark:bg-gray-900 dark:border-yellow-500/30',
  danger: 'bg-gray-900 border-red-500/30 dark:bg-gray-900 dark:border-red-500/30',
} as const

type CardVariant = keyof typeof variantStyles

interface CardProps {
  variant?: CardVariant
  title?: string
  description?: string
  children?: ReactNode
  className?: string
}

export function Card({ variant = 'default', title, description, children, className }: CardProps) {
  return (
    <div
      className={clsx(
        'rounded-xl border p-5 transition-colors',
        variantStyles[variant],
        className,
      )}
    >
      {title && (
        <div className="mb-3">
          <h3 className="text-sm font-medium text-gray-400 dark:text-gray-400">{title}</h3>
          {description && (
            <p className="text-xs text-gray-500 dark:text-gray-500 mt-0.5">{description}</p>
          )}
        </div>
      )}
      {children}
    </div>
  )
}
