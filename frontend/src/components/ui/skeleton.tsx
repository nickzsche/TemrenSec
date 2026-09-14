'use client'

import { clsx } from 'clsx'

interface SkeletonProps {
  variant?: 'line' | 'card' | 'chart' | 'table-row'
  count?: number
  className?: string
}

export function Skeleton({ variant = 'line', count = 1, className }: SkeletonProps) {
  const items = Array.from({ length: count }, (_, i) => i)

  if (variant === 'card') {
    return (
      <div className={clsx('rounded-xl border border-gray-800 bg-gray-900 p-5 animate-pulse', className)}>
        <div className="h-4 bg-gray-800 rounded w-1/3 mb-3" />
        <div className="h-3 bg-gray-800 rounded w-2/3 mb-2" />
        <div className="h-3 bg-gray-800 rounded w-1/2" />
      </div>
    )
  }

  if (variant === 'chart') {
    return (
      <div className={clsx('rounded-xl border border-gray-800 bg-gray-900 p-6 animate-pulse', className)}>
        <div className="h-4 bg-gray-800 rounded w-1/4 mb-6" />
        <div className="h-48 bg-gray-800 rounded" />
      </div>
    )
  }

  if (variant === 'table-row') {
    return (
      <div className="space-y-3">
        {items.map((i) => (
          <div key={i} className="flex items-center gap-4 animate-pulse">
            <div className="h-4 bg-gray-800 rounded w-16" />
            <div className="h-4 bg-gray-800 rounded flex-1" />
            <div className="h-4 bg-gray-800 rounded w-24" />
            <div className="h-4 bg-gray-800 rounded w-20" />
          </div>
        ))}
      </div>
    )
  }

  // line variant
  return (
    <div className="space-y-2">
      {items.map((i) => (
        <div key={i} className={clsx('h-4 bg-gray-800 rounded animate-pulse', className ?? 'w-full')} />
      ))}
    </div>
  )
}
