'use client'

import { useCallback, useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Clock, Plus, Trash2, Play, Pause, RefreshCw } from 'lucide-react'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { EmptyState } from '@/components/ui/empty-state'
import { Skeleton } from '@/components/ui/skeleton'
import { clsx } from 'clsx'

interface Schedule {
  id: string
  name: string
  target_url: string
  recurrence: string
  cron_expr: string
  enabled: boolean
  last_run?: string
  next_run?: string
  last_findings?: {
    critical: number
    high: number
    medium: number
    low: number
  }
}

function formatDate(dateStr?: string) {
  if (!dateStr) return 'Never'
  try {
    const d = new Date(dateStr)
    return d.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    })
  } catch {
    return dateStr
  }
}

function recurrenceLabel(schedule: Schedule) {
  switch (schedule.recurrence) {
    case 'hourly':
      return 'Every hour'
    case 'daily':
      return 'Every day at 2:00 AM'
    case 'weekly':
      return 'Every Monday at 2:00 AM'
    case 'monthly':
      return 'First day of each month at 2:00 AM'
    case 'custom':
      return `Cron: ${schedule.cron_expr}`
    default:
      return schedule.cron_expr || schedule.recurrence
  }
}

export default function SchedulesPage() {
  const router = useRouter()
  const [schedules, setSchedules] = useState<Schedule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const fetchSchedules = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const data: any = await api.getSchedules()
      setSchedules(data.schedules || data || [])
    } catch (err: any) {
      setError(err.message || 'Failed to load schedules')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchSchedules()
  }, [fetchSchedules])

  const handleToggle = useCallback(async (id: string, currentlyEnabled: boolean) => {
    try {
      await api.toggleSchedule(id, !currentlyEnabled)
      setSchedules((prev) =>
        prev.map((s) => (s.id === id ? { ...s, enabled: !currentlyEnabled } : s)),
      )
    } catch (err: any) {
      setError(err.message || 'Failed to toggle schedule')
    }
  }, [])

  const handleDelete = useCallback(async (id: string) => {
    try {
      await api.deleteSchedule(id)
      setSchedules((prev) => prev.filter((s) => s.id !== id))
    } catch (err: any) {
      setError(err.message || 'Failed to delete schedule')
    }
  }, [])

  if (loading) {
    return (
      <div className="p-8">
        <div className="flex items-center justify-between mb-8">
          <h1 className="text-xl font-bold text-white">Scheduled Scans</h1>
        </div>
        <Skeleton variant="card" count={3} />
      </div>
    )
  }

  return (
    <div className="p-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-3">
          <Clock className="w-5 h-5 text-gray-400" />
          <h1 className="text-xl font-bold text-white">Scheduled Scans</h1>
        </div>
        <Button variant="primary" size="sm" onClick={() => router.push('/dashboard/schedules/new')} className="gap-2">
          <Plus className="w-4 h-4" />
          New Schedule
        </Button>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Schedules list */}
      {schedules.length === 0 ? (
        <EmptyState
          icon={Clock}
          title="No scheduled scans"
          description="Set up recurring scans to automatically test your targets on a schedule."
          actionLabel="Create Schedule"
          onAction={() => router.push('/dashboard/schedules/new')}
        />
      ) : (
        <div className="space-y-4">
          {schedules.map((schedule) => (
            <Card key={schedule.id} className={clsx(!schedule.enabled && 'opacity-60')}>
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 mb-1">
                    <h3 className="text-sm font-medium text-white truncate">
                      {schedule.name}
                    </h3>
                    {!schedule.enabled && (
                      <span className="px-2 py-0.5 bg-gray-700 text-gray-400 text-xs rounded border border-gray-600">
                        Paused
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-gray-500 truncate mb-2">
                    {schedule.target_url}
                  </p>
                  <p className="text-xs text-gray-400 mb-2">
                    {recurrenceLabel(schedule)}
                  </p>
                  <div className="flex items-center gap-4 text-xs text-gray-500">
                    <span>Last run: {formatDate(schedule.last_run)}</span>
                    {schedule.next_run && (
                      <>
                        <span className="text-gray-700">|</span>
                        <span>Next: {formatDate(schedule.next_run)}</span>
                      </>
                    )}
                  </div>
                  {schedule.last_findings && (
                    <div className="flex items-center gap-3 mt-3">
                      {schedule.last_findings.critical > 0 && (
                        <span className="text-xs">
                          <Badge severity="CRITICAL" /> {schedule.last_findings.critical}
                        </span>
                      )}
                      {schedule.last_findings.high > 0 && (
                        <span className="text-xs">
                          <Badge severity="HIGH" /> {schedule.last_findings.high}
                        </span>
                      )}
                      {schedule.last_findings.medium > 0 && (
                        <span className="text-xs">
                          <Badge severity="MEDIUM" /> {schedule.last_findings.medium}
                        </span>
                      )}
                      {schedule.last_findings.low > 0 && (
                        <span className="text-xs">
                          <Badge severity="LOW" /> {schedule.last_findings.low}
                        </span>
                      )}
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  <button
                    onClick={() => handleToggle(schedule.id, schedule.enabled)}
                    className={clsx(
                      'p-2 rounded-lg transition',
                      schedule.enabled
                        ? 'text-yellow-400 hover:bg-yellow-500/10'
                        : 'text-green-400 hover:bg-green-500/10',
                    )}
                    title={schedule.enabled ? 'Pause schedule' : 'Resume schedule'}
                  >
                    {schedule.enabled ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                  </button>
                  <button
                    onClick={() => handleDelete(schedule.id)}
                    className="p-2 rounded-lg text-gray-500 hover:text-red-400 hover:bg-red-500/10 transition"
                    title="Delete schedule"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
