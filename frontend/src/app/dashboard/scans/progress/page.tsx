'use client'

import { Suspense, useEffect, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import { api } from '@/lib/api'

export default function ScanProgressPage() {
  return (
    <Suspense fallback={<div className="p-8 text-gray-400">Loading...</div>}>
      <ScanProgressContent />
    </Suspense>
  )
}

function ScanProgressContent() {
  const searchParams = useSearchParams()
  const scanId = searchParams.get('scanId')
  const [progress, setProgress] = useState<any>(null)
  const [wsConnected, setWsConnected] = useState(false)
  const [logs, setLogs] = useState<string[]>([])

  useEffect(() => {
    if (!scanId) return

    const wsUrl = `${process.env.NEXT_PUBLIC_API_URL?.replace('http', 'ws') || 'ws://localhost:8080'}/ws?client_id=frontend_${scanId}&scan_id=${scanId}`
    const ws = new WebSocket(wsUrl)

    ws.onopen = () => {
      setWsConnected(true)
      ws.send(JSON.stringify({ type: 'subscribe', topic: `scan:${scanId}` }))
    }

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data)
      if (msg.type === 'scan_update') {
        setProgress(msg.payload)
        if (msg.payload.status === 'completed') {
          setLogs(prev => [...prev, `Scan completed with ${msg.payload.findings} findings`])
        } else if (msg.payload.current_url) {
          setLogs(prev => [...prev, `Scanning: ${msg.payload.current_url}`])
        }
      }
    }

    ws.onclose = () => setWsConnected(false)
    ws.onerror = () => setWsConnected(false)

    return () => ws.close()
  }, [scanId])

  useEffect(() => {
    if (!scanId) return
    api.getScan(scanId).then((scan: any) => {
      if (scan.status === 'completed') {
        setProgress({
          scan_id: scanId,
          status: 'completed',
          progress: 100,
          scanned_urls: scan.pages_crawled,
          total_urls: scan.pages_crawled,
          findings: scan.total_findings,
        })
      }
    }).catch(console.error)
  }, [scanId])

  if (!scanId) return <div className="p-8 text-gray-400">No scan selected.</div>

  return (
    <div className="p-8 max-w-3xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Scan Progress</h1>
          <p className="text-gray-400 text-sm mt-1">ID: {scanId.substring(0, 8)}...</p>
        </div>
        <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-sm ${wsConnected ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}`}>
          <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
          {wsConnected ? 'Live' : 'Disconnected'}
        </div>
      </div>

      {progress && (
        <div className="space-y-6">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <span className={`text-sm font-medium ${
                progress.status === 'completed' ? 'text-green-400' :
                progress.status === 'running' ? 'text-blue-400' :
                progress.status === 'failed' ? 'text-red-400' :
                'text-yellow-400'
              }`}>
                {progress.status?.toUpperCase()}
              </span>
              <span className="text-white font-bold">{progress.progress || 0}%</span>
            </div>

            <div className="w-full h-3 bg-gray-800 rounded-full overflow-hidden mb-4">
              <div 
                className={`h-full rounded-full transition-all duration-500 ${
                  progress.status === 'completed' ? 'bg-green-500' :
                  progress.status === 'failed' ? 'bg-red-500' :
                  'bg-blue-500'
                }`}
                style={{ width: `${progress.progress || 0}%` }}
              />
            </div>

            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-2xl font-bold text-white">{progress.scanned_urls || 0}</p>
                <p className="text-xs text-gray-400">Scanned URLs</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{progress.total_urls || 0}</p>
                <p className="text-xs text-gray-400">Total URLs</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{progress.findings || 0}</p>
                <p className="text-xs text-gray-400">Findings</p>
              </div>
            </div>
          </div>

          {progress.current_url && progress.status === 'running' && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <p className="text-xs text-gray-400 mb-1">Currently Scanning</p>
              <code className="text-blue-400 text-sm break-all">{progress.current_url}</code>
            </div>
          )}

          {progress.vulnerabilities?.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
              <h3 className="text-sm font-medium text-gray-400 mb-3">Recent Findings</h3>
              <div className="space-y-2">
                {progress.vulnerabilities.map((v: any, i: number) => (
                  <div key={i} className="flex items-center gap-3 p-2 bg-gray-800/50 rounded-lg">
                    <span className={`w-2 h-2 rounded-full ${
                      v.severity === 'CRITICAL' ? 'bg-red-500' :
                      v.severity === 'HIGH' ? 'bg-orange-500' :
                      v.severity === 'MEDIUM' ? 'bg-yellow-500' :
                      'bg-blue-500'
                    }`} />
                    <span className="text-sm text-gray-300">{v.title}</span>
                    <span className="text-xs text-gray-500 ml-auto">{v.severity}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {logs.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
              <h3 className="text-sm font-medium text-gray-400 mb-3">Activity Log</h3>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {logs.map((log, i) => (
                  <p key={i} className="text-xs text-gray-500 font-mono">{log}</p>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
