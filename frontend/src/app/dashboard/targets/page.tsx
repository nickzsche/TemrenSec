'use client'

import { useEffect, useState } from 'react'
import { api } from '@/lib/api'

interface Target {
  id: string
  url: string
  name: string
  status: string
  security_score: number
  last_scan_at: string | null
  created_at: string
}

interface Project {
  id: string
  name: string
}

export default function TargetsPage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [targets, setTargets] = useState<Target[]>([])
  const [selectedProject, setSelectedProject] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [newUrl, setNewUrl] = useState('')
  const [newName, setNewName] = useState('')
  const [scanning, setScanning] = useState<string | null>(null)

  useEffect(() => {
    api.getProjects().then((data: any) => {
      const projs = data.projects || []
      setProjects(projs)
      if (projs.length > 0) {
        setSelectedProject(projs[0].id)
      }
    }).catch(console.error)
  }, [])

  useEffect(() => {
    if (!selectedProject) { setLoading(false); return }
    setLoading(true)
    api.getTargets(selectedProject)
      .then((data: any) => setTargets(data.targets || []))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [selectedProject])

  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await api.createTarget({ project_id: selectedProject, url: newUrl, name: newName })
      const data = await api.getTargets(selectedProject)
      setTargets((data as any).targets || [])
      setShowCreate(false)
      setNewUrl('')
      setNewName('')
    } catch (err: any) {
      alert(err.message)
    }
  }

  const handleStartScan = async (targetId: string) => {
    setScanning(targetId)
    try {
      await api.startScan(targetId)
      alert('Scan started!')
    } catch (err: any) {
      alert(err.message)
    } finally {
      setScanning(null)
    }
  }

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-2xl font-bold text-white">Targets</h1>
        <button onClick={() => setShowCreate(true)} disabled={!selectedProject}
          className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium transition">
          Add Target
        </button>
      </div>

      {projects.length > 1 && (
        <div className="mb-6">
          <select value={selectedProject} onChange={e => setSelectedProject(e.target.value)}
            className="bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-lg">
            {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>
      )}

      {showCreate && (
        <form onSubmit={handleCreateTarget} className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-6">
          <h3 className="text-lg font-semibold text-white mb-4">Add New Target</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <input type="text" placeholder="Target URL (e.g., https://example.com)" value={newUrl}
              onChange={e => setNewUrl(e.target.value)} required
              className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
            <input type="text" placeholder="Name (optional)" value={newName}
              onChange={e => setNewName(e.target.value)}
              className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
          </div>
          <div className="flex gap-2">
            <button type="submit" className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm transition">Add</button>
            <button type="button" onClick={() => setShowCreate(false)} className="text-gray-400 px-4 py-2 text-sm">Cancel</button>
          </div>
        </form>
      )}

      {loading ? <p className="text-gray-400">Loading...</p> : (
        <div className="space-y-4">
          {targets.map(t => (
            <div key={t.id} className="bg-gray-900 border border-gray-800 rounded-xl p-5 flex items-center justify-between">
              <div>
                <h3 className="text-white font-medium">{t.name || t.url}</h3>
                <p className="text-sm text-gray-400">{t.url}</p>
                <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                  <span>Status: <span className={t.status === 'active' ? 'text-green-400' : 'text-gray-400'}>{t.status}</span></span>
                  <span>Score: <span className={t.security_score >= 80 ? 'text-green-400' : t.security_score >= 50 ? 'text-yellow-400' : 'text-red-400'}>{t.security_score}/100</span></span>
                  {t.last_scan_at && <span>Last scan: {new Date(t.last_scan_at).toLocaleDateString()}</span>}
                </div>
              </div>
              <button onClick={() => handleStartScan(t.id)} disabled={scanning === t.id}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium transition">
                {scanning === t.id ? 'Starting...' : 'Start Scan'}
              </button>
            </div>
          ))}
          {targets.length === 0 && <p className="text-gray-500 text-center py-8">No targets yet. Add your first target to start scanning.</p>}
        </div>
      )}
    </div>
  )
}
