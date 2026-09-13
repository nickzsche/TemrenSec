const API_BASE = process.env.NEXT_PUBLIC_API_URL || '/api/v1'

class ApiClient {
  private token: string | null = null

  constructor() {
    if (typeof window !== 'undefined') {
      this.token = localStorage.getItem('temren_token')
    }
  }

  setToken(token: string) {
    this.token = token
    if (typeof window !== 'undefined') {
      localStorage.setItem('temren_token', token)
    }
  }

  clearToken() {
    this.token = null
    if (typeof window !== 'undefined') {
      localStorage.removeItem('temren_token')
      localStorage.removeItem('temren_refresh')
    }
  }

  private async request(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`
    }

    const res = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    })

    if (res.status === 401) {
      this.clearToken()
      if (typeof window !== 'undefined') {
        window.location.href = '/login'
      }
      throw new Error('Unauthorized')
    }

    const data = await res.json()
    if (!res.ok) {
      throw new Error(data.error || 'Request failed')
    }
    return data
  }

  async register(email: string, password: string, fullName: string) {
    const data = await this.request('POST', '/auth/register', { email, password, full_name: fullName })
    if (data.access_token) this.setToken(data.access_token)
    if (data.refresh_token && typeof window !== 'undefined') {
      localStorage.setItem('temren_refresh', data.refresh_token)
    }
    return data
  }

  async login(email: string, password: string, totpCode?: string) {
    const data = await this.request('POST', '/auth/login', { email, password, totp_code: totpCode })
    if (data.access_token) this.setToken(data.access_token)
    if (data.refresh_token && typeof window !== 'undefined') {
      localStorage.setItem('temren_refresh', data.refresh_token)
    }
    return data
  }

  async getMe() { return this.request('GET', '/auth/me') }
  async getDashboard() { return this.request('GET', '/dashboard') }
  async getProjects() { return this.request('GET', '/projects') }
  async createProject(name: string, description: string) { return this.request('POST', '/projects', { name, description }) }
  async deleteProject(id: string) { return this.request('DELETE', `/projects/${id}`) }

  async getTargets(projectId: string) { return this.request('GET', `/projects/${projectId}/targets`) }
  async createTarget(data: { project_id: string; url: string; name: string }) { return this.request('POST', '/targets', data) }
  async deleteTarget(id: string) { return this.request('DELETE', `/targets/${id}`) }

  async startScan(targetId: string, config?: { depth?: number; max_pages?: number }) {
    return this.request('POST', `/targets/${targetId}/scans`, config || {})
  }
  async getScans(targetId: string) { return this.request('GET', `/targets/${targetId}/scans`) }
  async getScan(scanId: string) { return this.request('GET', `/scans/${scanId}`) }
  async getScanVulns(scanId: string, severity?: string) {
    const params = severity ? `?severity=${severity}` : ''
    return this.request('GET', `/scans/${scanId}/vulnerabilities${params}`)
  }
  async getTargetVulns(targetId: string, severity?: string) {
    const params = severity ? `?severity=${severity}` : ''
    return this.request('GET', `/targets/${targetId}/vulnerabilities${params}`)
  }
  async updateVulnStatus(vulnId: string, status: string) {
    return this.request('PATCH', `/vulnerabilities/${vulnId}`, { status })
  }

  async getSchedules() {
    return this.request('GET', '/schedules')
  }

  async createSchedule(data: {
    name: string
    target_url: string
    cron_expr: string
    recurrence: string
    scan_config: Record<string, unknown>
  }) {
    return this.request('POST', '/schedules', data)
  }

  async deleteSchedule(id: string) {
    return this.request('DELETE', `/schedules/${id}`)
  }

  async toggleSchedule(id: string, enabled: boolean) {
    return this.request('PATCH', `/schedules/${id}`, { enabled })
  }

  logout() {
    this.clearToken()
    if (typeof window !== 'undefined') {
      window.location.href = '/login'
    }
  }
}

export const api = new ApiClient()

// authHeader returns the bearer header for pages that call v2 endpoints with a
// raw fetch (the v2 group is auth-gated in the backend). Empty when logged out.
export function authHeader(): Record<string, string> {
  if (typeof window === 'undefined') return {}
  const t = localStorage.getItem('temren_token')
  return t ? { Authorization: `Bearer ${t}` } : {}
}
