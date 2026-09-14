async function load() {
  const profilesEl = document.getElementById('profiles')
  const tbody = document.querySelector('#findings tbody')
  const countEl = document.getElementById('count')

  try {
    const profiles = await fetch('/api/v1/profiles').then(r => r.json())
    profilesEl.innerHTML = profiles.map(p =>
      `<li><strong>${p.name}</strong> — ${p.description} (${p.scanners.length} scanners)</li>`,
    ).join('')
  } catch (e) {
    profilesEl.innerHTML = '<li>failed to load profiles</li>'
  }

  try {
    const findings = await fetch('/api/v1/findings').then(r => r.json())
    countEl.textContent = (findings || []).length
    tbody.innerHTML = (findings || []).map(f => `
      <tr>
        <td class="sev-${f.Severity}">${f.Severity}</td>
        <td>${f.Scanner || ''}</td>
        <td>${f.Title || ''}</td>
        <td><code>${f.URL || ''}</code></td>
      </tr>
    `).join('')
  } catch (e) {
    countEl.textContent = 'error'
  }
}

load()
setInterval(load, 5000)
