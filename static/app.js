// CloudShield - Multi-Tenant SOC Live Controller & AI Engine Manager

let currentCompanyId = 1;
let currentPlan = 'FREE';
let currentApiKey = 'acme_sec_live_9921';
let companiesData = [];

document.addEventListener('DOMContentLoaded', () => {
  loadCompaniesList();
  refreshDashboard();
  // Auto-refresh SOC dashboard metrics and live alerts every 3 seconds
  setInterval(refreshDashboard, 3000);
});

async function loadCompaniesList() {
  try {
    const res = await fetch('/api/companies');
    if (!res.ok) return;
    const data = await res.json();
    companiesData = data.companies || [];
    const select = document.getElementById('tenantSelect');
    if (companiesData.length > 0) {
      select.innerHTML = companiesData.map(c => `
        <option value="${c.id}" ${c.id === currentCompanyId ? 'selected' : ''}>
          ${escapeHtml(c.name)} (${c.plan_name || 'FREE'})
        </option>
      `).join('');
      updateActiveTenantApiKey();
    }
  } catch (err) {
    console.error('Error loading companies:', err);
  }
}

function updateActiveTenantApiKey() {
  const activeComp = companiesData.find(c => c.id === currentCompanyId);
  if (activeComp && activeComp.api_key) {
    currentApiKey = activeComp.api_key;
  } else {
    currentApiKey = 'acme_sec_live_9921';
  }
  const keyEl = document.getElementById('gatewayApiKey');
  if (keyEl) {
    keyEl.textContent = currentApiKey;
  }
}

function changeTenant(companyId) {
  currentCompanyId = parseInt(companyId, 10);
  updateActiveTenantApiKey();
  showToast(`🏢 Switched active tenant context to Company #${currentCompanyId}`);
  refreshDashboard();
}

function copyApiKey() {
  if (!currentApiKey) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(currentApiKey).then(() => {
      showToast(`📋 Copied API Key to clipboard: ${currentApiKey}`);
    }).catch(() => {
      showToast(`Tenant API Key: ${currentApiKey}`);
    });
  } else {
    showToast(`Tenant API Key: ${currentApiKey}`);
  }
}

async function refreshDashboard() {
  await Promise.all([
    fetchMetrics(),
    fetchAlerts(),
    fetchLogs(),
    fetchAiAnomalies()
  ]);
}

// Fetch aggregate SOC metrics for the active tenant
async function fetchMetrics() {
  try {
    const res = await fetch(`/api/admin/metrics?company_id=${currentCompanyId}`);
    if (!res.ok) return;
    const data = await res.json();
    
    currentPlan = (data.plan_name || 'FREE').toUpperCase();
    
    // Update top counter values
    document.getElementById('metricTotalLogs').textContent = data.total_logs.toLocaleString();
    document.getElementById('metricNormalLogs').textContent = data.normal_logs.toLocaleString();
    document.getElementById('metricSuspiciousLogs').textContent = data.suspicious_logs.toLocaleString();
    document.getElementById('metricActiveAlerts').textContent = data.active_alerts.toLocaleString();
    
    // Update Plan Badge in Navbar
    const planBadge = document.getElementById('tenantPlanBadge');
    planBadge.textContent = `${currentPlan} PLAN`;
    planBadge.className = `plan-badge ${currentPlan}`;

    const upgradeBtn = document.getElementById('upgradeNavBtn');
    if (currentPlan === 'FREE') {
      upgradeBtn.style.display = 'inline-flex';
    } else {
      upgradeBtn.style.display = 'none';
    }

    // Active alert badge styling
    const countBadge = document.getElementById('alertCountBadge');
    countBadge.textContent = `${data.active_alerts} ACTIVE`;
    if (data.active_alerts === 0) {
      countBadge.className = 'alert-badge';
      countBadge.style.background = 'rgba(16, 172, 132, 0.15)';
      countBadge.style.color = 'var(--severity-low)';
    } else {
      countBadge.className = 'alert-badge CRITICAL';
    }
  } catch (err) {
    console.error('Error fetching metrics:', err);
  }
}

// Fetch AI Anomaly Detection Engine status & results
async function fetchAiAnomalies() {
  try {
    const res = await fetch(`/api/pro/ai-anomalies?company_id=${currentCompanyId}`);
    const data = await res.json();

    const lockedContainer = document.getElementById('aiLockedContainer');
    const unlockedContainer = document.getElementById('aiUnlockedContainer');
    const tag = document.getElementById('aiPlanStatusTag');

    if (res.status === 403 || data.locked === true) {
      // Locked on Free Plan
      lockedContainer.style.display = 'flex';
      unlockedContainer.style.display = 'none';
      tag.innerHTML = `<span class="plan-badge FREE">LOCKED ON FREE TIER</span>`;
    } else {
      // Unlocked on Pro Plan!
      lockedContainer.style.display = 'none';
      unlockedContainer.style.display = 'block';
      tag.innerHTML = `<span class="plan-badge PROFESSIONAL">⚡ PRO ENGINE ACTIVE</span>`;

      renderAiAnomalies(data.ai_results);
    }
  } catch (err) {
    console.error('Error checking AI anomalies:', err);
  }
}

function renderAiAnomalies(results) {
  const container = document.getElementById('aiAnomalyFeed');
  if (!results || !results.anomaly_records || results.anomaly_records.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; color: var(--text-dim); padding: 2rem; border: 1px dashed var(--border-color); border-radius: 8px;">
        <div style="font-size: 1.8rem; margin-bottom: 0.4rem;">🟢</div>
        <div style="font-weight: 600; color: var(--text-muted);">AI Behavioral Baselines Normal</div>
        <div style="font-size: 0.8rem; margin-top: 0.2rem;">No statistical deviations detected across ${results ? results.total_entities_analyzed : 0} analyzed client entities.</div>
      </div>
    `;
    return;
  }

  container.innerHTML = results.anomaly_records.map(anom => `
    <div class="anomaly-card ${anom.risk_level}">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <span class="score-badge" style="background: rgba(255, 75, 92, 0.2); color: var(--severity-critical);">
          DEV SCORE: ${anom.anomaly_score}
        </span>
        <span class="alert-badge ${anom.risk_level}">${anom.risk_level} RISK</span>
      </div>
      <div style="font-weight: 700; color: #fff; font-size: 0.95rem; margin-bottom: 0.25rem;">
        ${escapeHtml(anom.entity)}
      </div>
      <div style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 0.6rem;">
        <strong>Total Analyzed Events:</strong> ${anom.total_events} requests
      </div>
      <ul style="font-size: 0.78rem; color: var(--text-muted); padding-left: 1.2rem; margin-bottom: 0.75rem;">
        ${anom.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
      </ul>
      <div style="font-size: 0.75rem; color: var(--accent-cyan); font-weight: 600;">
        🛡️ Action: ${escapeHtml(anom.mitigation)}
      </div>
    </div>
  `).join('');
}

// Sandbox Upgrade Simulation
async function simulateUpgrade(planName) {
  const btn = document.getElementById('btnUpgradePro');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Processing Sandbox Payment...';
  }

  showToast(`💳 Initiating simulated payment gateway for ${planName} Plan (₹999)...`);

  setTimeout(async () => {
    try {
      const res = await fetch('/api/subscriptions/upgrade', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          company_id: currentCompanyId,
          plan_name: planName,
          payment_method: 'SANDBOX_MOCK_UPI'
        })
      });

      const data = await res.json();
      if (res.ok) {
        showToast(`🎉 Payment Verified! Upgraded to ${planName} Plan!`);
        closeModal('pricingModal');
        await loadCompaniesList();
        await refreshDashboard();
      } else {
        showToast(`❌ Upgrade failed: ${data.detail}`);
      }
    } catch (err) {
      showToast(`❌ Payment simulation failed`);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = '⚡ Upgrade with Sandbox Pay';
      }
    }
  }, 1200);
}

// Fetch active security alerts
async function fetchAlerts() {
  try {
    const res = await fetch(`/api/admin/alerts?company_id=${currentCompanyId}`);
    if (!res.ok) return;
    const data = await res.json();
    
    const container = document.getElementById('alertFeedContainer');
    if (!data.alerts || data.alerts.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; color: var(--text-dim); padding: 3rem; border: 1px dashed var(--border-color); border-radius: 12px;">
          <div style="font-size: 2rem; margin-bottom: 0.5rem;">🟢</div>
          <div style="font-weight: 600; color: var(--text-muted);">No Active Threats Detected</div>
          <div style="font-size: 0.8rem; margin-top: 0.2rem;">Stream real-time security events using the Live Ingestion Gateway above or run <code>python agent.py --stream</code>.</div>
        </div>
      `;
      return;
    }
    
    container.innerHTML = data.alerts.map(alert => `
      <div class="alert-card ${alert.severity}">
        <div class="alert-header">
          <span class="alert-badge ${alert.severity}">${alert.severity} • ${alert.alert_type}</span>
          <span class="alert-time">${formatTime(alert.timestamp)}</span>
        </div>
        <div class="alert-message">${escapeHtml(alert.message)}</div>
        <div class="alert-meta">
          <span>Source IP: <strong>${escapeHtml(alert.source_ip)}</strong></span>
          ${alert.target_user ? `<span>Target User: <strong>${escapeHtml(alert.target_user)}</strong></span>` : ''}
        </div>
        <div class="alert-actions">
          ${alert.status === 'ACTIVE' ? `
            <button class="btn btn-secondary" style="padding: 0.3rem 0.7rem; font-size: 0.75rem;" onclick="resolveAlert(${alert.id})">
              🛡️ Mitigate & Resolve
            </button>
          ` : `
            <span style="font-size: 0.75rem; color: var(--severity-low); font-weight: 600;">✓ Mitigated & Resolved</span>
          `}
        </div>
      </div>
    `).join('');

  } catch (err) {
    console.error('Error fetching alerts:', err);
  }
}

// Fetch real-time activity audit logs
async function fetchLogs() {
  try {
    const res = await fetch(`/api/admin/logs?company_id=${currentCompanyId}&limit=25`);
    if (!res.ok) return;
    const data = await res.json();
    
    const tbody = document.getElementById('logsTableBody');
    if (!data.logs || data.logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 2rem;">No logs recorded for this tenant</td></tr>`;
      return;
    }

    tbody.innerHTML = data.logs.map(log => `
      <tr>
        <td style="color: var(--text-muted);">${formatTime(log.timestamp)}</td>
        <td style="font-weight: 600;">${escapeHtml(log.action)}</td>
        <td>${escapeHtml(log.username || 'anonymous')}</td>
        <td style="color: var(--accent-cyan);">${escapeHtml(log.ip_address)}</td>
        <td><span class="status-badge ${log.status}">${escapeHtml(log.status)}</span></td>
      </tr>
    `).join('');

  } catch (err) {
    console.error('Error fetching logs:', err);
  }
}

// Real-Time Event Dispatcher Presets
function applyProbePreset(type) {
  if (type === 'brute-force') {
    document.getElementById('liveAction').value = 'LOGIN_FAILED';
    document.getElementById('liveUser').value = 'admin';
    document.getElementById('liveIp').value = '192.168.1.105';
    document.getElementById('liveStatus').value = 'FAILURE';
    document.getElementById('liveDetails').value = 'Authentication failure - rapid credential guessing attempt';
  } else if (type === 'privilege') {
    document.getElementById('liveAction').value = 'UNAUTHORIZED_ACCESS';
    document.getElementById('liveUser').value = 'student_user';
    document.getElementById('liveIp').value = '10.0.4.12';
    document.getElementById('liveStatus').value = 'BLOCKED';
    document.getElementById('liveDetails').value = 'Attempted access to restricted /admin/system-secrets';
  } else if (type === 'tor') {
    document.getElementById('liveAction').value = 'LOGIN_SUCCESS';
    document.getElementById('liveUser').value = 'student_user';
    document.getElementById('liveIp').value = '185.220.101.5';
    document.getElementById('liveStatus').value = 'SUCCESS';
    document.getElementById('liveDetails').value = 'Authentication received through known Tor Exit Node proxy';
  } else if (type === 'normal') {
    document.getElementById('liveAction').value = 'API_REQUEST';
    document.getElementById('liveUser').value = 'alice_dev';
    document.getElementById('liveIp').value = '172.16.0.45';
    document.getElementById('liveStatus').value = 'SUCCESS';
    document.getElementById('liveDetails').value = 'Verified cloud dashboard resource request - HTTP 200';
  }
}

// Dispatches real live event to /api/v1/events
async function handleLiveEventSubmit(event) {
  event.preventDefault();
  const btn = document.getElementById('btnSendLiveEvent');
  const action = document.getElementById('liveAction').value.trim();
  const username = document.getElementById('liveUser').value.trim();
  const ip_address = document.getElementById('liveIp').value.trim();
  const status = document.getElementById('liveStatus').value;
  const details = document.getElementById('liveDetails').value.trim();

  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Dispatching...';
  }

  try {
    const res = await fetch('/api/v1/events', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': currentApiKey
      },
      body: JSON.stringify({
        api_key: currentApiKey,
        action,
        username,
        ip_address,
        status,
        details,
        user_agent: 'CloudShield-WebConsole/2.0'
      })
    });

    const data = await res.json();
    if (res.ok) {
      if (data.alerts_triggered > 0) {
        showToast(`🚨 Event #${data.event_id} Ingested! ⚠️ THREAT DETECTED (${data.alerts_triggered} Alert Triggered)`);
      } else {
        showToast(`✅ Event #${data.event_id} Ingested: ${action} (${status})`);
      }
      refreshDashboard();
    } else {
      showToast(`❌ Ingestion Error: ${data.detail || 'Failed to dispatch'}`);
    }
  } catch (err) {
    showToast(`❌ Network error transmitting event`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🚀 Transmit Event';
    }
  }
}

// Compliance Export Handlers
function exportAuditLogs() {
  showToast(`📥 Preparing compliance CSV export for Tenant #${currentCompanyId}...`);
  window.location.href = `/api/admin/export/logs?company_id=${currentCompanyId}`;
}

function exportIncidentsJson() {
  showToast(`📥 Downloading incident forensic JSON report...`);
  window.open(`/api/admin/export/alerts?company_id=${currentCompanyId}`, '_blank');
}

// Backward-compatible trigger for any programmatic callers
async function triggerSimulation(type) {
  applyProbePreset(type);
  const form = document.getElementById('liveEventForm');
  if (form) {
    form.dispatchEvent(new Event('submit'));
  }
}

// Resolve an alert
async function resolveAlert(alertId) {
  try {
    const res = await fetch(`/api/admin/alerts/${alertId}/resolve`, { method: 'POST' });
    if (res.ok) {
      showToast(`🛡️ Alert #${alertId} mitigated and resolved`);
      refreshDashboard();
    }
  } catch (err) {
    showToast(`❌ Error resolving alert`);
  }
}

// Test User Login Submit
async function handleTestLogin(event) {
  event.preventDefault();
  const username = document.getElementById('loginUsername').value;
  const password = document.getElementById('loginPassword').value;

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, company_id: currentCompanyId })
    });
    const data = await res.json();

    if (res.ok) {
      showToast(`🔓 Welcome ${data.username}! Login successful.`);
      closeModal('authModal');
      refreshDashboard();
    } else {
      showToast(`❌ Login Failed: ${data.detail.message || 'Invalid credentials'}`);
      refreshDashboard();
    }
  } catch (err) {
    showToast(`❌ Error during login attempt`);
  }
}

function handleWrongLogin() {
  document.getElementById('loginPassword').value = 'WrongPassword99!';
  const form = document.getElementById('loginForm');
  form.dispatchEvent(new Event('submit'));
}

// Modal Helpers
function openModal(id) {
  document.getElementById(id).classList.add('active');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('active');
}

// Toast Notifications
function showToast(message) {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.5s ease';
    setTimeout(() => toast.remove(), 500);
  }, 3500);
}

// Helper formatting utilities
function formatTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}


// Onboard New Tenant Company
async function handleCompanyRegister(event) {
  event.preventDefault();
  const company_name = document.getElementById('newCompanyName').value.trim();
  const domain = document.getElementById('newCompanyDomain').value.trim();
  const admin_username = document.getElementById('newCompanyAdminUser').value.trim();
  const admin_email = document.getElementById('newCompanyAdminEmail').value.trim();
  const password = document.getElementById('newCompanyPassword').value;
  const btn = document.getElementById('btnCreateTenant');

  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Provisioning Cloud Tenant...';
  }

  try {
    const res = await fetch('/api/companies/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ company_name, domain, admin_username, admin_email, password })
    });
    const data = await res.json();

    if (res.ok) {
      showToast(`🎉 Organization '${company_name}' provisioned!`);
      closeModal('companyModal');
      document.getElementById('companyRegisterForm').reset();
      
      // Auto-switch to the new company!
      currentCompanyId = data.tenant_data.company_id;
      await loadCompaniesList();
      await refreshDashboard();
    } else {
      showToast(`❌ Onboarding Failed: ${data.detail || 'Could not register organization'}`);
    }
  } catch (err) {
    showToast(`❌ Error creating company tenant`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🚀 Create Tenant & Launch FREE SIEM';
    }
  }
}
