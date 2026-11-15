'use strict';

/**
 * OBSX Security — Node Operator Dashboard
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the OBSX Source-Available License v1.0 (Zone 2) — See LICENSE file.
 * Free for self-hosted internal use; commercial SaaS hosting and competing extraction prohibited.
 */

(function () {
  const viewLoggedOut = document.getElementById('view-logged-out');
  const viewLoggedIn = document.getElementById('view-logged-in');
  const authStepEmail = document.getElementById('auth-step-email');
  const authStepCode = document.getElementById('auth-step-code');
  const inpEmail = document.getElementById('inp-auth-email');
  const chkAcceptLegal = document.getElementById('chk-accept-legal');
  const inpCode = document.getElementById('inp-auth-code');
  const btnSendCode = document.getElementById('btn-send-code');
  const btnVerifyCode = document.getElementById('btn-verify-code');
  const btnBackEmail = document.getElementById('btn-back-email');
  const btnSignout = document.getElementById('btn-signout');
  const btnTestAlert = document.getElementById('btn-test-alert');
  const btnExportData = document.getElementById('btn-export-data');
  const btnDeleteAccount = document.getElementById('btn-delete-account');
  const dialogDeleteAccount = document.getElementById('dialog-delete-account');
  const btnCancelDeleteAccount = document.getElementById('btn-cancel-delete-account');
  const btnConfirmDeleteAccount = document.getElementById('btn-confirm-delete-account');
  const deleteAccountError = document.getElementById('delete-account-error');
  const authMsg = document.getElementById('auth-msg');

  const userEmailDisplay = document.getElementById('user-email-display');
  const metricTotal = document.getElementById('metric-total');
  const metricAccept = document.getElementById('metric-accept');
  const metricReject = document.getElementById('metric-reject');
  const metricRate = document.getElementById('metric-rate');
  const recentEvents = document.getElementById('recent-events');
  const threatBreakdown = document.getElementById('threat-breakdown');
  const navAuthStatus = document.getElementById('nav-auth-status');

  // Projects & API Credentials Elements
  const btnToggleNewProject = document.getElementById('btn-toggle-new-project');
  const formCreateProject = document.getElementById('form-create-project');
  const btnCancelCreateProject = document.getElementById('btn-cancel-create-project');
  const btnSubmitCreateProject = document.getElementById('btn-submit-create-project');
  const inpNewProjectName = document.getElementById('inp-new-project-name');
  const inpNewProjectOrigins = document.getElementById('inp-new-project-origins');
  const projectsList = document.getElementById('projects-list');
  const projectsCountBadge = document.getElementById('projects-count-badge');
  const keyRevealBanner = document.getElementById('key-reveal-banner');
  const revealSecretKey = document.getElementById('reveal-secret-key');
  const btnCopyRevealedSecret = document.getElementById('btn-copy-revealed-secret');
  const btnDismissKeyReveal = document.getElementById('btn-dismiss-key-reveal');

  // Project-Isolated Telemetry Elements (Option B)
  const selectTelemetryProject = document.getElementById('select-telemetry-project');
  const btnLoadProjectTelemetry = document.getElementById('btn-load-project-telemetry');
  const telemetryAuthBadge = document.getElementById('telemetry-auth-badge');
  const projectEmptyStatusCard = document.getElementById('project-empty-status-card');
  const projectTelemetryContainer = document.getElementById('project-telemetry-container');
  const snippetInstallTag = document.getElementById('snippet-install-tag');
  const btnCopyInstallTag = document.getElementById('btn-copy-install-tag');

  let activeEmail = '';
  let pollingInterval = null;
  let activeTelemetryPid = null;
  let cachedUserProjects = [];

  function showMsg(text, isError = false, devCode = '') {
    if (!authMsg) return;
    authMsg.style.display = 'block';
    authMsg.style.color = isError ? 'var(--bad)' : 'var(--good)';
    if (devCode) {
      authMsg.textContent = text + ' ';
      const strong = document.createElement('strong');
      strong.textContent = devCode;
      authMsg.appendChild(strong);
      return;
    }
    authMsg.textContent = text;
  }

  async function readJsonSafe(res) {
    try {
      const data = await res.json();
      return data && typeof data === 'object' ? data : null;
    } catch {
      return null;
    }
  }

  function extractResponseError(res, data, fallback = 'Request failed') {
    if (data && typeof data === 'object') {
      const msg = data.message || data.error || (data.dispatch && data.dispatch.error) || data.reason;
      if (msg) {
        const codes = Array.isArray(data.reasons)
          ? data.reasons.map((r) => (r && r.code ? String(r.code) : '')).filter(Boolean)
          : [];
        return codes.length ? `${msg} (${codes.join(', ')})` : String(msg);
      }
    }
    return res && Number.isFinite(res.status) && res.status > 0 ? `HTTP ${res.status}` : fallback;
  }

  const operatorBannerState = {
    lastAdvJson: '',
    lastAdvSnapshot: null,
    adapting: false,
    acceptingLicense: false,
    stickyAdaptNotice: false,
    stickyChickensNotice: false,
    adaptStatusText: '',
    licenseStatusText: '',
    bountyStatusText: '',
    diffOpen: false,
    diffContent: '',
  };

  // 1. Check Session State on Load
  async function checkAuth() {
    try {
      const res = await fetch('/api/v1/me');
      const data = await readJsonSafe(res);
      if (res.ok && data && data.ok && data.user) {
        renderLoggedIn(data.user, data);
      } else {
        renderLoggedOut();
      }
    } catch (err) {
      console.error('Session check failed:', err);
      renderLoggedOut();
    }
  }

  function renderLoggedIn(user, meData) {
    if (viewLoggedOut) viewLoggedOut.style.display = 'none';
    if (viewLoggedIn) viewLoggedIn.style.display = 'block';
    if (userEmailDisplay) userEmailDisplay.textContent = user.email;
    if (navAuthStatus) {
      navAuthStatus.innerHTML = `<span class="badge badge-good" style="margin-left: 8px;">Operator: ${escapeHtml(String(user.email || '').split('@')[0])}</span>`;
    }

    renderOperatorDriftBanner(meData && meData.upstreamAdvisory ? meData.upstreamAdvisory : null);
    loadProjects();
    startTelemetryPolling();
  }

  function renderLoggedOut() {
    operatorBannerState.stickyAdaptNotice = false;
    operatorBannerState.stickyChickensNotice = false;
    operatorBannerState.lastAdvSnapshot = null;
    operatorBannerState.lastAdvJson = '';
    if (viewLoggedOut) viewLoggedOut.style.display = 'block';
    if (viewLoggedIn) viewLoggedIn.style.display = 'none';
    if (authStepEmail) authStepEmail.style.display = 'flex';
    if (authStepCode) authStepCode.style.display = 'none';
    if (navAuthStatus) navAuthStatus.innerHTML = '';
    if (keyRevealBanner) keyRevealBanner.style.display = 'none';
    if (pollingInterval) clearInterval(pollingInterval);
  }

  // --- Projects & API Credentials Management ---
  function showRevealedKey(secretKey) {
    if (!keyRevealBanner || !revealSecretKey) return;
    revealSecretKey.textContent = secretKey;
    keyRevealBanner.style.display = 'block';
    keyRevealBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  btnDismissKeyReveal?.addEventListener('click', () => {
    if (keyRevealBanner) keyRevealBanner.style.display = 'none';
  });

  btnCopyRevealedSecret?.addEventListener('click', async () => {
    if (!revealSecretKey) return;
    const text = revealSecretKey.textContent || '';
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      const prev = btnCopyRevealedSecret.textContent;
      btnCopyRevealedSecret.textContent = 'Copied!';
      setTimeout(() => { btnCopyRevealedSecret.textContent = prev; }, 1800);
    } catch {
      prompt('Copy secret key manually:', text);
    }
  });

  btnToggleNewProject?.addEventListener('click', () => {
    if (!formCreateProject) return;
    const isHidden = formCreateProject.style.display === 'none';
    formCreateProject.style.display = isHidden ? 'block' : 'none';
    if (isHidden && inpNewProjectName) {
      inpNewProjectName.focus();
    }
  });

  btnCancelCreateProject?.addEventListener('click', () => {
    if (formCreateProject) formCreateProject.style.display = 'none';
  });

  btnSubmitCreateProject?.addEventListener('click', async () => {
    const name = (inpNewProjectName ? inpNewProjectName.value : '').trim();
    if (!name) {
      alert('Please enter a project name.');
      return;
    }
    const rawOrigins = (inpNewProjectOrigins ? inpNewProjectOrigins.value : '').trim();
    const origins = rawOrigins ? rawOrigins.split(',').map((s) => s.trim()).filter(Boolean) : [];

    btnSubmitCreateProject.disabled = true;
    btnSubmitCreateProject.textContent = 'Attesting & creating...';

    const { token, nonce } = await harvestAttestation();

    try {
      const res = await fetch('/api/v1/project', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, origins, token, nonce }),
      });
      const data = await readJsonSafe(res);
      if (res.ok && data && data.ok && data.project) {
        if (formCreateProject) formCreateProject.style.display = 'none';
        if (inpNewProjectName) inpNewProjectName.value = '';
        if (inpNewProjectOrigins) inpNewProjectOrigins.value = '';
        showRevealedKey(data.project.secretKey);
        await loadProjects();
      } else {
        alert('Failed to create project: ' + extractResponseError(res, data));
      }
    } catch (err) {
      alert('Error creating project: ' + err.message);
    } finally {
      btnSubmitCreateProject.disabled = false;
      btnSubmitCreateProject.textContent = 'Create & Generate Keys';
    }
  });

  async function loadProjects() {
    if (!projectsList) return;
    try {
      const res = await fetch('/api/v1/projects');
      const data = await readJsonSafe(res);
      if (!res.ok || !data || !data.ok || !Array.isArray(data.projects)) {
        projectsList.innerHTML = '<p style="color:var(--text-muted); font-size:13px;">Unable to load projects.</p>';
        return;
      }

      const projs = data.projects;
      if (projectsCountBadge) {
        projectsCountBadge.textContent = `${projs.length} Project${projs.length === 1 ? '' : 's'}`;
      }

      if (projs.length === 0) {
        projectsList.innerHTML = `
          <div style="padding: 24px; text-align: center; background: var(--bg-card-subtle); border-radius: var(--radius-sm); border: 1px dashed var(--border);">
            <p style="color: var(--text-muted); font-size: 13.5px; margin-bottom: 12px;">You have no custom projects registered yet. Create your first project to receive production site keys (<code>pk_live_...</code>) and server secrets (<code>sk_live_...</code>).</p>
            <button type="button" class="btn btn-primary" id="btn-create-first-project" style="font-size: 13px;">+ Create First Project</button>
          </div>
        `;
        document.getElementById('btn-create-first-project')?.addEventListener('click', () => {
          if (formCreateProject) {
            formCreateProject.style.display = 'block';
            inpNewProjectName?.focus();
          }
        });
        return;
      }

      projectsList.innerHTML = projs.map((p) => {
        const createdDate = new Date(p.created || Date.now()).toLocaleDateString();
        const isPassive = p.settings && p.settings.mode === 'passive';
        const rawSnippet = isPassive
          ? `<script src="https://obsx.tech/obsx.min.js" data-obsx-site="${p.publicKey}" data-obsx-mode="passive"></script>`
          : `<script src="https://obsx.tech/obsx.min.js" data-obsx-site="${p.publicKey}"></script>`;

        return `
          <div class="card" style="padding: 18px 20px; background: var(--bg-card-subtle); border: 1px solid var(--border); border-radius: var(--radius-sm);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
              <div>
                <strong style="font-size: 15px; color: var(--text);">${escapeHtml(p.name)}</strong>
                <code style="margin-left: 8px; font-size: 11.5px; color: var(--text-muted); background: var(--bg); padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border);">${escapeHtml(p.pid)}</code>
                <span style="font-size: 11.5px; color: var(--text-muted); margin-left: 8px;">Created ${escapeHtml(createdDate)}</span>
              </div>
              <div style="display: flex; gap: 8px;">
                <button type="button" class="btn btn-secondary btn-rotate-sk" data-pid="${escapeHtml(p.pid)}" style="font-size: 11.5px; padding: 4px 10px;">Rotate Secret Key</button>
                <button type="button" class="btn btn-secondary btn-delete-proj" data-pid="${escapeHtml(p.pid)}" data-name="${escapeHtml(p.name)}" style="font-size: 11.5px; padding: 4px 10px; color: var(--bad);">Delete</button>
              </div>
            </div>

            <!-- Public Key (Client SDK) -->
            <div style="margin-bottom: 10px;">
              <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">Public Site Key (Client SDK)</div>
              <div style="display: flex; gap: 8px; align-items: center;">
                <input type="text" readonly value="${escapeHtml(p.publicKey)}" class="form-input" style="flex: 1; font-family: var(--font-mono); font-size: 12px; padding: 6px 10px; margin-bottom: 0;" />
                <button type="button" class="btn btn-copy btn-copy-inline" data-copy="${escapeHtml(p.publicKey)}">Copy Key</button>
              </div>
            </div>

            <!-- Secret Verification Key -->
            <div style="margin-bottom: 10px;">
              <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">Secret Verification Key (Backend API)</div>
              <div style="display: flex; gap: 8px; align-items: center;">
                <input type="text" readonly value="sk_••••••••••••••••••••••••••••••••" class="form-input" style="flex: 1; font-family: var(--font-mono); font-size: 12px; padding: 6px 10px; margin-bottom: 0; color: var(--text-muted);" />
                <button type="button" class="btn btn-secondary btn-rotate-inline" data-pid="${escapeHtml(p.pid)}" style="font-size: 11.5px; padding: 4px 10px;">Rotate</button>
              </div>
            </div>

            <!-- Client Script Embed Snippet -->
            <div>
              <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">Frontend Embed Tag</div>
              <div style="display: flex; gap: 8px; align-items: center;">
                <input type="text" readonly value="${escapeHtml(rawSnippet)}" class="form-input" style="flex: 1; font-family: var(--font-mono); font-size: 11.5px; padding: 6px 10px; margin-bottom: 0;" />
                <button type="button" class="btn btn-copy btn-copy-inline" data-copy="${escapeHtml(rawSnippet)}">Copy Tag</button>
              </div>
            </div>

            <!-- Operational Gate Mode (Enforce vs Passive) -->
            <div style="margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
              <div>
                <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Operational Gate Mode</div>
                <div style="display: flex; align-items: center; gap: 8px; margin-top: 3px;">
                  <span class="badge ${isPassive ? 'badge-warn' : 'badge-good'}" id="mode-badge-${escapeHtml(p.pid)}">
                    ${isPassive ? '○ Passive (Audit / Observability)' : '● Enforcing (Active Cryptographic Gate)'}
                  </span>
                  <span style="font-size: 11.5px; color: var(--text-muted);">
                    ${isPassive ? 'Telemetry audited; zero requests blocked' : 'Hostile traffic blocked at edge'}
                  </span>
                </div>
              </div>
              <div>
                <button type="button" class="btn btn-secondary btn-toggle-mode" data-pid="${escapeHtml(p.pid)}" data-mode="${isPassive ? 'passive' : 'enforce'}" style="font-size: 11.5px; padding: 4px 10px;">
                  ${isPassive ? 'Switch to Enforce' : 'Switch to Passive'}
                </button>
              </div>
            </div>

            <!-- Autonomous Vector Circuit Breaker -->
            <div style="margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
              <div>
                <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Autonomous Vector Circuit Breaker</div>
                <div style="display: flex; align-items: center; gap: 8px; margin-top: 3px;">
                  <span class="badge ${p.settings && p.settings.adaptiveCircuitBreaker ? 'badge-good' : 'badge-secondary'}" id="cb-badge-${escapeHtml(p.pid)}">
                    ${p.settings && p.settings.adaptiveCircuitBreaker ? '● Active (Auto-Shedding)' : '○ Inactive (Off by default)'}
                  </span>
                  <span id="cb-details-${escapeHtml(p.pid)}" style="font-size: 11.5px; color: var(--text-muted);"></span>
                </div>
              </div>
              <div style="display: flex; gap: 8px;">
                <button type="button" class="btn btn-secondary btn-toggle-cb" data-pid="${escapeHtml(p.pid)}" data-enabled="${p.settings && p.settings.adaptiveCircuitBreaker ? 'true' : 'false'}" style="font-size: 11.5px; padding: 4px 10px;">
                  ${p.settings && p.settings.adaptiveCircuitBreaker ? 'Disable' : 'Enable'}
                </button>
                <button type="button" class="btn btn-secondary btn-reset-cb" data-pid="${escapeHtml(p.pid)}" id="btn-reset-cb-${escapeHtml(p.pid)}" style="font-size: 11.5px; padding: 4px 10px; display: none;">
                  Reset Vectors
                </button>
              </div>
            </div>

            <!-- Automated AI Crawler Policy -->
            <div style="margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
              <div>
                <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Automated AI Crawler Access Policy</div>
                <div style="display: flex; align-items: center; gap: 8px; margin-top: 3px; flex-wrap: wrap;">
                  <span class="badge ${(p.settings && p.settings.blockOpenAiScrapers !== false) ? 'badge-good' : 'badge-secondary'}">
                    ${(p.settings && p.settings.blockOpenAiScrapers !== false) ? '● Blocking Automated AI Crawlers' : '○ Allowed'}
                  </span>
                </div>
              </div>
              <div>
                <button type="button" class="btn btn-secondary btn-toggle-openai" data-pid="${escapeHtml(p.pid)}" data-enabled="${(p.settings && p.settings.blockOpenAiScrapers !== false) ? 'true' : 'false'}" style="font-size: 11.5px; padding: 4px 10px;">
                  ${(p.settings && p.settings.blockOpenAiScrapers !== false) ? 'Allow AI Crawlers' : 'Block AI Crawlers'}
                </button>
              </div>
            </div>
          </div>
        `;
      }).join('');

      // Wire up inline buttons
      projectsList.querySelectorAll('.btn-copy-inline').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const text = btn.getAttribute('data-copy');
          if (!text) return;
          try {
            await navigator.clipboard.writeText(text);
            const orig = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = orig; }, 1800);
          } catch {
            prompt('Copy text:', text);
          }
        });
      });

      projectsList.querySelectorAll('.btn-rotate-sk, .btn-rotate-inline').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const pid = btn.getAttribute('data-pid');
          if (!pid) return;
          if (!confirm(`Are you sure you want to rotate the secret verification key for project ${pid}?\n\nThe existing secret key will be immediately revoked.`)) {
            return;
          }
          btn.disabled = true;
          const orig = btn.textContent;
          btn.textContent = 'Attesting & rotating...';
          const { token, nonce } = await harvestAttestation();
          try {
            const res = await fetch(`/api/v1/project/${pid}/rotate-key`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ token, nonce }),
            });
            const data = await readJsonSafe(res);
            if (res.ok && data && data.ok && data.secretKey) {
              showRevealedKey(data.secretKey);
            } else {
              alert('Key rotation failed: ' + extractResponseError(res, data));
            }
          } catch (err) {
            alert('Error rotating key: ' + err.message);
          } finally {
            btn.disabled = false;
            btn.textContent = orig;
          }
        });
      });

      function bindProjectMutation(selector, { buildRequest, failurePrefix, errorPrefix, confirmAction }) {
        projectsList.querySelectorAll(selector).forEach((btn) => {
          btn.addEventListener('click', async () => {
            const pid = btn.getAttribute('data-pid');
            if (!pid) return;
            if (confirmAction && !confirmAction(btn, pid)) return;
            btn.disabled = true;
            const { token, nonce } = await harvestAttestation();
            try {
              const { url, init } = buildRequest(btn, pid, { token, nonce });
              const res = await fetch(url, init);
              const data = await readJsonSafe(res);
              if (res.ok && data && data.ok) {
                await loadProjects();
              } else {
                alert(`${failurePrefix}: ` + extractResponseError(res, data));
                btn.disabled = false;
              }
            } catch (err) {
              alert(`${errorPrefix}: ` + err.message);
              btn.disabled = false;
            }
          });
        });
      }

      bindProjectMutation('.btn-delete-proj', {
        confirmAction: (btn, pid) => {
          const name = btn.getAttribute('data-name');
          return confirm(`Are you sure you want to permanently delete "${name}" (${pid})?\n\nAll client requests using this site key will immediately be blocked.`);
        },
        buildRequest: (_btn, pid, { token, nonce }) => ({
          url: `/api/v1/project/${pid}`,
          init: {
            method: 'DELETE',
            headers: {
              'Content-Type': 'application/json',
              'X-OBSX-Token': token || '',
              'X-OBSX-Nonce': nonce || '',
            },
            body: JSON.stringify({ token, nonce }),
          },
        }),
        failurePrefix: 'Failed to delete project',
        errorPrefix: 'Error deleting project',
      });

      // Operational Gate Mode Toggle (Enforce vs Passive)
      bindProjectMutation('.btn-toggle-mode', {
        buildRequest: (btn, pid, { token, nonce }) => ({
          url: `/api/v1/project/${pid}/settings`,
          init: {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              mode: btn.getAttribute('data-mode') === 'passive' ? 'enforce' : 'passive',
              token,
              nonce,
            }),
          },
        }),
        failurePrefix: 'Failed to update mode',
        errorPrefix: 'Error updating mode',
      });

      // Circuit Breaker Toggle & Reset Handlers
      bindProjectMutation('.btn-toggle-cb', {
        buildRequest: (btn, pid, { token, nonce }) => ({
          url: `/api/v1/project/${pid}/settings`,
          init: {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              adaptiveCircuitBreaker: btn.getAttribute('data-enabled') !== 'true',
              token,
              nonce,
            }),
          },
        }),
        failurePrefix: 'Failed to update circuit breaker',
        errorPrefix: 'Error updating circuit breaker',
      });

      bindProjectMutation('.btn-toggle-openai', {
        buildRequest: (btn, pid, { token, nonce }) => ({
          url: `/api/v1/project/${pid}/settings`,
          init: {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              blockOpenAiScrapers: btn.getAttribute('data-enabled') !== 'true',
              token,
              nonce,
            }),
          },
        }),
        failurePrefix: 'Failed to update OpenAI scraper setting',
        errorPrefix: 'Error updating OpenAI scraper setting',
      });

      bindProjectMutation('.btn-reset-cb', {
        buildRequest: (_btn, pid, { token, nonce }) => ({
          url: `/api/v1/project/${pid}/circuit-breaker/reset`,
          init: {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, nonce }),
          },
        }),
        failurePrefix: 'Reset failed',
        errorPrefix: 'Error resetting vectors',
      });

      // Display managed cloud note for circuit breaker
      projs.forEach((p) => {
        const detailsSpan = document.getElementById(`cb-details-${p.pid}`);
        const resetBtn = document.getElementById(`btn-reset-cb-${p.pid}`);
        if (detailsSpan) {
          detailsSpan.innerHTML = `<span style="color:var(--text-muted); font-size:11px;">(Managed cloud capability on obsx.tech)</span>`;
        }
        if (resetBtn) resetBtn.style.display = 'none';
      });

      // Synchronize Guarded Project Selector (Option B)
      cachedUserProjects = projs;
      if (selectTelemetryProject) {
        const prev = selectTelemetryProject.value;
        if (cachedUserProjects.length === 0) {
          selectTelemetryProject.innerHTML = '<option value="">No projects created yet</option>';
          if (projectEmptyStatusCard) projectEmptyStatusCard.style.display = 'none';
          if (projectTelemetryContainer) projectTelemetryContainer.style.display = 'none';
        } else {
          selectTelemetryProject.innerHTML = cachedUserProjects.map((p) => `
            <option value="${escapeHtml(p.pid)}" ${p.pid === (prev || activeTelemetryPid) ? 'selected' : ''}>
              ${escapeHtml(p.name || 'Untitled')} (${escapeHtml(p.publicKey)})
            </option>
          `).join('');

          const exists = cachedUserProjects.some((p) => p.pid === activeTelemetryPid);
          if (!activeTelemetryPid || !exists) {
            activeTelemetryPid = cachedUserProjects[0].pid;
            selectTelemetryProject.value = activeTelemetryPid;
          }
          loadProjectTelemetry(activeTelemetryPid, false);
        }
      }
    } catch (err) {
      console.warn('Projects fetch error:', err);
      projectsList.innerHTML = '<p style="color:var(--bad); font-size:13px;">Error loading projects.</p>';
    }
  }

  async function harvestAttestation(opts = {}) {
    if (!window.OBSX) return { token: null, nonce: null };
    try {
      // Reuse the session warmed at page load (its age satisfies the minimum
      // human-duration check); only force a new handshake when retrying a stale one.
      const att = await window.OBSX.getAttestation(opts.fresh ? { fresh: true } : {});
      return { token: att.token || null, nonce: att.nonce || null };
    } catch (e) {
      console.warn('[Auth Attestation]', e);
      return { token: null, nonce: null };
    }
  }

  // POST /api/v1/auth/email with the warmed attestation; if the gate says the
  // session itself was stale (expired / replayed / missing), retry once with a new handshake.
  async function authEmailRequest(body) {
    let last = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const { token, nonce } = await harvestAttestation({ fresh: attempt > 0 });
      const res = await fetch('/api/v1/auth/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...body, token, nonce }),
      });
      const data = await readJsonSafe(res);
      last = { res, data };
      const ok = res.ok && data && data.ok;
      const stale = !ok && data && Array.isArray(data.reasons) &&
        data.reasons.some((r) => r && ['invalid_token', 'token_reused', 'expired', 'missing_token'].includes(r.code));
      if (ok || !stale) return last;
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
    return last;
  }

  // 2. Request OTP Code
  chkAcceptLegal?.addEventListener('change', () => {
    chkAcceptLegal.setAttribute('aria-invalid', chkAcceptLegal.checked ? 'false' : 'true');
  });

  if (authStepEmail) {
    authStepEmail.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = (inpEmail ? inpEmail.value : '').trim();
      if (!email || !email.includes('@')) {
        inpEmail?.focus();
        return showMsg('Please enter a valid operator email address.', true);
      }
      if (chkAcceptLegal && !chkAcceptLegal.checked) {
        chkAcceptLegal.setAttribute('aria-invalid', 'true');
        chkAcceptLegal.focus();
        return showMsg('Please accept the Terms of Service and Privacy Policy to continue.', true);
      }
      activeEmail = email;
      if (btnSendCode) {
        btnSendCode.disabled = true;
        btnSendCode.textContent = 'Attesting & sending code...';
      }

      try {
        const { res, data } = await authEmailRequest({
          email,
          action: 'start',
          termsAccepted: Boolean(!chkAcceptLegal || chkAcceptLegal.checked),
        });

        if (res.ok && data && data.ok) {
          authStepEmail.style.display = 'none';
          authStepCode.style.display = 'flex';
          if (inpCode) {
            inpCode.value = '';
            inpCode.focus();
          }

          if (data.devMode && data.devCode) {
            showMsg('Verification code generated! Dev/Test mode code:', false, data.devCode);
          } else {
            showMsg('Verification code sent to your email!', false);
          }
        } else {
          showMsg(extractResponseError(res, data, 'Failed to dispatch verification code.'), true);
        }
      } catch (err) {
        showMsg('Network error requesting code: ' + err.message, true);
      } finally {
        if (btnSendCode) {
          btnSendCode.disabled = false;
          btnSendCode.textContent = 'Send Verification Code';
        }
      }
    });
  }

  // 3. Verify OTP Code
  if (authStepCode) {
    authStepCode.addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = (inpCode ? inpCode.value : '').trim();
      if (!code || code.length < 6) {
        inpCode?.focus();
        return showMsg('Please enter the 6-digit one-time code.', true);
      }

      if (btnVerifyCode) {
        btnVerifyCode.disabled = true;
        btnVerifyCode.textContent = 'Attesting & verifying...';
      }

      try {
        const { res, data } = await authEmailRequest({
          action: 'verify',
          email: activeEmail,
          code,
          termsAccepted: Boolean(!chkAcceptLegal || chkAcceptLegal.checked),
        });

        if (res.ok && data && data.ok) {
          showMsg('Verified successfully! Accessing node dashboard...', false);
          setTimeout(() => {
            checkAuth();
          }, 300);
        } else {
          showMsg(extractResponseError(res, data, 'Invalid or expired code.'), true);
        }
      } catch (err) {
        showMsg('Verification failed: ' + err.message, true);
      } finally {
        if (btnVerifyCode) {
          btnVerifyCode.disabled = false;
          btnVerifyCode.textContent = 'Verify & Enter';
        }
      }
    });
  }

  // 4. Back Button
  if (btnBackEmail) {
    btnBackEmail.addEventListener('click', () => {
      authStepEmail.style.display = 'flex';
      authStepCode.style.display = 'none';
      if (authMsg) authMsg.style.display = 'none';
    });
  }

  // 5. Sign Out
  if (btnSignout) {
    btnSignout.addEventListener('click', async () => {
      try {
        await fetch('/api/v1/auth/logout', { method: 'POST' });
        renderLoggedOut();
      } catch (err) {
        console.error('Logout error:', err);
      }
    });
  }

  // 5b. Data Portability Export (GDPR Art. 20 / CCPA Right to Know)
  if (btnExportData) {
    btnExportData.addEventListener('click', async () => {
      btnExportData.disabled = true;
      btnExportData.textContent = 'Exporting...';
      try {
        const res = await fetch('/api/v1/me/export');
        const data = await readJsonSafe(res);
        if (!res.ok || !data || !data.ok) {
          alert('Export failed: ' + extractResponseError(res, data));
          return;
        }
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'obsx-data-export.json';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      } catch (err) {
        alert('Export error: ' + err.message);
      } finally {
        btnExportData.disabled = false;
        btnExportData.textContent = 'Export My Data';
      }
    });
  }

  // 5c. Account Deletion Modal (GDPR Art. 17 / CCPA Delete)
  if (btnDeleteAccount && dialogDeleteAccount) {
    btnDeleteAccount.addEventListener('click', () => {
      if (deleteAccountError) {
        deleteAccountError.style.display = 'none';
        deleteAccountError.textContent = '';
      }
      dialogDeleteAccount.showModal();
    });
  }

  if (btnCancelDeleteAccount && dialogDeleteAccount) {
    btnCancelDeleteAccount.addEventListener('click', () => {
      dialogDeleteAccount.close();
    });
  }

  if (btnConfirmDeleteAccount && dialogDeleteAccount) {
    btnConfirmDeleteAccount.addEventListener('click', async () => {
      btnConfirmDeleteAccount.disabled = true;
      btnConfirmDeleteAccount.textContent = 'Deleting...';
      try {
        const res = await fetch('/api/v1/me', { method: 'DELETE' });
        const data = await readJsonSafe(res);
        if (!res.ok || !data || !data.ok) {
          if (deleteAccountError) {
            deleteAccountError.textContent = 'Deletion failed: ' + extractResponseError(res, data);
            deleteAccountError.style.display = 'block';
          }
          return;
        }
        dialogDeleteAccount.close();
        renderLoggedOut();
      } catch (err) {
        if (deleteAccountError) {
          deleteAccountError.textContent = 'Deletion error: ' + err.message;
          deleteAccountError.style.display = 'block';
        }
      } finally {
        btnConfirmDeleteAccount.disabled = false;
        btnConfirmDeleteAccount.textContent = 'Permanently Delete';
      }
    });
  }

  async function dispatchTestAlertRequest(button, { idleLabel, loadingLabel, recipient = '' }) {
    if (!button) return;
    button.disabled = true;
    button.textContent = loadingLabel;
    try {
      const { token, nonce } = await harvestAttestation();
      const res = await fetch('/api/v1/alert/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient, token, nonce }),
      });
      const data = await readJsonSafe(res);
      if (res.ok && data && data.ok) {
        alert(data.throttled
          ? 'Alert recorded, but throttled by 5-minute circuit breaker to protect operator inbox!'
          : `Critical security advisory dispatched successfully to ${data.alert?.recipient || 'operator'}!`);
        fetchAlertsHistory();
      } else {
        alert('Alert dispatch failed: ' + extractResponseError(res, data));
      }
    } catch (err) {
      alert('Alert test error: ' + err.message);
    } finally {
      button.disabled = false;
      button.textContent = idleLabel;
    }
  }

  // 6. Test Security Alert Dispatch
  if (btnTestAlert) {
    btnTestAlert.addEventListener('click', () => {
      dispatchTestAlertRequest(btnTestAlert, {
        idleLabel: 'Send Test Alert',
        loadingLabel: 'Attesting & sending...',
      });
    });
  }

  function triggerFileDownload(filename, content, mimeType) {
    try {
      if (typeof Blob !== 'function' || typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') {
        return false;
      }
      const blob = new Blob([content], { type: mimeType || 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      if (link.style) link.style.display = 'none';
      if (document.body && typeof document.body.appendChild === 'function') {
        document.body.appendChild(link);
      }
      if (typeof link.click === 'function') link.click();
      setTimeout(() => {
        if (typeof link.remove === 'function') link.remove();
        else if (link.parentNode && typeof link.parentNode.removeChild === 'function') {
          link.parentNode.removeChild(link);
        }
        if (typeof URL.revokeObjectURL === 'function') URL.revokeObjectURL(url);
      }, 1000);
      return true;
    } catch (_) {
      return false;
    }
  }

  function buildDiagnosticPayload(advSnapshot) {
    const snap = advSnapshot && typeof advSnapshot === 'object'
      ? advSnapshot
      : (operatorBannerState.lastAdvSnapshot || {});
    const lic = snap.licenseStatus && typeof snap.licenseStatus === 'object' ? snap.licenseStatus : {};
    return {
      generatedAt: new Date().toISOString(),
      product: 'OBSX Security Engine',
      mascot: 'Opi (Sec) the Chicken',
      version: String(snap.version || '2.2.0+'),
      edition: String(snap.edition || 'official'),
      commit: String(snap.localCommit || 'local'),
      platform: (typeof navigator !== 'undefined' && navigator.platform) ? String(navigator.platform) : 'unknown',
      userAgent: (typeof navigator !== 'undefined' && navigator.userAgent) ? String(navigator.userAgent) : 'unknown',
      licenseStatus: {
        accepted: Boolean(lic.accepted),
        acceptedVia: lic.acceptedVia || null,
        licenseChanged: Boolean(lic.licenseChanged),
        treeChanged: Boolean(lic.treeChanged),
        safeMode: Boolean(lic.safeMode),
        safeModeReason: lic.safeModeReason || null,
        licenseSha256: lic.licenseSha256 || null,
        treeFingerprint: lic.treeFingerprint || null,
        missingCriticalFiles: Array.isArray(lic.missingCriticalFiles) ? lic.missingCriticalFiles.slice(0, 20) : [],
      },
      locallyModifiedFiles: Array.isArray(snap.locallyModifiedFiles) ? snap.locallyModifiedFiles.slice(0, 50) : [],
    };
  }

  function buildBugReportTemplate(diag) {
    const ls = diag.licenseStatus || {};
    const modList = diag.locallyModifiedFiles && diag.locallyModifiedFiles.length
      ? diag.locallyModifiedFiles.join(', ')
      : 'None';
    return [
      '====================================================================',
      'OBSX.TECH — PRE-FILLED BUG & EDGE-CASE REPORT',
      'Mascot: Opi (Sec) the Chicken  |  Contact: security@obsx.tech',
      '====================================================================',
      '',
      'Thank you for helping the chickens at obsx.tech! If we verify your bug,',
      'your name or preferred handle goes directly on the git commit & site,',
      'plus permanent free access to Sentinel cloud node on your own machine',
      '(please do not share it—the chicken here at obsx.tech worked hard on it!).',
      '',
      '--- AUTO-FILLED DIAGNOSTICS (DO NOT REMOVE) ---',
      `Reported At:       ${diag.generatedAt}`,
      `OBSX Release:      v${diag.version}`,
      `Git Commit:        ${diag.commit}`,
      `Node Edition:      ${diag.edition}`,
      `Platform / UA:     ${diag.platform} | ${diag.userAgent}`,
      `License SHA-256:   ${ls.licenseSha256 || 'unavailable'}`,
      `Tree Fingerprint:  ${ls.treeFingerprint || 'unavailable'}`,
      `License Accepted:  ${ls.accepted ? `yes (${ls.acceptedVia || 'operator'})` : 'no'}`,
      `Safe Mode State:   ${ls.safeMode ? `active (${ls.safeModeReason || 'unknown'})` : 'inactive'}`,
      `Modified Files:    ${modList}`,
      '----------------------------------------------',
      '',
      'Name or Handle (for Git Commit & Site Attribution): [optional]',
      'Sentinel Machine / Node Identifier (for Bounty):    [optional]',
      '',
      '1. SUMMARY OF WHAT YOU WERE TESTING OR EXPERIMENTING WITH:',
      '   [Describe the edge case, custom modification, or bug here]',
      '',
      '2. STEPS TO REPRODUCE:',
      '   1) ...',
      '   2) ...',
      '',
      '3. EXPECTED VS. ACTUAL BEHAVIOR:',
      '   Expected: ...',
      '   Actual:   ...',
      '',
      '4. ATTACHED DIAGNOSTICS:',
      '   Please also attach obsx-diagnostics.json if exported.',
      '',
    ].join('\n');
  }

  function buildSecurityMailtoHref(subject, diag) {
    const ls = diag.licenseStatus || {};
    const body = [
      'Hello Opi (Sec) and the chickens at obsx.tech,',
      '',
      `Node Release: v${diag.version} (${diag.commit})`,
      `Edition: ${diag.edition}`,
      `Safe Mode: ${ls.safeMode ? (ls.safeModeReason || 'active') : 'inactive'}`,
      `License SHA-256: ${ls.licenseSha256 || 'n/a'}`,
      `Tree Fingerprint: ${ls.treeFingerprint || 'n/a'}`,
      '',
      'Details about what I was testing / encountered:',
      '',
    ].join('\n');
    return `mailto:security@obsx.tech?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  }

  function syncBannerFeedbackAndDiff() {
    const adaptFeedback = document.getElementById('operator-adapt-feedback');
    if (adaptFeedback) adaptFeedback.textContent = operatorBannerState.adaptStatusText;
    const licFeedback = document.getElementById('operator-license-feedback');
    if (licFeedback) licFeedback.textContent = operatorBannerState.licenseStatusText;
    const bountyFeedback = document.getElementById('operator-bounty-feedback');
    if (bountyFeedback) bountyFeedback.textContent = operatorBannerState.bountyStatusText;
    const btnDiff = document.getElementById('btn-view-upstream-diff');
    const diffView = document.getElementById('operator-upstream-diff-view');
    if (btnDiff && diffView) {
      diffView.textContent = operatorBannerState.diffContent;
      diffView.style.display = operatorBannerState.diffOpen ? 'block' : 'none';
      btnDiff.textContent = operatorBannerState.diffOpen ? 'Hide Upstream Diff' : 'View Upstream Diff';
    }
  }

  function renderOperatorDriftBanner(adv) {
    if (adv && typeof adv === 'object' && (adv.version || adv.edition || adv.licenseStatus || adv.localCommit)) {
      const prevSnap = operatorBannerState.lastAdvSnapshot || {};
      operatorBannerState.lastAdvSnapshot = {
        ...prevSnap,
        ...adv,
        licenseStatus: {
          ...(prevSnap.licenseStatus || {}),
          ...(adv.licenseStatus || {}),
        },
      };
    }

    let driftBanner = document.getElementById('operator-drift-advisory-banner');
    const hasReminder = Boolean(adv && adv.showReminder);
    if (!hasReminder && !operatorBannerState.stickyAdaptNotice && !operatorBannerState.stickyChickensNotice) {
      if (driftBanner) driftBanner.style.display = 'none';
      operatorBannerState.lastAdvJson = '';
      operatorBannerState.adaptStatusText = '';
      operatorBannerState.licenseStatusText = '';
      operatorBannerState.bountyStatusText = '';
      operatorBannerState.diffOpen = false;
      operatorBannerState.diffContent = '';
      return;
    }

    // Do not rebuild DOM while an operator mutation is in flight or polls would re-enable buttons / orphan handlers.
    if (operatorBannerState.adapting || operatorBannerState.acceptingLicense) return;

    const effectiveAdv = adv || {};
    const diagSnap = buildDiagnosticPayload(operatorBannerState.lastAdvSnapshot || effectiveAdv);
    const advJson = JSON.stringify({
      adv: effectiveAdv,
      stickyAdaptNotice: operatorBannerState.stickyAdaptNotice,
      stickyChickensNotice: operatorBannerState.stickyChickensNotice,
      adaptStatusText: operatorBannerState.adaptStatusText,
    });
    if (driftBanner && advJson === operatorBannerState.lastAdvJson) {
      driftBanner.style.display = 'block';
      return;
    }

    if (!driftBanner) {
      driftBanner = document.createElement('div');
      driftBanner.id = 'operator-drift-advisory-banner';
      const parentTarget = viewLoggedIn || (projectTelemetryContainer && projectTelemetryContainer.parentNode) || document.body;
      if (parentTarget && typeof parentTarget.insertBefore === 'function') {
        parentTarget.insertBefore(driftBanner, parentTarget.firstChild || null);
      } else if (parentTarget && typeof parentTarget.appendChild === 'function') {
        parentTarget.appendChild(driftBanner);
      }
    }

    operatorBannerState.lastAdvJson = advJson;
    const modFiles = (effectiveAdv.locallyModifiedFiles && effectiveAdv.locallyModifiedFiles.length)
      ? effectiveAdv.locallyModifiedFiles.map((f) => `<code>${escapeHtml(f)}</code>`).join(', ')
      : 'None';
    const upCommits = (effectiveAdv.upstreamCommits && effectiveAdv.upstreamCommits.length)
      ? `<div style="margin-top:6px;"><strong>New Official Upstream Commits (${escapeHtml(effectiveAdv.commitsBehind)} behind):</strong><ul style="margin:4px 0 0 18px; padding:0;">${effectiveAdv.upstreamCommits.map((c) => `<li><code>${escapeHtml(c)}</code></li>`).join('')}</ul></div>`
      : '';
    const upFiles = (effectiveAdv.upstreamChangedFiles && effectiveAdv.upstreamChangedFiles.length)
      ? `<div style="margin-top:4px;"><strong>Changed Upstream Files:</strong> ${effectiveAdv.upstreamChangedFiles.map((f) => `<code>${escapeHtml(f)}</code>`).join(', ')}</div>`
      : '';
    const overlapWarn = (effectiveAdv.overlappingFiles && effectiveAdv.overlappingFiles.length)
      ? `<div style="margin-top:4px; color:#f59e0b;"><strong>Adaptation Overlap Detected:</strong> Both your local node and official upstream modified ${effectiveAdv.overlappingFiles.map((f) => `<code>${escapeHtml(f)}</code>`).join(', ')}.</div>`
      : '';

    const lic = effectiveAdv.licenseStatus || null;
    const missingFiles = lic && Array.isArray(lic.missingCriticalFiles) ? lic.missingCriticalFiles : [];
    const hasGitDrift = Boolean(effectiveAdv.dirtyWorkingTree || (effectiveAdv.commitsBehind && effectiveAdv.commitsBehind > 0));
    const snapModFiles = operatorBannerState.lastAdvSnapshot && Array.isArray(operatorBannerState.lastAdvSnapshot.locallyModifiedFiles)
      ? operatorBannerState.lastAdvSnapshot.locallyModifiedFiles
      : [];
    const hasLocalForkEdits = Boolean(hasGitDrift || snapModFiles.length > 0);
    const hasTamperDiscrepancy = Boolean(
      lic && (
        missingFiles.length > 0 ||
        lic.treeChanged ||
        lic.safeModeReason === 'critical_integrity_changed' ||
        lic.safeModeReason === 'corrupt_license_state' ||
        lic.safeModeReason === 'missing_license_file' ||
        lic.safeModeReason === 'missing_critical_files'
      )
    );
    const needsLicenseAction = Boolean(
      lic && !missingFiles.length &&
      (!lic.accepted || lic.licenseChanged || lic.treeChanged || lic.safeModeReason === 'corrupt_license_state' || lic.safeModeReason === 'critical_integrity_changed')
    );
    const showLicenseNoticeCard = Boolean(lic && (lic.safeMode || lic.licenseChanged || lic.treeChanged) && !hasTamperDiscrepancy);
    const showChickensCard = Boolean(operatorBannerState.stickyChickensNotice && !hasTamperDiscrepancy && !(lic && lic.safeMode));

    const licHashShort = lic && lic.licenseSha256 ? `${String(lic.licenseSha256).slice(0, 12)}...` : 'unavailable';
    const treeHashShort = lic && lic.treeFingerprint ? `${String(lic.treeFingerprint).slice(0, 12)}...` : 'unavailable';
    const mailtoHref = buildSecurityMailtoHref(
      hasTamperDiscrepancy
        ? `OBSX Integrity Discrepancy / Safe Mode Report (${diagSnap.commit})`
        : `OBSX Bug & Edge-Case Report (${diagSnap.commit})`,
      diagSnap
    );

    const tamperStateLabel = missingFiles.length > 0
      ? 'Missing / Deleted'
      : (lic && lic.safeModeReason === 'corrupt_license_state')
      ? 'Corrupt State'
      : 'Modified / Tampered';
    const tamperLocationHtml = missingFiles.length > 0
      ? missingFiles.map((f) => `<code>${escapeHtml(f)}</code>`).join(', ')
      : '<code>LICENSE</code>, <code>CORE_WATCH_FILES</code>, or <code>.obsx-license-state.json</code>';

    const tamperNoticeBox = hasTamperDiscrepancy
      ? `<div style="margin-top:8px; padding:12px 14px; border-radius:6px; border:1px solid rgba(248, 113, 113, 0.45); background:rgba(15, 23, 42, 0.6);">
          <p style="margin:0 0 8px 0;"><strong>We noticed an unexpected discrepancy within your local deployment of our code!</strong></p>
          <p style="margin:0 0 8px 0; color:var(--text-muted);">Don't worry&mdash;we aren't accusing you of anything (yet)! We know that merge conflicts, local experimentation, and accidental overwrites happen all the time to developers working normally.</p>
          <div style="margin:8px 0; padding:8px 10px; border-radius:4px; background:rgba(0,0,0,0.35); border:1px solid rgba(248,113,113,0.25); font-size:12px;">
            <div><strong>Discrepancy Details</strong></div>
            <div style="margin-top:4px;"><strong>Location:</strong> ${tamperLocationHtml}</div>
            <div style="margin-top:2px;"><strong>Current State:</strong> ${escapeHtml(tamperStateLabel)} &middot; <strong>Reason:</strong> <code>${escapeHtml((lic && lic.safeModeReason) || 'integrity_check')}</code></div>
            <div style="margin-top:2px; color:var(--text-muted);">Release <code>v${escapeHtml(diagSnap.version)}</code> &middot; Commit <code>${escapeHtml(diagSnap.commit)}</code> &middot; License <code>${escapeHtml(licHashShort)}</code> &middot; Engine <code>${escapeHtml(treeHashShort)}</code></div>
          </div>
          <p style="margin:8px 0 6px 0;">If you did tamper with the license check or delete it altogether, we would greatly appreciate it if you put it back!</p>
          <p style="margin:0 0 10px 0; color:var(--text-muted);">If this was an unintended error or a false alarm, feel free to reach out to us at <a href="${escapeHtml(mailtoHref)}" style="color:#38bdf8;">security@obsx.tech</a> with details about what you were testing.</p>
          <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
            ${needsLicenseAction ? '<button type="button" id="btn-accept-license" class="btn btn-primary" style="min-height:30px; font-size:12px; padding:5px 12px;">Accept Current LICENSE</button>' : ''}
            <a href="${escapeHtml(mailtoHref)}" class="btn btn-secondary" style="min-height:30px; font-size:12px; padding:5px 12px; text-decoration:none; display:inline-flex; align-items:center;">Email security@obsx.tech</a>
            <span id="operator-license-feedback" role="status" aria-live="polite" style="font-size:12px; color:#f59e0b;"></span>
          </div>
        </div>`
      : '';

    const licenseNoticeBox = showLicenseNoticeCard
      ? `<div style="margin-top:8px; padding:12px 14px; border-radius:6px; border:1px solid rgba(245, 158, 11, 0.35); background:rgba(15, 23, 42, 0.55);">
          <p style="margin:0 0 8px 0;"><strong>Hello, dear user.</strong> Effective with OBSX <code>v2.2.0+</code>, updated releases operate under our Dual-License model: <strong>Zone 1</strong> (client telemetry snippet and public docs) remains open-source under the <strong>MIT License</strong>, <strong>Zone 2</strong> (self-hosted engine in <code>lib/</code>) uses the <strong>OBSX Source-Available License v1.0</strong>, and proprietary <strong>OBSX Sentinel&trade;</strong> remains closed-source.</p>
          <p style="margin:0 0 8px 0; color:var(--text-muted);">All historical pre-v2.2.0 commits remain irrevocably under MIT terms forever, while running v2.2.0+ requires confirming the current <code>LICENSE</code>. We sincerely apologize for any disruption, but this strategic decision was made to ensure the long-term sustainability, security, and integrity of the protocol.</p>
          <div style="margin:8px 0; display:flex; gap:12px; flex-wrap:wrap; font-size:12px;">
            <a href="/terms.html" target="_blank" rel="noopener noreferrer" style="color:#38bdf8;">Review Zone 1 / Zone 2 Terms</a>
            <a href="https://github.com/jidiotspam-hue/obsx/blob/main/LICENSE" target="_blank" rel="noopener noreferrer" style="color:#38bdf8;">Inspect Official LICENSE on GitHub</a>
          </div>
          <div style="margin:8px 0; padding:8px 10px; border-radius:4px; background:rgba(0,0,0,0.3); font-size:12px; color:var(--text-muted);">
            <strong>Node Diagnostics:</strong> Release <code>v${escapeHtml(diagSnap.version)}</code> &middot; Commit <code>${escapeHtml(diagSnap.commit)}</code> &middot; Edition <code>${escapeHtml(diagSnap.edition)}</code> &middot; License <code>${escapeHtml(licHashShort)}</code> &middot; Engine <code>${escapeHtml(treeHashShort)}</code> &middot; Status <code>${escapeHtml((lic && lic.safeModeReason) || (lic && lic.licenseChanged ? 'license_changed' : 'integrity_check'))}</code>
          </div>
          <p style="margin:0 0 10px 0; color:var(--text-muted);">For automated or headless deployments, confirm <code>LICENSE</code> and set <code>OBSX_ACCEPT_LICENSE=true</code> in your process environment (never <code>.env</code>). Have a great day!</p>
          <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
            ${needsLicenseAction ? '<button type="button" id="btn-accept-license" class="btn btn-primary" style="min-height:30px; font-size:12px; padding:5px 12px;">Accept Current LICENSE</button>' : ''}
            <span id="operator-license-feedback" role="status" aria-live="polite" style="font-size:12px; color:#f59e0b;"></span>
          </div>
        </div>`
      : '';

    const dirtyForkPara = hasLocalForkEdits
      ? '<p style="margin:0 0 8px 0; color:var(--text-muted);">Don\'t worry: if you are running a custom fork or local modifications, we strictly recorded verification for your license verification state&mdash;none of your other files, configs, or customizations were touched. Feel free to keep building, testing, and exploring the engine freely!</p>'
      : '';

    const chickensNoticeBox = showChickensCard
      ? `<div style="margin-top:8px; padding:12px 14px; border-radius:6px; border:1px solid rgba(56, 189, 248, 0.4); background:rgba(15, 23, 42, 0.55);">
          <p style="margin:0 0 8px 0;"><strong>Official Integrity Restored &bull; Custom Changes Preserved</strong></p>
          <p style="margin:0 0 8px 0;">We noticed that you clicked our restore button. We genuinely appreciate you taking the time to experiment with our project, test its boundaries, or help us catch weird edge-case bugs. Breaking things is half the fun of software engineering, and it shows that you are actively engaging with what we built.</p>
          ${dirtyForkPara}
          <p style="margin:0 0 10px 0; font-weight:600; color:#7dd3fc;">So for now, until you decide to have fun experimenting with the codebase again, there is nothing here but us chickens!</p>
          <div style="margin:8px 0 10px 0; padding:10px 12px; border-radius:4px; background:rgba(0,0,0,0.3); border:1px solid rgba(56,189,248,0.25); font-size:12px;">
            <div style="margin-bottom:4px;"><strong>Verified Bug Bounty &amp; Opi (Sec) Notice</strong></div>
            <p style="margin:0; color:var(--text-muted);">If you do happen to find an edge case in the future, or even just a silly little bug during your testing (again, thanks for experimenting!), we would truly appreciate it if you reported it to us at <a href="${escapeHtml(mailtoHref)}" style="color:#38bdf8;">security@obsx.tech</a>! Don't worry about the tedious administrative details&mdash;us chickens here at obsx.tech already took care of that by pre-filling your system environment, node version, and diagnostic metadata below. To thank you for helping the chickens at obsx.tech, we will keep your name (or preferred handle) directly on the git commit and on the site! If we can verify your bug, as a direct reward you will be given permanent free access to the Sentinel cloud node on your own machine! (Please do not share it&mdash;the chicken here at obsx.tech worked hard on it!).</p>
          </div>
          <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
            <button type="button" id="btn-download-bug-template" class="btn btn-primary" style="min-height:30px; font-size:12px; padding:5px 12px;">Download Pre-Filled Bug Report</button>
            <button type="button" id="btn-download-diag-json" class="btn btn-secondary" style="min-height:30px; font-size:12px; padding:5px 12px;">Export Diagnostics (JSON)</button>
            <a href="${escapeHtml(mailtoHref)}" class="btn btn-secondary" style="min-height:30px; font-size:12px; padding:5px 12px; text-decoration:none; display:inline-flex; align-items:center;">Email security@obsx.tech</a>
            <button type="button" id="btn-dismiss-chickens-notice" class="btn btn-secondary" style="min-height:30px; font-size:12px; padding:5px 12px;">Dismiss</button>
            <span id="operator-bounty-feedback" role="status" aria-live="polite" style="font-size:12px; color:#38bdf8;"></span>
          </div>
        </div>`
      : '';

    const isChickensPrimary = Boolean(!hasGitDrift && !hasTamperDiscrepancy && !showLicenseNoticeCard && showChickensCard);
    const headerAccent = hasTamperDiscrepancy
      ? '#fca5a5'
      : isChickensPrimary
      ? '#7dd3fc'
      : '#f59e0b';
    const badgeClass = hasTamperDiscrepancy
      ? 'badge-bad'
      : isChickensPrimary
      ? 'badge-good'
      : 'badge-warn';

    driftBanner.style.cssText = hasTamperDiscrepancy
      ? 'margin: 0 0 16px 0; padding: 14px 16px; border-radius: 8px; border: 1px solid rgba(248, 113, 113, 0.5); background: rgba(239, 68, 68, 0.08); font-size: 12.5px; line-height: 1.5;'
      : isChickensPrimary
      ? 'margin: 0 0 16px 0; padding: 14px 16px; border-radius: 8px; border: 1px solid rgba(56, 189, 248, 0.45); background: rgba(56, 189, 248, 0.08); font-size: 12.5px; line-height: 1.5;'
      : 'margin: 0 0 16px 0; padding: 14px 16px; border-radius: 8px; border: 1px solid rgba(245, 158, 11, 0.45); background: rgba(245, 158, 11, 0.08); font-size: 12.5px; line-height: 1.5;';

    const bannerTitle = hasGitDrift
      ? '[PRIVATE OPERATOR ADVISORY] Local Node Customization &amp; Upstream Sync Paused'
      : hasTamperDiscrepancy
      ? '[PRIVATE OPERATOR ADVISORY] Hello, user. &mdash; OBSX Integrity Guardian Safe Mode Active'
      : operatorBannerState.stickyAdaptNotice
      ? '[PRIVATE OPERATOR ADVISORY] Local Adaptation &amp; Stash Notice'
      : isChickensPrimary
      ? '[PRIVATE OPERATOR ADVISORY] Nothing here but us chickens!'
      : '[PRIVATE OPERATOR ADVISORY] Hello, dear user. &mdash; License Integrity &amp; Dual-License Notice';
    const bannerSubtitle = hasGitDrift
      ? 'Auto-updater paused fast-forward sync to protect your local changes. Only you (authenticated operator) can see this notice.'
      : hasTamperDiscrepancy
      ? 'We noticed an unexpected discrepancy within your local deployment of our code! Only you (authenticated operator) can see this notice.'
      : operatorBannerState.stickyAdaptNotice
      ? 'Upstream sync completed, and overlapping local edits remain safely preserved in git stash until you restore or dismiss this notice.'
      : isChickensPrimary
      ? 'Official Integrity Restored &bull; Verified Operator Acceptance Recorded &bull; Custom Changes Preserved'
      : 'Operator attention required for Dual-License &amp; integrity verification. Only you (authenticated operator) can see this notice.';

    const stickyNoticeBox = (!hasGitDrift && operatorBannerState.stickyAdaptNotice)
      ? `<div style="margin-top:8px; padding:8px 10px; border-radius:6px; border:1px solid rgba(245, 158, 11, 0.35); background:rgba(0,0,0,0.25); display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
          <span id="operator-adapt-feedback" role="status" aria-live="polite" style="font-size:11.5px; color:#f59e0b;"></span>
          <button type="button" id="btn-dismiss-adapt-notice" class="btn btn-secondary" style="min-height:28px; font-size:11.5px; padding:4px 10px;">Dismiss</button>
        </div>`
      : '';
    const gitControls = hasGitDrift
      ? `
      <div style="margin-top:6px;"><strong>Your Modified Files:</strong> ${modFiles}</div>
      ${upCommits}
      ${upFiles}
      ${overlapWarn}
      <div style="margin-top:8px;">
        <strong>Adapt &amp; Rebase Command:</strong>
        <code style="display:block; margin-top:4px; padding:6px 8px; background:rgba(0,0,0,0.35); border-radius:4px; user-select:all;">${escapeHtml(effectiveAdv.adaptationCommand || 'git fetch origin main && git stash && git pull --rebase origin main && git stash pop')}</code>
      </div>
      <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
        <button type="button" id="btn-view-upstream-diff" class="btn btn-secondary" style="min-height:30px; font-size:11.5px; padding:5px 10px;">View Upstream Diff</button>
        <button type="button" id="btn-auto-adapt-node" class="btn btn-primary" style="min-height:30px; font-size:11.5px; padding:5px 10px;">1-Click Auto-Adapt &amp; Rebase</button>
        <span id="operator-adapt-feedback" role="status" aria-live="polite" style="font-size:11.5px; color:#f59e0b;"></span>
      </div>
      <pre id="operator-upstream-diff-view" style="display:none; margin-top:8px; padding:8px; max-height:220px; overflow:auto; background:rgba(0,0,0,0.45); border-radius:4px; font-size:11px; white-space:pre-wrap;"></pre>
      `
      : stickyNoticeBox;

    driftBanner.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; margin-bottom:6px;">
        <div style="display:flex; align-items:center; gap:12px; min-width:0; flex:1;">
          <img src="/opi-sec.png" alt="Opi (Sec) the Chicken, OBSX Security guardian mascot" width="44" height="44" style="width:44px; height:44px; border-radius:8px; border:1px solid rgba(56,189,248,0.35); background:rgba(15,23,42,0.85); image-rendering:pixelated; flex-shrink:0;" />
          <div style="min-width:0;">
            <h2 style="margin:0; font-size:14.5px; font-weight:700; color:${escapeHtml(headerAccent)};">${bannerTitle}</h2>
            <div style="margin-top:2px; color:var(--text-muted); font-size:12px;">${bannerSubtitle}</div>
          </div>
        </div>
        <span class="badge ${escapeHtml(badgeClass)}">Edition: ${escapeHtml(effectiveAdv.edition || 'modified-local')}</span>
      </div>
      ${tamperNoticeBox}
      ${licenseNoticeBox}
      ${chickensNoticeBox}
      ${gitControls}
    `;
    driftBanner.style.display = 'block';
    syncBannerFeedbackAndDiff();

    const btnDismissAdapt = document.getElementById('btn-dismiss-adapt-notice');
    if (btnDismissAdapt) {
      btnDismissAdapt.onclick = () => {
        operatorBannerState.stickyAdaptNotice = false;
        operatorBannerState.adaptStatusText = '';
        operatorBannerState.lastAdvJson = '';
        renderOperatorDriftBanner(adv);
      };
    }

    const btnDismissChickens = document.getElementById('btn-dismiss-chickens-notice');
    if (btnDismissChickens) {
      btnDismissChickens.onclick = () => {
        operatorBannerState.stickyChickensNotice = false;
        operatorBannerState.bountyStatusText = '';
        operatorBannerState.lastAdvJson = '';
        renderOperatorDriftBanner(adv);
      };
    }

    const btnDownloadBugTemplate = document.getElementById('btn-download-bug-template');
    if (btnDownloadBugTemplate) {
      btnDownloadBugTemplate.onclick = () => {
        const currentDiag = buildDiagnosticPayload(operatorBannerState.lastAdvSnapshot || effectiveAdv);
        const downloaded = triggerFileDownload(
          'obsx-prefilled-bug-report.txt',
          buildBugReportTemplate(currentDiag),
          'text/plain;charset=utf-8'
        );
        operatorBannerState.bountyStatusText = downloaded
          ? 'Downloaded obsx-prefilled-bug-report.txt (attach to your email to security@obsx.tech!)'
          : 'Pre-filled bug report generated.';
        syncBannerFeedbackAndDiff();
      };
    }

    const btnDownloadDiagJson = document.getElementById('btn-download-diag-json');
    if (btnDownloadDiagJson) {
      btnDownloadDiagJson.onclick = () => {
        const currentDiag = buildDiagnosticPayload(operatorBannerState.lastAdvSnapshot || effectiveAdv);
        const downloaded = triggerFileDownload(
          'obsx-diagnostics.json',
          JSON.stringify(currentDiag, null, 2),
          'application/json;charset=utf-8'
        );
        operatorBannerState.bountyStatusText = downloaded
          ? 'Exported obsx-diagnostics.json with live node metadata.'
          : 'Diagnostics bundle prepared.';
        syncBannerFeedbackAndDiff();
      };
    }

    const btnDiff = document.getElementById('btn-view-upstream-diff');
    if (btnDiff) {
      btnDiff.onclick = async () => {
        if (operatorBannerState.diffOpen) {
          operatorBannerState.diffOpen = false;
          syncBannerFeedbackAndDiff();
          return;
        }
        btnDiff.textContent = 'Loading diff...';
        try {
          const dRes = await fetch('/api/v1/system/diff');
          const dData = await readJsonSafe(dRes);
          if (dRes.ok && dData) {
            operatorBannerState.diffContent = `=== UPSTREAM DIFF (HEAD..origin/main) ===\n${dData.upstreamDiff || 'None'}\n\n=== LOCAL WORKING TREE DIFF ===\n${dData.localDiff || 'None'}`;
          } else {
            operatorBannerState.diffContent = 'Failed to load diff: ' + extractResponseError(dRes, dData);
          }
        } catch (e) {
          operatorBannerState.diffContent = 'Failed to load diff.';
        }
        operatorBannerState.diffOpen = true;
        syncBannerFeedbackAndDiff();
      };
    }

    const btnAdapt = document.getElementById('btn-auto-adapt-node');
    if (btnAdapt) {
      btnAdapt.onclick = async () => {
        if (operatorBannerState.adapting) return;
        operatorBannerState.adapting = true;
        operatorBannerState.stickyAdaptNotice = false;
        operatorBannerState.adaptStatusText = '';
        btnAdapt.disabled = true;
        btnAdapt.textContent = 'Adapting & Rebasing...';
        syncBannerFeedbackAndDiff();
        try {
          const aRes = await fetch('/api/v1/system/adapt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{}',
          });
          const aData = await readJsonSafe(aRes);
          const succeeded = Boolean(aRes.ok && aData && aData.ok);
          operatorBannerState.stickyAdaptNotice = !succeeded;
          operatorBannerState.adaptStatusText = succeeded
            ? `Adapted to ${aData.commit}!`
            : extractResponseError(aRes, aData, 'Conflict detected');
          if (activeTelemetryPid && succeeded) {
            setTimeout(() => loadProjectTelemetry(activeTelemetryPid, false), 400);
          }
        } catch (e) {
          operatorBannerState.stickyAdaptNotice = true;
          operatorBannerState.adaptStatusText = 'Adapt failed';
        } finally {
          operatorBannerState.adapting = false;
          btnAdapt.disabled = false;
          btnAdapt.textContent = '1-Click Auto-Adapt & Rebase';
          syncBannerFeedbackAndDiff();
        }
      };
    }

    const btnAcceptLic = document.getElementById('btn-accept-license');
    if (btnAcceptLic) {
      btnAcceptLic.onclick = async () => {
        if (operatorBannerState.acceptingLicense) return;
        operatorBannerState.acceptingLicense = true;
        operatorBannerState.licenseStatusText = '';
        btnAcceptLic.disabled = true;
        btnAcceptLic.textContent = 'Recording acceptance...';
        syncBannerFeedbackAndDiff();
        try {
          const lRes = await fetch('/api/v1/system/license/accept', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{}',
          });
          const lData = await readJsonSafe(lRes);
          if (lRes.ok && lData && lData.ok) {
            operatorBannerState.licenseStatusText = 'LICENSE Accepted';
            if (!lData.safeMode) {
              operatorBannerState.stickyChickensNotice = true;
            }
            if (activeTelemetryPid) {
              setTimeout(() => loadProjectTelemetry(activeTelemetryPid, false), 400);
            } else {
              setTimeout(() => checkAuth(), 400);
            }
          } else {
            operatorBannerState.licenseStatusText = extractResponseError(lRes, lData, 'Acceptance failed');
          }
        } catch (e) {
          operatorBannerState.licenseStatusText = 'Acceptance failed';
        } finally {
          operatorBannerState.acceptingLicense = false;
          btnAcceptLic.disabled = false;
          btnAcceptLic.textContent = 'Accept Current LICENSE';
          syncBannerFeedbackAndDiff();
        }
      };
    }
  }

  // 7. Isolated Tenant Project Telemetry Poller (Option B)
  async function loadProjectTelemetry(pid, isManualClick = false) {
    if (!pid) return;
    activeTelemetryPid = pid;

    if (isManualClick && btnLoadProjectTelemetry) {
      btnLoadProjectTelemetry.disabled = true;
      btnLoadProjectTelemetry.textContent = 'Attesting & loading...';
    }

    let headers = {};
    if (isManualClick) {
      const { token, nonce } = await harvestAttestation();
      if (token) {
        headers['x-obsx-token'] = token;
        if (nonce) headers['x-obsx-nonce'] = nonce;
      }
    }

    try {
      const res = await fetch(`/api/v1/project/${pid}/telemetry`, { headers });
      const data = await readJsonSafe(res);
      if (!res.ok || !data || !data.ok) {
        console.warn('Project telemetry query error:', extractResponseError(res, data));
        return;
      }

      if (telemetryAuthBadge) {
        telemetryAuthBadge.textContent = isManualClick ? '[OPERATOR VERIFIED - ATTESTED]' : '[OPERATOR VERIFIED]';
        telemetryAuthBadge.className = 'badge badge-good';
      }

      const proj = data.project || cachedUserProjects.find((p) => p.pid === pid) || {};
      const pk = proj.publicKey || '';

      // Render Private Operator-Only Upstream Drift & Adaptation Reminder (when local tree is dirty or behind upstream)
      renderOperatorDriftBanner(data.upstreamAdvisory);

      const stats = data.stats || {};
      const hasTraffic = Boolean(data.hasTraffic && stats.total > 0);

      if (!hasTraffic) {
        // Render Minimal Status Card with Install Instructions
        if (projectTelemetryContainer) projectTelemetryContainer.style.display = 'none';
        if (projectEmptyStatusCard) {
          projectEmptyStatusCard.style.display = 'block';
          if (snippetInstallTag) {
            snippetInstallTag.textContent = `<script src="https://obsx.tech/obsx.min.js" data-obsx-site="${pk}" async></script>`;
          }
        }
      } else {
        // Render Isolated Telemetry Grid & Stream
        if (projectEmptyStatusCard) projectEmptyStatusCard.style.display = 'none';
        if (projectTelemetryContainer) projectTelemetryContainer.style.display = 'block';

        if (metricTotal) metricTotal.textContent = (stats.total || 0).toLocaleString();
        if (metricAccept) metricAccept.textContent = ((stats.breakdown && (stats.breakdown.accept + (stats.breakdown.observe || 0))) || 0).toLocaleString();
        if (metricReject) metricReject.textContent = ((stats.breakdown && stats.breakdown.reject) || 0).toLocaleString();
        const metricShadowReject = document.getElementById('metric-shadow-reject');
        if (metricShadowReject) {
          metricShadowReject.textContent = ((stats.breakdown && stats.breakdown.shadowReject) || 0).toLocaleString();
        }
        if (metricRate) metricRate.textContent = `${stats.acceptRate || 100}%`;

        // Render Recent Events Feed
        const REASON_DESCRIPTIONS = {
          proxy_virtualization: 'Web proxy / unblocker shims or tunnel headers detected',
          automation_cdp: 'Active Chrome DevTools Protocol / Playwright / Puppeteer detected',
          automation_webdriver: 'navigator.webdriver automation flag present',
          automation_headless: 'Headless browser fingerprint indicators',
          bad_signature: 'OBSX.seal() HMAC signature mismatch (payload tampered)',
          stale_signature: 'OBSX.seal() signature expired or clock skew exceeded',
          invalid_pow: 'Micro-Proof-of-Work challenge failed or missing',
          missing_telemetry: 'No client behavioral telemetry recorded',
          missing_signals: 'Insufficient physical pointer/touch/keyboard signals',
          synthetic_cadence: 'Scripted keystroke cadence lacking biological variance',
          linear_pointer: 'Synthetic linear pointer trajectory (low jerk)',
          tampered_builtins: 'Native JS built-ins or prototypes monkey-patched',
          software_rasterizer_anomaly: 'Software GPU rasterizer (SwiftShader/llvmpipe)',
          token_reused: 'Single-use attestation token replay rejected',
          expired: 'Attestation token expired before submission',
          invalid_token: 'Forged, malformed, or missing attestation token',
          too_fast: 'Action completed faster than minimum human duration',
          openai_scraper_blocked: 'OpenAI/ChatGPT crawler blocked by origin policy',
        };

        const btnFilterRejects = document.getElementById('btn-filter-rejects');
        if (btnFilterRejects && !btnFilterRejects.dataset.bound) {
          btnFilterRejects.dataset.bound = '1';
          btnFilterRejects.addEventListener('click', () => {
            const active = btnFilterRejects.dataset.active === '1';
            btnFilterRejects.dataset.active = active ? '0' : '1';
            btnFilterRejects.textContent = active ? 'Rejects Only' : 'Show All';
            loadProjectTelemetry(activeTelemetryPid, false);
          });
        }
        const onlyRejects = Boolean(btnFilterRejects && btnFilterRejects.dataset.active === '1');

        if (recentEvents && Array.isArray(data.recentEvents)) {
          const filteredEvents = onlyRejects
            ? data.recentEvents.filter((ev) => ev.verdict === 'reject' || ev.shadowVerdict === 'reject')
            : data.recentEvents;
          if (filteredEvents.length === 0) {
            recentEvents.innerHTML = onlyRejects
              ? '<p style="color:var(--good); padding:10px 0;">Zero rejected events in recent stream.</p>'
              : '<p style="color:var(--text-muted); padding:10px 0;">Awaiting incoming actions...</p>';
          } else {
            recentEvents.innerHTML = filteredEvents.map((ev) => {
              const isPassive = ev.verdict === 'observe' || ev.mode === 'passive';
              const pillClass = ev.verdict === 'accept'
                ? 'badge-good'
                : ev.verdict === 'observe'
                ? (ev.shadowVerdict === 'reject' ? 'badge-warn' : 'badge-good')
                : ev.verdict === 'review'
                ? 'badge-warn'
                : 'badge-bad';
              const labelText = isPassive && ev.shadowVerdict
                ? `OBSERVE (Shadow ${String(ev.shadowVerdict || '').toUpperCase()} - Risk ${ev.risk})`
                : `${String(ev.verdict || '').toUpperCase()} (Risk ${ev.risk})`;
              const timeAgo = Math.max(0, Math.round((Date.now() - ev.timestamp) / 1000));
              return `
                <div style="padding: 9px 0; border-bottom: 1px solid var(--border);">
                  <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                      <strong>${escapeHtml(ev.action)}</strong>
                      <span style="color:var(--text-muted); margin-left:6px; font-size:11.5px;">(${escapeHtml(ev.maskedIp)})</span>
                    </div>
                    <span class="badge ${pillClass}">${escapeHtml(labelText)}</span>
                  </div>
                  <div style="font-size:11.5px; color:var(--text-muted); margin-top:3px;">
                    ${ev.reasons && ev.reasons.length ? ev.reasons.map((r) => escapeHtml(REASON_DESCRIPTIONS[r] ? `${r} (${REASON_DESCRIPTIONS[r]})` : r)).join(' · ') : 'All cryptographic invariants satisfied'}
                    <span style="float:right;">${timeAgo < 60 ? `${timeAgo}s ago` : `${Math.round(timeAgo / 60)}m ago`}</span>
                  </div>
                </div>
              `;
            }).join('');
          }
        }

        // Render Threat Breakdown
        if (threatBreakdown && stats.topReasons) {
          const reasonEntries = Object.entries(stats.topReasons);
          if (reasonEntries.length === 0) {
            threatBreakdown.innerHTML = '<p style="color:var(--good);">Zero active threat vectors. All current traffic attested legitimate.</p>';
          } else {
            const totalReasons = reasonEntries.reduce((acc, [, cnt]) => acc + Number(cnt || 0), 0) || 1;
            threatBreakdown.innerHTML = reasonEntries.map(([code, count]) => {
              const pct = Math.max(1, Math.round((Number(count || 0) / totalReasons) * 100));
              const desc = REASON_DESCRIPTIONS[code] || 'Automated risk rule triggered';
              return `
                <div style="padding:7px 0; border-bottom:1px solid var(--border);">
                  <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span><code>${escapeHtml(code)}</code></span>
                    <strong style="color:var(--bad);">${Number(count || 0)} caught (${pct}%)</strong>
                  </div>
                  <div style="font-size:11.5px; color:var(--text-muted); margin-top:2px;">${escapeHtml(desc)}</div>
                </div>
              `;
            }).join('');
          }
        }
      }
    } catch (err) {
      console.warn('Project telemetry query error:', err);
    } finally {
      if (isManualClick && btnLoadProjectTelemetry) {
        btnLoadProjectTelemetry.disabled = false;
        btnLoadProjectTelemetry.textContent = 'Load Telemetry';
      }
    }
  }

  function startTelemetryPolling() {
    if (pollingInterval) clearInterval(pollingInterval);
    pollingInterval = setInterval(() => {
      if (activeTelemetryPid) {
        loadProjectTelemetry(activeTelemetryPid, false);
      }
    }, 4000);
  }

  selectTelemetryProject?.addEventListener('change', () => {
    if (selectTelemetryProject.value) {
      loadProjectTelemetry(selectTelemetryProject.value, true);
    }
  });

  btnLoadProjectTelemetry?.addEventListener('click', () => {
    if (selectTelemetryProject && selectTelemetryProject.value) {
      loadProjectTelemetry(selectTelemetryProject.value, true);
    }
  });

  btnCopyInstallTag?.addEventListener('click', async () => {
    if (!snippetInstallTag) return;
    const text = snippetInstallTag.textContent || '';
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      const prev = btnCopyInstallTag.textContent;
      btnCopyInstallTag.textContent = 'Copied!';
      setTimeout(() => { btnCopyInstallTag.textContent = prev; }, 1800);
    } catch {
      prompt('Copy embed tag manually:', text);
    }
  });

  // 8. Kinematic Jerk Radar & Neuromuscular Waveform Visualizer
  const kinCanvas = document.getElementById('kinematic-canvas');
  const kinBadge = document.getElementById('kinematic-badge');
  const kinPoints = document.getElementById('kin-points');
  const kinJerk = document.getElementById('kin-jerk');
  const kinStatus = document.getElementById('kin-status');
  const btnSimBot = document.getElementById('btn-sim-bot-spline');
  const btnClearRadar = document.getElementById('btn-clear-radar');

  let motionBuffer = [];
  let isSimulatingBot = false;

  function initKinematicRadar() {
    if (!kinCanvas) return;
    const ctx = kinCanvas.getContext('2d');
    const width = kinCanvas.width;
    const height = kinCanvas.height;

    function drawGrid() {
      ctx.fillStyle = '#0c1017';
      ctx.fillRect(0, 0, width, height);

      // Radar grid lines
      ctx.strokeStyle = '#161f30';
      ctx.lineWidth = 1;
      for (let x = 0; x < width; x += 40) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += 40) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }
    }

    drawGrid();

    function computeJerkMetrics(points) {
      if (points.length < 5) return { variance: 0, isHuman: true };
      const jerks = [];
      for (let i = 2; i < points.length; i++) {
        const dt1 = (points[i].t - points[i - 1].t) || 16;
        const dt0 = (points[i - 1].t - points[i - 2].t) || 16;
        const vx1 = (points[i].x - points[i - 1].x) / dt1;
        const vy1 = (points[i].y - points[i - 1].y) / dt1;
        const vx0 = (points[i - 1].x - points[i - 2].x) / dt0;
        const vy0 = (points[i - 1].y - points[i - 2].y) / dt0;

        const ax = (vx1 - vx0) / ((dt1 + dt0) / 2);
        const ay = (vy1 - vy0) / ((dt1 + dt0) / 2);
        const j = Math.sqrt(ax * ax + ay * ay);
        jerks.push(j);
      }

      if (jerks.length === 0) return { variance: 0, isHuman: true };
      const mean = jerks.reduce((a, b) => a + b, 0) / jerks.length;
      const variance = jerks.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / jerks.length;
      return { variance, isHuman: variance > 0.0001 };
    }

    function renderPoints(color = '#10b981') {
      drawGrid();
      if (motionBuffer.length < 2) return;

      ctx.beginPath();
      ctx.strokeStyle = color;
      ctx.lineWidth = 2.5;
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      ctx.moveTo(motionBuffer[0].x, motionBuffer[0].y);

      for (let i = 1; i < motionBuffer.length; i++) {
        ctx.lineTo(motionBuffer[i].x, motionBuffer[i].y);
      }
      ctx.stroke();

      // Glowing radar head
      const last = motionBuffer[motionBuffer.length - 1];
      ctx.fillStyle = color;
      ctx.shadowColor = color;
      ctx.shadowBlur = 10;
      ctx.beginPath();
      ctx.arc(last.x, last.y, 4, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    kinCanvas.addEventListener('mousemove', (e) => {
      if (isSimulatingBot) return;
      const rect = kinCanvas.getBoundingClientRect();
      const scaleX = kinCanvas.width / rect.width;
      const scaleY = kinCanvas.height / rect.height;
      const x = (e.clientX - rect.left) * scaleX;
      const y = (e.clientY - rect.top) * scaleY;

      motionBuffer.push({ x, y, t: performance.now() });
      if (motionBuffer.length > 80) motionBuffer.shift();

      renderPoints('#10b981');
      const { variance } = computeJerkMetrics(motionBuffer);

      if (kinPoints) kinPoints.textContent = motionBuffer.length;
      if (kinJerk) kinJerk.textContent = variance.toFixed(5);
      if (kinStatus) {
        kinStatus.textContent = 'Natural Neuromuscular Tremor (Risk 0)';
        kinStatus.style.color = 'var(--good)';
      }
      if (kinBadge) {
        kinBadge.className = 'badge badge-good';
        kinBadge.textContent = 'Biological Human Motion';
      }
    });

    btnClearRadar?.addEventListener('click', () => {
      motionBuffer = [];
      drawGrid();
      if (kinPoints) kinPoints.textContent = '0';
      if (kinJerk) kinJerk.textContent = 'Warming up...';
      if (kinStatus) {
        kinStatus.textContent = 'Listening for movement';
        kinStatus.style.color = 'var(--good)';
      }
      if (kinBadge) {
        kinBadge.className = 'badge badge-good';
        kinBadge.textContent = 'Biological Human Motion';
      }
    });

    btnSimBot?.addEventListener('click', () => {
      isSimulatingBot = true;
      motionBuffer = [];
      drawGrid();

      if (kinBadge) {
        kinBadge.className = 'badge badge-bad';
        kinBadge.textContent = 'Synthetic Spline Bot';
      }

      // Generate a smooth cubic Bezier spline with constant mathematical cadence (zero jerk variance)
      let step = 0;
      const totalSteps = 60;
      const p0 = { x: 50, y: 150 };
      const p1 = { x: 250, y: 30 };
      const p2 = { x: 600, y: 170 };
      const p3 = { x: 800, y: 50 };

      const interval = setInterval(() => {
        if (step > totalSteps) {
          clearInterval(interval);
          isSimulatingBot = false;
          if (kinStatus) {
            kinStatus.textContent = 'Hard Reject: Synthetic Spline (Zero Jerk Variance)';
            kinStatus.style.color = 'var(--bad)';
          }
          return;
        }

        const t = step / totalSteps;
        const x = Math.pow(1 - t, 3) * p0.x + 3 * Math.pow(1 - t, 2) * t * p1.x + 3 * (1 - t) * Math.pow(t, 2) * p2.x + Math.pow(t, 3) * p3.x;
        const y = Math.pow(1 - t, 3) * p0.y + 3 * Math.pow(1 - t, 2) * t * p1.y + 3 * (1 - t) * Math.pow(t, 2) * p2.y + Math.pow(t, 3) * p3.y;
        motionBuffer.push({ x, y, t: step * 16.6 });

        renderPoints('#ef4444');
        if (kinPoints) kinPoints.textContent = motionBuffer.length;
        if (kinJerk) kinJerk.textContent = '0.00000 (Flat)';
        if (kinStatus) {
          kinStatus.textContent = 'Simulating synthetic mathematical spline...';
          kinStatus.style.color = 'var(--bad)';
        }

        step++;
      }, 20);
    });
  }

  // 9. Critical Security Alerts Dispatcher & History Poller
  const mailerStatusBadge = document.getElementById('mailer-status-badge');
  const inpAlertRecipient = document.getElementById('inp-alert-recipient');
  const btnDispatchTestAlert = document.getElementById('btn-dispatch-test-alert');
  const alertsHistory = document.getElementById('alerts-history');

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  async function fetchAlertsHistory() {
    try {
      const res = await fetch('/api/v1/alerts');
      const data = await readJsonSafe(res);
      if (!res.ok || !data || !data.ok) return;

      if (mailerStatusBadge && data.mailer) {
        if (data.mailer.configured) {
          mailerStatusBadge.className = 'badge badge-good';
          mailerStatusBadge.textContent = `SMTP Active (${data.mailer.from})`;
        } else {
          mailerStatusBadge.className = 'badge badge-warn';
          mailerStatusBadge.textContent = `Dev Console (${data.mailer.from})`;
        }
      }

      if (alertsHistory && Array.isArray(data.alerts)) {
        if (data.alerts.length === 0) {
          alertsHistory.innerHTML = '<p style="color:var(--text-muted); padding:6px 0;">No critical incidents dispatched yet. Node operating cleanly.</p>';
        } else {
          alertsHistory.innerHTML = data.alerts.map((alt) => {
            const timeAgo = Math.round((Date.now() - alt.timestamp) / 1000);
            const timeStr = timeAgo < 60 ? `${timeAgo}s ago` : `${Math.round(timeAgo / 60)}m ago`;
            const badgeClass = alt.throttled ? 'badge-warn' : 'badge-bad';
            const statusLabel = alt.throttled ? 'THROTTLED (5m COOLDOWN)' : 'DISPATCHED';

            return `
              <div style="padding: 8px 0; border-bottom: 1px solid var(--border);">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                  <div>
                    <strong style="color:var(--text);">${escapeHtml(alt.title)}</strong>
                    <span style="color:var(--text-muted); margin-left:6px; font-size:11px;">(${escapeHtml(alt.clientIp)})</span>
                  </div>
                  <span class="badge ${badgeClass}">${escapeHtml(statusLabel)}</span>
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:3px;">
                  <span>${escapeHtml(alt.detail)} &bull; Target: <code>${escapeHtml(alt.recipient)}</code></span>
                  <span style="float:right;">${timeStr}</span>
                </div>
              </div>
            `;
          }).join('');
        }
      }
    } catch (err) {
      console.warn('Alert history fetch error:', err);
    }
  }

  btnDispatchTestAlert?.addEventListener('click', () => {
    const recipient = (inpAlertRecipient ? inpAlertRecipient.value : '').trim();
    dispatchTestAlertRequest(btnDispatchTestAlert, {
      idleLabel: 'Dispatch Test Alert',
      loadingLabel: 'Attesting & dispatching...',
      recipient,
    });
  });

  // Initialize
  checkAuth();
  initKinematicRadar();
  fetchAlertsHistory();
  setInterval(fetchAlertsHistory, 6000);

  if (document.getElementById('shield-state')) {
    const fmtCount = (n) => (n || 0).toLocaleString();
    const pollBotProtection = async () => {
      try {
        const r = await fetch('/api/v1/bot-protection');
        const d = await readJsonSafe(r);
        if (!r.ok || !d || !d.ok) return;
        const st = document.getElementById('shield-state');
        if (!st) return;
        st.textContent = !d.enabled ? 'DISABLED' : (d.engaged ? 'UNDER ATTACK — ENGAGED' : 'ARMED');
        st.style.color = d.engaged ? '#e11d48' : '#16a34a';
        document.getElementById('shield-req').textContent = fmtCount(d.counters.requests);
        document.getElementById('shield-chal').textContent = fmtCount(d.counters.challenged);
        document.getElementById('shield-solved').textContent = fmtCount(d.counters.solved);
        document.getElementById('shield-blocked').textContent = fmtCount(d.counters.blocked);
        document.getElementById('shield-quar').textContent = fmtCount(d.counters.quarantined);
        document.getElementById('shield-mode').textContent = d.mode + ' · ' + d.difficultyBits + '-bit proof-of-work';
        const list = document.getElementById('shield-offenders');
        const offs = (d.topOffenders || []).slice(0, 6);
        list.textContent = d.redacted
          ? 'Offender details are visible to signed-in operators only.'
          : offs.length
          ? 'Top offenders: ' + offs.map((o) => o.ip + ' (' + o.hits + '×, ' + o.reason + ')').join(' · ')
          : 'No offenders currently flagged.';
      } catch {}
    };
    pollBotProtection();
    setInterval(pollBotProtection, 10000);
  }
})();
