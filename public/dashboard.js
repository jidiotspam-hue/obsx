'use strict';

/**
 * OBSX Security — Node Operator Dashboard
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the Elastic License 2.0 + OBSX Zone 2 Terms — See LICENSE file.
 * Free for self-hosted internal use; commercial SaaS hosting and competing extraction prohibited.
 */

(function () {
  const viewLoggedOut = document.getElementById('view-logged-out');
  const viewLoggedIn = document.getElementById('view-logged-in');
  const authStepEmail = document.getElementById('auth-step-email');
  const authStepCode = document.getElementById('auth-step-code');
  const inpEmail = document.getElementById('inp-auth-email');
  const inpCode = document.getElementById('inp-auth-code');
  const btnSendCode = document.getElementById('btn-send-code');
  const btnVerifyCode = document.getElementById('btn-verify-code');
  const btnBackEmail = document.getElementById('btn-back-email');
  const btnSignout = document.getElementById('btn-signout');
  const btnTestAlert = document.getElementById('btn-test-alert');
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

  // 1. Check Session State on Load
  async function checkAuth() {
    try {
      const res = await fetch('/api/v1/me');
      const data = await res.json();
      if (data.ok && data.user) {
        renderLoggedIn(data.user);
      } else {
        renderLoggedOut();
      }
    } catch (err) {
      console.error('Session check failed:', err);
      renderLoggedOut();
    }
  }

  function renderLoggedIn(user) {
    if (viewLoggedOut) viewLoggedOut.style.display = 'none';
    if (viewLoggedIn) viewLoggedIn.style.display = 'block';
    if (userEmailDisplay) userEmailDisplay.textContent = user.email;
    if (navAuthStatus) {
      navAuthStatus.innerHTML = `<span class="badge badge-good" style="margin-left: 8px;">Operator: ${escapeHtml(String(user.email || '').split('@')[0])}</span>`;
    }

    loadProjects();
    startTelemetryPolling();
  }

  function renderLoggedOut() {
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
      const data = await res.json();
      if (data.ok && data.project) {
        if (formCreateProject) formCreateProject.style.display = 'none';
        if (inpNewProjectName) inpNewProjectName.value = '';
        if (inpNewProjectOrigins) inpNewProjectOrigins.value = '';
        showRevealedKey(data.project.secretKey);
        await loadProjects();
      } else {
        alert('Failed to create project: ' + (data.error || data.message || 'Unknown error'));
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
      const data = await res.json();
      if (!data.ok || !Array.isArray(data.projects)) {
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
                <span style="font-size: 11.5px; color: var(--text-muted); margin-left: 8px;">Created ${createdDate}</span>
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

            <!-- OpenAI / ChatGPT Scraper Gate ("get your own ram") -->
            <div style="margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
              <div style="display: flex; align-items: center; gap: 10px;">
                <img src="/dram-dark.jpg" alt="Pixel DRAM Stick" style="width: 44px; height: auto; border-radius: 5px; border: 1px solid var(--border); image-rendering: pixelated; background: #000;" />
                <div>
                  <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">OpenAI / ChatGPT Scraper Policy (DRAM Sovereignty)</div>
                  <div style="display: flex; align-items: center; gap: 8px; margin-top: 3px; flex-wrap: wrap;">
                    <span class="badge ${(p.settings && p.settings.blockOpenAiScrapers !== false) ? 'badge-good' : 'badge-secondary'}">
                      ${(p.settings && p.settings.blockOpenAiScrapers !== false) ? '● Blocking OpenAI Scrapers ("get your own ram")' : '○ Allowed'}
                    </span>
                    <a href="/?utm_source=chatgpt.com" target="_blank" rel="noopener" style="font-size: 11.5px; color: var(--accent); text-decoration: none; font-weight: 600;">Preview DRAM Balloons &rarr;</a>
                  </div>
                </div>
              </div>
              <div>
                <button type="button" class="btn btn-secondary btn-toggle-openai" data-pid="${escapeHtml(p.pid)}" data-enabled="${(p.settings && p.settings.blockOpenAiScrapers !== false) ? 'true' : 'false'}" style="font-size: 11.5px; padding: 4px 10px;">
                  ${(p.settings && p.settings.blockOpenAiScrapers !== false) ? 'Allow OpenAI' : 'Block OpenAI ("get your own ram")'}
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
            const data = await res.json();
            if (data.ok && data.secretKey) {
              showRevealedKey(data.secretKey);
            } else {
              alert('Key rotation failed: ' + (data.error || 'Unknown error'));
            }
          } catch (err) {
            alert('Error rotating key: ' + err.message);
          } finally {
            btn.disabled = false;
            btn.textContent = orig;
          }
        });
      });

      projectsList.querySelectorAll('.btn-delete-proj').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const pid = btn.getAttribute('data-pid');
          const name = btn.getAttribute('data-name');
          if (!pid) return;
          if (!confirm(`Are you sure you want to permanently delete "${name}" (${pid})?\n\nAll client requests using this site key will immediately be blocked.`)) {
            return;
          }
          btn.disabled = true;
          const { token, nonce } = await harvestAttestation();
          try {
            const res = await fetch(`/api/v1/project/${pid}`, {
              method: 'DELETE',
              headers: {
                'Content-Type': 'application/json',
                'X-OBSX-Token': token || '',
                'X-OBSX-Nonce': nonce || '',
              },
              body: JSON.stringify({ token, nonce }),
            });
            const data = await res.json();
            if (data.ok) {
              await loadProjects();
            } else {
              alert('Failed to delete project: ' + (data.error || 'Unknown error'));
              btn.disabled = false;
            }
          } catch (err) {
            alert('Error deleting project: ' + err.message);
            btn.disabled = false;
          }
        });
      });

      // Operational Gate Mode Toggle (Enforce vs Passive)
      projectsList.querySelectorAll('.btn-toggle-mode').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const pid = btn.getAttribute('data-pid');
          const currentMode = btn.getAttribute('data-mode');
          const nextMode = currentMode === 'passive' ? 'enforce' : 'passive';

          btn.disabled = true;
          const { token, nonce } = await harvestAttestation();
          try {
            const res = await fetch(`/api/v1/project/${pid}/settings`, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ mode: nextMode, token, nonce }),
            });
            const data = await res.json();
            if (data.ok) {
              await loadProjects();
            } else {
              alert('Failed to update mode: ' + (data.error || 'Unknown error'));
              btn.disabled = false;
            }
          } catch (err) {
            alert('Error updating mode: ' + err.message);
            btn.disabled = false;
          }
        });
      });

      // Circuit Breaker Toggle & Reset Handlers
      projectsList.querySelectorAll('.btn-toggle-cb').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const pid = btn.getAttribute('data-pid');
          const isCurrentlyEnabled = btn.getAttribute('data-enabled') === 'true';
          const nextState = !isCurrentlyEnabled;

          btn.disabled = true;
          const { token, nonce } = await harvestAttestation();
          try {
            const res = await fetch(`/api/v1/project/${pid}/settings`, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ adaptiveCircuitBreaker: nextState, token, nonce }),
            });
            const data = await res.json();
            if (data.ok) {
              await loadProjects();
            } else {
              alert('Failed to update circuit breaker: ' + (data.error || 'Unknown error'));
              btn.disabled = false;
            }
          } catch (err) {
            alert('Error updating circuit breaker: ' + err.message);
            btn.disabled = false;
          }
        });
      });

      projectsList.querySelectorAll('.btn-toggle-openai').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const pid = btn.getAttribute('data-pid');
          const isCurrentlyEnabled = btn.getAttribute('data-enabled') === 'true';
          const nextState = !isCurrentlyEnabled;

          btn.disabled = true;
          const { token, nonce } = await harvestAttestation();
          try {
            const res = await fetch(`/api/v1/project/${pid}/settings`, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ blockOpenAiScrapers: nextState, token, nonce }),
            });
            const data = await res.json();
            if (data.ok) {
              await loadProjects();
            } else {
              alert('Failed to update OpenAI scraper setting: ' + (data.error || 'Unknown error'));
              btn.disabled = false;
            }
          } catch (err) {
            alert('Error updating OpenAI scraper setting: ' + err.message);
            btn.disabled = false;
          }
        });
      });

      projectsList.querySelectorAll('.btn-reset-cb').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const pid = btn.getAttribute('data-pid');
          btn.disabled = true;
          const { token, nonce } = await harvestAttestation();
          try {
            const res = await fetch(`/api/v1/project/${pid}/circuit-breaker/reset`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ token, nonce }),
            });
            const data = await res.json();
            if (data.ok) {
              await loadProjects();
            } else {
              alert('Reset failed: ' + (data.error || 'Unknown error'));
              btn.disabled = false;
            }
          } catch (err) {
            alert('Error resetting vectors: ' + err.message);
            btn.disabled = false;
          }
        });
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

  async function harvestAttestation() {
    if (!window.OBSX) return { token: null, nonce: null };
    try {
      const att = await window.OBSX.getAttestation({ fresh: true });
      return { token: att.token || null, nonce: att.nonce || null };
    } catch (e) {
      console.warn('[Auth Attestation]', e);
      return { token: null, nonce: null };
    }
  }

  // 2. Request OTP Code
  if (btnSendCode) {
    btnSendCode.addEventListener('click', async () => {
      const email = (inpEmail ? inpEmail.value : '').trim();
      if (!email || !email.includes('@')) {
        return showMsg('Please enter a valid operator email address.', true);
      }
      activeEmail = email;
      btnSendCode.disabled = true;
      btnSendCode.textContent = 'Attesting & sending code...';

      const { token, nonce } = await harvestAttestation();

      try {
        const res = await fetch('/api/v1/auth/email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, action: 'start', token, nonce }),
        });
        const data = await res.json();

        if (data.ok) {
          authStepEmail.style.display = 'none';
          authStepCode.style.display = 'flex';
          if (inpCode) {
            inpCode.value = '';
            inpCode.focus();
          }

          if (data.devMode && data.devCode) {
            showMsg('Verification code generated! Dev/Test mode code:', false, data.devCode);
          } else {
            showMsg('Verification code sent from official@obsx.tech to your email!', false);
          }
        } else {
          showMsg(data.error || 'Failed to dispatch verification code.', true);
        }
      } catch (err) {
        showMsg('Network error requesting code: ' + err.message, true);
      } finally {
        btnSendCode.disabled = false;
        btnSendCode.textContent = 'Send Verification Code';
      }
    });
  }

  // 3. Verify OTP Code
  if (btnVerifyCode) {
    btnVerifyCode.addEventListener('click', async () => {
      const code = (inpCode ? inpCode.value : '').trim();
      if (!code || code.length < 6) {
        return showMsg('Please enter the 6-digit one-time code.', true);
      }

      btnVerifyCode.disabled = true;
      btnVerifyCode.textContent = 'Attesting & verifying...';

      const { token, nonce } = await harvestAttestation();

      try {
        const res = await fetch('/api/v1/auth/email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'verify',
            email: activeEmail,
            code,
            token,
            nonce,
          }),
        });
        const data = await res.json();

        if (data.ok) {
          showMsg('Verified successfully! Accessing node dashboard...', false);
          setTimeout(() => {
            checkAuth();
          }, 300);
        } else {
          showMsg(data.error || 'Invalid or expired code.', true);
        }
      } catch (err) {
        showMsg('Verification failed: ' + err.message, true);
      } finally {
        btnVerifyCode.disabled = false;
        btnVerifyCode.textContent = 'Verify & Enter';
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

  // 6. Test Security Alert Dispatch
  if (btnTestAlert) {
    btnTestAlert.addEventListener('click', async () => {
      btnTestAlert.disabled = true;
      btnTestAlert.textContent = 'Sending...';
      try {
        const res = await fetch('/api/v1/alert/test', { method: 'POST' });
        const data = await res.json();
        alert(data.ok ? 'Security alert successfully queued/dispatched!' : ('Error: ' + data.error));
      } catch (err) {
        alert('Alert test error: ' + err.message);
      } finally {
        btnTestAlert.disabled = false;
        btnTestAlert.textContent = 'Send Test Alert';
      }
    });
  }

  const operatorBannerState = {
    lastAdvJson: '',
    adapting: false,
    acceptingLicense: false,
    stickyAdaptNotice: false,
    adaptStatusText: '',
    licenseStatusText: '',
    diffOpen: false,
    diffContent: '',
  };

  function syncBannerFeedbackAndDiff() {
    const adaptFeedback = document.getElementById('operator-adapt-feedback');
    if (adaptFeedback) adaptFeedback.textContent = operatorBannerState.adaptStatusText;
    const licFeedback = document.getElementById('operator-license-feedback');
    if (licFeedback) licFeedback.textContent = operatorBannerState.licenseStatusText;
    const btnDiff = document.getElementById('btn-view-upstream-diff');
    const diffView = document.getElementById('operator-upstream-diff-view');
    if (btnDiff && diffView) {
      diffView.textContent = operatorBannerState.diffContent;
      diffView.style.display = operatorBannerState.diffOpen ? 'block' : 'none';
      btnDiff.textContent = operatorBannerState.diffOpen ? 'Hide Upstream Diff' : 'View Upstream Diff';
    }
  }

  function renderOperatorDriftBanner(adv) {
    let driftBanner = document.getElementById('operator-drift-advisory-banner');
    const hasReminder = Boolean(adv && adv.showReminder);
    if (!hasReminder && !operatorBannerState.stickyAdaptNotice) {
      if (driftBanner) driftBanner.style.display = 'none';
      operatorBannerState.lastAdvJson = '';
      operatorBannerState.adaptStatusText = '';
      operatorBannerState.licenseStatusText = '';
      operatorBannerState.diffOpen = false;
      operatorBannerState.diffContent = '';
      return;
    }

    // Do not rebuild DOM while an operator mutation is in flight or polls would re-enable buttons / orphan handlers.
    if (operatorBannerState.adapting || operatorBannerState.acceptingLicense) return;

    const effectiveAdv = adv || {};
    const advJson = JSON.stringify({
      adv: effectiveAdv,
      stickyAdaptNotice: operatorBannerState.stickyAdaptNotice,
      adaptStatusText: operatorBannerState.adaptStatusText,
    });
    if (driftBanner && advJson === operatorBannerState.lastAdvJson) {
      driftBanner.style.display = 'block';
      return;
    }

    if (!driftBanner) {
      driftBanner = document.createElement('div');
      driftBanner.id = 'operator-drift-advisory-banner';
      driftBanner.style.cssText = 'margin: 0 0 16px 0; padding: 14px 16px; border-radius: 8px; border: 1px solid rgba(245, 158, 11, 0.45); background: rgba(245, 158, 11, 0.08); font-size: 12.5px; line-height: 1.5;';
      const parentTarget = (projectTelemetryContainer && projectTelemetryContainer.parentNode) || document.body;
      parentTarget.insertBefore(driftBanner, projectTelemetryContainer || parentTarget.firstChild);
    }

    operatorBannerState.lastAdvJson = advJson;
    const modFiles = (effectiveAdv.locallyModifiedFiles && effectiveAdv.locallyModifiedFiles.length)
      ? effectiveAdv.locallyModifiedFiles.map((f) => `<code>${escapeHtml(f)}</code>`).join(', ')
      : 'None';
    const upCommits = (effectiveAdv.upstreamCommits && effectiveAdv.upstreamCommits.length)
      ? `<div style="margin-top:6px;"><strong>New Official Upstream Commits (${effectiveAdv.commitsBehind} behind):</strong><ul style="margin:4px 0 0 18px; padding:0;">${effectiveAdv.upstreamCommits.map((c) => `<li><code>${escapeHtml(c)}</code></li>`).join('')}</ul></div>`
      : '';
    const upFiles = (effectiveAdv.upstreamChangedFiles && effectiveAdv.upstreamChangedFiles.length)
      ? `<div style="margin-top:4px;"><strong>Changed Upstream Files:</strong> ${effectiveAdv.upstreamChangedFiles.map((f) => `<code>${escapeHtml(f)}</code>`).join(', ')}</div>`
      : '';
    const overlapWarn = (effectiveAdv.overlappingFiles && effectiveAdv.overlappingFiles.length)
      ? `<div style="margin-top:4px; color:#f59e0b;"><strong>Adaptation Overlap Detected:</strong> Both your local node and official upstream modified ${effectiveAdv.overlappingFiles.map((f) => `<code>${escapeHtml(f)}</code>`).join(', ')}.</div>`
      : '';
    const lic = effectiveAdv.licenseStatus;
    const hasGitDrift = Boolean(effectiveAdv.dirtyWorkingTree || (effectiveAdv.commitsBehind && effectiveAdv.commitsBehind > 0));
    const needsLicenseAction = Boolean(
      lic && (!lic.missingCriticalFiles || !lic.missingCriticalFiles.length) &&
      (!lic.accepted || lic.licenseChanged || lic.safeModeReason === 'corrupt_license_state')
    );
    const licenseNotice = lic && (lic.safeMode || lic.licenseChanged)
      ? `<div style="margin-top:6px; padding:8px 10px; border-radius:6px; border:1px solid rgba(245, 158, 11, 0.35); background:rgba(0,0,0,0.2);">
          <strong>License Integrity Status:</strong> ${lic.safeMode ? `Safe Mode (${escapeHtml(lic.safeModeReason || 'integrity_check')})` : 'Updated LICENSE detected'}
          ${lic.missingCriticalFiles && lic.missingCriticalFiles.length ? ` · Missing: ${lic.missingCriticalFiles.map((f) => `<code>${escapeHtml(f)}</code>`).join(', ')}` : ''}
          ${needsLicenseAction ? ' · <button type="button" id="btn-accept-license" class="btn btn-secondary" style="font-size:11px; padding:2px 8px; margin-left:4px;">Accept Current LICENSE</button>' : ''}
          <span id="operator-license-feedback" style="margin-left:8px; color:#f59e0b;"></span>
        </div>`
      : '';
    const bannerTitle = hasGitDrift
      ? '[PRIVATE OPERATOR ADVISORY] Local Node Customization &amp; Upstream Sync Paused'
      : operatorBannerState.stickyAdaptNotice
      ? '[PRIVATE OPERATOR ADVISORY] Local Adaptation &amp; Stash Notice'
      : '[PRIVATE OPERATOR ADVISORY] License Integrity &amp; Safe Mode Notice';
    const bannerSubtitle = hasGitDrift
      ? 'Auto-updater paused fast-forward sync to protect your local changes. Only you (authenticated operator) can see this notice.'
      : operatorBannerState.stickyAdaptNotice
      ? 'Upstream sync completed, and overlapping local edits remain safely preserved in git stash until you restore or dismiss this notice.'
      : 'Operator attention required for license integrity verification. Only you (authenticated operator) can see this notice.';
    const stickyNoticeBox = (!hasGitDrift && operatorBannerState.stickyAdaptNotice)
      ? `<div style="margin-top:8px; padding:8px 10px; border-radius:6px; border:1px solid rgba(245, 158, 11, 0.35); background:rgba(0,0,0,0.25); display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
          <span id="operator-adapt-feedback" style="font-size:11.5px; color:#f59e0b;"></span>
          <button type="button" id="btn-dismiss-adapt-notice" class="btn btn-secondary" style="font-size:11px; padding:2px 8px;">Dismiss</button>
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
        <button type="button" id="btn-view-upstream-diff" class="btn btn-secondary" style="font-size:11.5px; padding:5px 10px;">View Upstream Diff</button>
        <button type="button" id="btn-auto-adapt-node" class="btn btn-primary" style="font-size:11.5px; padding:5px 10px;">1-Click Auto-Adapt &amp; Rebase</button>
        <span id="operator-adapt-feedback" style="font-size:11.5px; color:#f59e0b;"></span>
      </div>
      <pre id="operator-upstream-diff-view" style="display:none; margin-top:8px; padding:8px; max-height:220px; overflow:auto; background:rgba(0,0,0,0.45); border-radius:4px; font-size:11px; white-space:pre-wrap;"></pre>
      `
      : stickyNoticeBox;

    driftBanner.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
        <strong style="color:#f59e0b;">${bannerTitle}</strong>
        <span class="badge badge-warn">Edition: ${escapeHtml(effectiveAdv.edition || 'modified-local')}</span>
      </div>
      <div style="color:var(--text-muted);">
        ${bannerSubtitle}
      </div>
      ${licenseNotice}
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
          const dData = await dRes.json();
          operatorBannerState.diffContent = `=== UPSTREAM DIFF (HEAD..origin/main) ===\n${dData.upstreamDiff || 'None'}\n\n=== LOCAL WORKING TREE DIFF ===\n${dData.localDiff || 'None'}`;
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
          const aData = await aRes.json();
          const succeeded = Boolean(aRes.ok && aData.ok);
          operatorBannerState.stickyAdaptNotice = !succeeded;
          operatorBannerState.adaptStatusText = succeeded
            ? `Adapted to ${aData.commit}!`
            : (aData.message || aData.error || 'Conflict detected');
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
          const lData = await lRes.json();
          if (lRes.ok && lData.ok) {
            operatorBannerState.licenseStatusText = 'LICENSE Accepted';
            if (activeTelemetryPid) {
              setTimeout(() => loadProjectTelemetry(activeTelemetryPid, false), 400);
            }
          } else {
            operatorBannerState.licenseStatusText = lData.error || 'Acceptance failed';
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
      const data = await res.json();
      if (!data.ok) {
        console.warn('Project telemetry query error:', data.error);
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
        if (recentEvents && Array.isArray(data.recentEvents)) {
          if (data.recentEvents.length === 0) {
            recentEvents.innerHTML = '<p style="color:var(--text-muted); padding:10px 0;">Awaiting incoming actions...</p>';
          } else {
            recentEvents.innerHTML = data.recentEvents.map((ev) => {
              const isPassive = ev.verdict === 'observe' || ev.mode === 'passive';
              const pillClass = ev.verdict === 'accept'
                ? 'badge-good'
                : ev.verdict === 'observe'
                ? (ev.shadowVerdict === 'reject' ? 'badge-warn' : 'badge-good')
                : ev.verdict === 'review'
                ? 'badge-warn'
                : 'badge-bad';
              const labelText = isPassive && ev.shadowVerdict
                ? `OBSERVE (Shadow ${ev.shadowVerdict.toUpperCase()} - Risk ${ev.risk})`
                : `${ev.verdict.toUpperCase()} (Risk ${ev.risk})`;
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
                    ${ev.reasons && ev.reasons.length ? ev.reasons.map(escapeHtml).join(' · ') : 'All cryptographic invariants satisfied'}
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
            threatBreakdown.innerHTML = reasonEntries.map(([code, count]) => `
              <div style="display:flex; justify-content:space-between; padding:5px 0; border-bottom:1px solid var(--border);">
                <span><code>${escapeHtml(code)}</code></span>
                <strong style="color:var(--bad);">${count} caught</strong>
              </div>
            `).join('');
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
      const data = await res.json();
      if (!data.ok) return;

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

  btnDispatchTestAlert?.addEventListener('click', async () => {
    btnDispatchTestAlert.disabled = true;
    btnDispatchTestAlert.textContent = 'Attesting & dispatching...';

    const { token, nonce } = await harvestAttestation();
    const recipient = (inpAlertRecipient ? inpAlertRecipient.value : '').trim();
    try {
      const res = await fetch('/api/v1/alert/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient, token, nonce }),
      });
      const data = await res.json();
      if (data.ok) {
        alert(data.throttled
          ? 'Alert recorded, but throttled by 5-minute circuit breaker to protect operator inbox!'
          : `Critical security advisory dispatched successfully from official@obsx.tech to ${data.alert?.recipient || 'operator'}!`);
        fetchAlertsHistory();
      } else {
        alert('Alert dispatch failed: ' + (data.error || 'Unknown error'));
      }
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      btnDispatchTestAlert.disabled = false;
      btnDispatchTestAlert.textContent = 'Dispatch Test Alert';
    }
  });

  // Initialize
  checkAuth();
  initKinematicRadar();
  fetchAlertsHistory();
  setInterval(fetchAlertsHistory, 6000);
})();
