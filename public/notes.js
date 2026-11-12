'use strict';

(function () {
  let activeUser = null;
  let activeMode = 'obsx'; // 'obsx' or 'advisory'

  const notesContainer = document.getElementById('notes-container');
  const notesCount = document.getElementById('notes-count');
  const authUserLabel = document.getElementById('auth-user-label');
  const btnQuickLogin = document.getElementById('btn-quick-login');
  const btnModeObsx = document.getElementById('btn-mode-obsx');
  const btnModeAdvisory = document.getElementById('btn-mode-advisory');
  const noteProtectionPill = document.getElementById('note-protection-pill');
  const btnSaveNote = document.getElementById('btn-save-note');
  const inpNoteTitle = document.getElementById('inp-note-title');
  const inpNoteContent = document.getElementById('inp-note-content');
  const benchmarkResults = document.getElementById('benchmark-results');
  const benchmarkTableBody = document.getElementById('benchmark-table-body');

  // 1. Initialize OBSX SDK
  async function initObsx() {
    try {
      if (window.OBSX) {
        await window.OBSX.init({ site: 'pk_obsx_sandbox' });
      }
    } catch (err) {
      console.warn('[Notes App] OBSX initialization:', err.message);
    }
  }
  initObsx();

  // 2. Load User Profile
  async function loadUser() {
    try {
      const res = await fetch('/api/v1/me');
      const data = await res.json();
      if (data.ok && data.user) {
        activeUser = data.user;
        authUserLabel.textContent = data.user.email;
        btnQuickLogin.textContent = 'Sign Out';
      } else {
        activeUser = null;
        authUserLabel.textContent = 'Demo Guest';
        btnQuickLogin.textContent = 'Sign In';
      }
      loadNotes();
    } catch {
      activeUser = null;
    }
  }

  async function getAttestationSafe() {
    if (!window.OBSX) return { token: null, nonce: null };
    try {
      const att = await window.OBSX.getAttestation({ fresh: true });
      return { token: att.token || null, nonce: att.nonce || null };
    } catch {
      return { token: null, nonce: null };
    }
  }

  // 3. Quick Login / Sign Out
  btnQuickLogin?.addEventListener('click', async () => {
    if (activeUser) {
      await fetch('/api/v1/auth/logout', { method: 'POST' });
      activeUser = null;
      loadUser();
      return;
    }

    const email = prompt('Enter your email to sign in via 6-digit verification code:');
    if (!email) return;

    try {
      const { token: startToken, nonce: startNonce } = await getAttestationSafe();

      const startRes = await fetch('/api/v1/auth/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'start', email, token: startToken, nonce: startNonce }),
      });
      const startData = await startRes.json();
      if (!startData.ok) {
        alert('Login failed: ' + (startData.error || 'Unknown error'));
        return;
      }

      const promptMsg = startData.devMode
        ? `[DEV MODE] Verification Code: ${startData.devCode}\nEnter code:`
        : `A 6-digit verification code was dispatched from official@obsx.tech.\nEnter code:`;

      const code = prompt(promptMsg);
      if (!code) return;

      const { token: verifyToken, nonce: verifyNonce } = await getAttestationSafe();

      const verifyRes = await fetch('/api/v1/auth/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'verify', email, code, token: verifyToken, nonce: verifyNonce }),
      });
      const verifyData = await verifyRes.json();
      if (!verifyData.ok) {
        alert('Verification failed: ' + (verifyData.error || 'Invalid code'));
        return;
      }

      loadUser();
    } catch (err) {
      alert('Error: ' + err.message);
    }
  });

  // 4. Protection Mode Switcher
  btnModeObsx?.addEventListener('click', () => {
    activeMode = 'obsx';
    btnModeObsx.className = 'mode-btn active obsx';
    btnModeAdvisory.className = 'mode-btn';
    noteProtectionPill.className = 'badge badge-good';
    noteProtectionPill.textContent = 'OBSX Shield Active (PoW + Jerk + Anti-Proxy)';
  });

  btnModeAdvisory?.addEventListener('click', () => {
    activeMode = 'advisory';
    btnModeAdvisory.className = 'mode-btn active advisory';
    btnModeObsx.className = 'mode-btn';
    noteProtectionPill.className = 'badge badge-warn';
    noteProtectionPill.textContent = 'Advisory Mode — Unattested Telemetry';
  });

  // 5. Load Notes
  async function loadNotes() {
    try {
      const res = await fetch('/api/v1/notes');
      const data = await res.json();
      if (!data.ok || !Array.isArray(data.notes)) {
        notesContainer.innerHTML = '<p style="color: var(--text-muted); font-size: 14px;">Sign in or create a note to see your attested notes.</p>';
        notesCount.textContent = '0 Notes';
        return;
      }

      notesCount.textContent = `${data.notes.length} Notes`;
      if (data.notes.length === 0) {
        notesContainer.innerHTML = '<p style="color: var(--text-muted); font-size: 14px;">No notes yet. Create one above.</p>';
        return;
      }

      notesContainer.innerHTML = data.notes
        .map((n) => {
          const isObsx = n.protection === 'obsx';
          const pill = isObsx
            ? '<span class="badge badge-good">[OBSX ATTESTED]</span>'
            : '<span class="badge badge-warn">[ADVISORY ONLY]</span>';
          const dateStr = new Date(n.created).toLocaleString();

          return `
            <div class="note-card" id="note-${n.id}">
              <div class="note-header">
                <div>
                  <span class="note-title">${escapeHtml(n.title)}</span>
                  ${pill}
                </div>
                <button type="button" class="btn btn-secondary" onclick="window.__deleteNote('${n.id}')" style="padding: 2px 8px; font-size: 11px;">Delete</button>
              </div>
              <div class="note-content">${escapeHtml(n.content)}</div>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">Created ${dateStr}</div>
            </div>
          `;
        })
        .join('');
    } catch (err) {
      console.error(err);
    }
  }

  // 6. Save Note
  btnSaveNote?.addEventListener('click', async () => {
    const title = inpNoteTitle.value.trim();
    const content = inpNoteContent.value.trim();
    if (!title && !content) {
      alert('Please enter a note title or content.');
      return;
    }

    btnSaveNote.disabled = true;
    btnSaveNote.textContent = 'Attesting...';

    async function submitNote(isRetry = false) {
      let payload = {
        title,
        content,
        protectionMode: activeMode,
      };

      if (activeMode === 'obsx') {
        if (!window.OBSX) {
          alert('Security Attestation Engine is initializing. Please wait a moment and try again.');
          return;
        }
        // Collect real biometric entropy & solve micro-PoW challenge
        const attestation = await window.OBSX.getAttestation({ fresh: isRetry });
        if (!attestation || !attestation.token) {
          alert('Unable to generate security attestation token. Please refresh the page.');
          return;
        }
        payload.token = attestation.token;
        payload.nonce = attestation.nonce;
      } else {
        // Advisory mode: submits advisory mock
        payload.telemetry = { advisory: true };
      }

      const res = await fetch('/api/v1/notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();

      // If token expired, spent, or server restarted, transparently auto-rehandshake once
      const isStale = !data.ok && data.verdict?.reasons?.some((r) => r.code === 'invalid_token' || r.code === 'token_reused' || r.code === 'expired');
      if (isStale && !isRetry && window.OBSX) {
        btnSaveNote.textContent = 'Re-authenticating...';
        await new Promise((resolve) => setTimeout(resolve, 250));
        await window.OBSX.rehandshake();
        return submitNote(true);
      }

      if (!data.ok) {
        alert('Blocked by Security Gate: ' + (data.verdict?.reasons?.map((r) => r.text || r.code).join(', ') || data.error));
      } else {
        inpNoteTitle.value = '';
        inpNoteContent.value = '';
        loadNotes();
      }
    }

    try {
      await submitNote();
    } catch (err) {
      alert('Failed to save note: ' + err.message);
    } finally {
      btnSaveNote.disabled = false;
      btnSaveNote.textContent = 'Save Note';
    }
  });

  // 7. Delete Note Helper
  window.__deleteNote = async function (id) {
    if (!confirm('Are you sure you want to delete this note?')) return;
    try {
      const { token, nonce } = await getAttestationSafe();
      const res = await fetch(`/api/v1/notes/${id}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'X-OBSX-Token': token || '',
          'X-OBSX-Nonce': nonce || '',
        },
        body: JSON.stringify({ token, nonce }),
      });
      const data = await res.json();
      if (!data.ok && data.error === 'security_gate_rejected') {
        alert('Delete blocked by OBSX Security Gate: ' + (data.reasons?.[0]?.text || data.error));
        return;
      }
      loadNotes();
    } catch (err) {
      alert('Error deleting note: ' + err.message);
    }
  };

  // 8. Attack Simulator & Live Benchmark Arena
  function renderBenchmarkRow(vectorName, obsxResult, advisoryResult) {
    benchmarkResults.style.display = 'block';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${escapeHtml(vectorName)}</strong></td>
      <td><span class="badge ${obsxResult.badge}">${escapeHtml(obsxResult.text)}</span></td>
      <td><span class="badge ${advisoryResult.badge}">${escapeHtml(advisoryResult.text)}</span></td>
    `;
    benchmarkTableBody.prepend(tr);
  }

  async function runAttackProbe(vectorName, mode) {
    try {
      const res = await fetch('/api/v1/vault/drain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode,
          attackVector: vectorName,
          amount: 500,
        }),
      });
      const data = await res.json();
      if (mode === 'obsx') {
        if (!data.drained) {
          const reasonText = data.verdict?.reasons?.[0]?.text || data.verdict?.reasons?.[0]?.code || 'Attack Defeated';
          return {
            badge: 'badge-good',
            text: `HARD REJECT (Risk ${data.verdict?.risk || 100} · ${reasonText})`,
          };
        }
        return { badge: 'badge-warn', text: 'ALLOWED' };
      } else {
        if (data.drained) {
          return {
            badge: 'badge-bad',
            text: 'BYPASSED ($500 Drained at Risk 0)',
          };
        }
        return { badge: 'badge-good', text: 'BLOCKED' };
      }
    } catch {
      return { badge: 'badge-warn', text: 'Probe Error' };
    }
  }

  // Attack 1: Empty Signals {}
  document.getElementById('btn-atk-empty')?.addEventListener('click', async () => {
    const obsxRes = await runAttackProbe('empty_signals', 'obsx');
    const advisoryRes = await runAttackProbe('empty_signals', 'advisory');
    renderBenchmarkRow('Empty Payload {} / No PoW', obsxRes, advisoryRes);
  });

  // Attack 2: Web Proxy Relay (Bare-Mux / Sovereign Gateway)
  document.getElementById('btn-atk-proxy')?.addEventListener('click', async () => {
    const obsxRes = await runAttackProbe('proxy_virtualization', 'obsx');
    const advisoryRes = await runAttackProbe('proxy_virtualization', 'advisory');
    renderBenchmarkRow('Web Proxy Relay (Bare/Wisp/Sovereign Gateway)', obsxRes, advisoryRes);
  });

  // Attack 3: Constant-Acceleration Spline (Zero Jerk)
  document.getElementById('btn-atk-jerk')?.addEventListener('click', async () => {
    const obsxRes = await runAttackProbe('zero_jerk_spline', 'obsx');
    const advisoryRes = await runAttackProbe('zero_jerk_spline', 'advisory');
    renderBenchmarkRow('Zero-Jerk Synthetic Spline', obsxRes, advisoryRes);
  });

  // Attack 4: .bind() Function Tampering
  document.getElementById('btn-atk-tamper')?.addEventListener('click', async () => {
    const obsxRes = await runAttackProbe('bind_tamper', 'obsx');
    const advisoryRes = await runAttackProbe('bind_tamper', 'advisory');
    renderBenchmarkRow('Function.prototype.bind Poison', obsxRes, advisoryRes);
  });

  // Attack 5: Concurrent Token Replay Race
  document.getElementById('btn-atk-replay')?.addEventListener('click', async () => {
    const obsxRes = await runAttackProbe('token_replay', 'obsx');
    const advisoryRes = await runAttackProbe('token_replay', 'advisory');
    renderBenchmarkRow('Concurrent Token Replay Race', obsxRes, advisoryRes);
  });

  function escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  loadUser();
})();
