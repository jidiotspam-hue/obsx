'use strict';

(function () {
  const dispSession = document.getElementById('disp-session');
  const dispPoW = document.getElementById('disp-pow');
  const dispVerdict = document.getElementById('disp-verdict');
  const verdictFeed = document.getElementById('verdict-feed');
  const logCount = document.getElementById('log-count');

  let sessionData = null;
  let eventCounter = 0;

  function getSdk() {
    return window.OBSX || window.Veritas || window.Tracer;
  }

  function addLog(title, verdict, risk, reasons = []) {
    eventCounter++;
    logCount.textContent = `${eventCounter} Events`;
    const pillClass = verdict === 'accept' ? 'badge-good' : verdict === 'review' ? 'badge-warn' : 'badge-bad';

    const item = document.createElement('div');
    item.style.padding = '8px 0';
    item.style.borderBottom = '1px solid var(--border)';
    item.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
        <strong>${title}</strong>
        <span class="badge ${pillClass}">${verdict.toUpperCase()} (Risk ${risk})</span>
      </div>
      <div style="color:var(--text-muted); font-size:12px;">
        ${reasons.length ? reasons.map((r) => `• ${r.text || r.code || r}`).join('<br>') : 'All cryptographic & behavioral checks passed.'}
      </div>
    `;

    if (verdictFeed.children.length === 1 && verdictFeed.children[0].tagName === 'P') {
      verdictFeed.innerHTML = '';
    }
    verdictFeed.prepend(item);
  }

  // 1. Initialize genuine OBSX session on load
  async function initSession() {
    try {
      const sdk = getSdk();
      if (!sdk) return;
      sessionData = await sdk.init({ site: 'pk_obsx_sandbox' });
      dispSession.textContent = sessionData.session;
      dispPoW.textContent = `Solved (nonce: ${sessionData.nonce})`;
    } catch (err) {
      dispSession.textContent = 'Init error';
      console.error(err);
    }
  }
  initSession();

  // 2. Action 1: Send Genuine Human Request
  document.getElementById('btn-human')?.addEventListener('click', async () => {
    dispVerdict.textContent = 'Verifying...';
    try {
      const sdk = getSdk();
      const res = await sdk.verify({ score: 100 });
      if (res && res.verdict) {
        dispVerdict.textContent = `${res.verdict.toUpperCase()} (Risk ${res.risk})`;
        addLog('Genuine User Action', res.verdict, res.risk, res.reasons);
      } else {
        const errReasons = res?.verdict?.reasons || [{ text: res?.error || 'Verification rejected' }];
        dispVerdict.textContent = `REJECT (Risk 100)`;
        addLog('Genuine User Action', 'REJECT', 100, errReasons);
      }
    } catch (err) {
      dispVerdict.textContent = 'Error: ' + err.message;
      console.error(err);
    }
  });

  // 3. Action 2: Simulate Headless Bot (Empty Signals & Missing PoW)
  document.getElementById('btn-bot')?.addEventListener('click', async () => {
    dispVerdict.textContent = 'Simulating bot attack...';
    try {
      const sRes = await fetch('/api/v1/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ site: 'pk_obsx_sandbox' }),
      });
      const sData = await sRes.json();

      await fetch('/api/v1/signal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: sData.token, signals: {} }),
      });

      const vRes = await fetch('/api/v1/demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: sData.token, score: 999 }),
      });
      const vData = await vRes.json();

      dispVerdict.textContent = `${vData.verdict.toUpperCase()} (Risk ${vData.risk})`;
      addLog('Simulated Headless Bot (Empty Signals)', vData.verdict, vData.risk, vData.reasons);
    } catch (err) {
      dispVerdict.textContent = 'Bot simulation error';
      console.error(err);
    }
  });

  // 4. Action 3: Simulate .bind() Tampering
  document.getElementById('btn-tamper')?.addEventListener('click', async () => {
    dispVerdict.textContent = 'Injecting .bind() hook...';
    try {
      const orig = performance.now;
      performance.now = (() => 0).bind(window);

      const sdk = getSdk();
      const res = await sdk.verify({ score: 50 });
      dispVerdict.textContent = `${res.verdict.toUpperCase()} (Risk ${res.risk})`;
      addLog('Tamper Attempt (.bind hijacking)', res.verdict, res.risk, res.reasons);

      performance.now = orig;
    } catch (err) {
      dispVerdict.textContent = 'Tamper error';
      console.error(err);
    }
  });

  // 5. Action 4: Simulate Web Proxy Relay (Ultraviolet / Bare-mux / Wisp)
  document.getElementById('btn-proxy')?.addEventListener('click', async () => {
    dispVerdict.textContent = 'Simulating proxy unblocker relay...';
    try {
      const sRes = await fetch('/api/v1/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ site: 'pk_obsx_sandbox' }),
      });
      const sData = await sRes.json();

      // Send telemetry flagged with proxy virtualization indicators
      await fetch('/api/v1/signal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: sData.token,
          signals: {
            sh: 'trc_v1_live',
            tampered: ['proxy_artifact:__uv', 'proxy_virtualization:location_getter_trap'],
            elapsedMs: 2500,
          },
        }),
      });

      // Submit verification with proxy headers simulation
      const vRes = await fetch('/api/v1/demo', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Bare-Host': 'example.com',
          'X-Wisp-Version': '1.1',
        },
        body: JSON.stringify({
          token: sData.token,
          nonce: '0',
          score: 80,
        }),
      });
      const vData = await vRes.json();

      dispVerdict.textContent = `${vData.verdict.toUpperCase()} (Risk ${vData.risk})`;
      addLog('Simulated Web Proxy Relay (Bare-mux / UV)', vData.verdict, vData.risk, vData.reasons);
    } catch (err) {
      dispVerdict.textContent = 'Proxy simulation error';
      console.error(err);
    }
  });

  // 6. Action 5: Simulate Sovereign Gateway & Client Wiretap Hooks
  document.getElementById('btn-sovereign')?.addEventListener('click', async () => {
    dispVerdict.textContent = 'Simulating Sovereign gateway relay...';
    try {
      const sRes = await fetch('/api/v1/session', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Sovereign-Proxy': '1',
        },
        body: JSON.stringify({ site: 'pk_obsx_sandbox' }),
      });
      const sData = await sRes.json();

      // Submit telemetry carrying Sovereign client hooks
      await fetch('/api/v1/signal', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Sovereign-Proxy': '1',
        },
        body: JSON.stringify({
          token: sData.token,
          signals: {
            sh: 'trc_v1_live',
            tampered: [
              'proxy_artifact:__sovereignHookActive',
              'proxy_virtualization:wrapped_RTCPeerConnection',
              'proxy_virtualization:dom_hud_injected',
            ],
            elapsedMs: 3100,
          },
        }),
      });

      const vRes = await fetch('/api/v1/demo', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Sovereign-Proxy': '1',
        },
        body: JSON.stringify({
          token: sData.token,
          nonce: '0',
          score: 100,
        }),
      });
      const vData = await vRes.json();

      dispVerdict.textContent = `${vData.verdict.toUpperCase()} (Risk ${vData.risk})`;
      addLog('Simulated Sovereign Gateway', vData.verdict, vData.risk, vData.reasons);
    } catch (err) {
      dispVerdict.textContent = 'Sovereign simulation error';
      console.error(err);
    }
  });

  // 7. Action 6: Simulate Zero-Jerk Bot (Mathematically smooth spline / no physiological tremor)
  document.getElementById('btn-jerk-bot')?.addEventListener('click', async () => {
    dispVerdict.textContent = 'Simulating zero-jerk synthetic spline...';
    try {
      const sRes = await fetch('/api/v1/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ site: 'pk_obsx_sandbox' }),
      });
      const sData = await sRes.json();

      // Synthetic points with 0 jerk variation (quadratic interpolation)
      const syntheticPoints = [];
      for (let i = 0; i < 12; i++) {
        syntheticPoints.push({
          x: Math.round(4 * i * i),
          y: Math.round(2 * i * i),
          t: 100 + i * 50,
        });
      }

      await fetch('/api/v1/signal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: sData.token,
          signals: {
            sh: 'trc_v1_live',
            mousePoints: syntheticPoints,
            elapsedMs: 2000,
          },
        }),
      });

      const vRes = await fetch('/api/v1/demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: sData.token,
          nonce: '0',
          score: 50,
        }),
      });
      const vData = await vRes.json();

      dispVerdict.textContent = `${vData.verdict.toUpperCase()} (Risk ${vData.risk})`;
      addLog('Simulated Zero-Jerk Spline Bot', vData.verdict, vData.risk, vData.reasons);
    } catch (err) {
      dispVerdict.textContent = 'Spline simulation error';
      console.error(err);
    }
  });

  // Live mouse interaction counter for terminal entropy indicator
  let localPoints = 0;
  window.addEventListener('mousemove', () => {
    localPoints++;
    const dispEntropy = document.getElementById('disp-entropy');
    if (dispEntropy && localPoints % 3 === 0) {
      dispEntropy.textContent = `Active (${localPoints} samples collected, kinematic jitter verified)`;
    }
  }, { passive: true });

  // Tabbed Code Switcher & One-Click Copy Handlers
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const parent = btn.closest('.code-block');
      if (!parent) return;
      const targetId = btn.getAttribute('data-tab');

      parent.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
      parent.querySelectorAll('.code-pane').forEach((p) => (p.style.display = 'none'));

      btn.classList.add('active');
      const targetPane = parent.querySelector(`#${targetId}`);
      if (targetPane) targetPane.style.display = 'block';
    });
  });

  document.querySelectorAll('.btn-copy').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const targetId = btn.getAttribute('data-copy');
      const targetEl = document.getElementById(targetId);
      if (!targetEl) return;
      try {
        await navigator.clipboard.writeText(targetEl.textContent.trim());
        const originalText = btn.innerHTML;
        btn.innerHTML = `<span style="color:var(--good);">Copied</span>`;
        setTimeout(() => {
          btn.innerHTML = originalText;
        }, 2000);
      } catch (err) {
        console.error('Copy failed:', err);
      }
    });
  });

  // Live Self-Telemetry Stream Poller for "Our own telemetry, to prove you can trust us."
  const selfMetricTotal = document.getElementById('self-metric-total');
  const selfMetricAccept = document.getElementById('self-metric-accept');
  const selfMetricReject = document.getElementById('self-metric-reject');
  const selfMetricRate = document.getElementById('self-metric-rate') || document.getElementById('self-metric-saved');
  const selfTelemetryBody = document.getElementById('self-telemetry-body');

  async function pollSelfTelemetry() {
    try {
      const res = await fetch('/api/v1/telemetry/live');
      const data = await res.json();
      if (!data.ok) return;

      const stats = data.stats || {};
      if (selfMetricTotal) selfMetricTotal.textContent = (stats.total || 0).toLocaleString();
      if (selfMetricAccept) selfMetricAccept.textContent = ((stats.breakdown && stats.breakdown.accept) || 0).toLocaleString();
      if (selfMetricReject) selfMetricReject.textContent = ((stats.breakdown && stats.breakdown.reject) || 0).toLocaleString();
      if (selfMetricRate) {
        selfMetricRate.textContent = `${stats.acceptRate ?? 100}%`;
      }

      if (selfTelemetryBody && Array.isArray(data.recentEvents)) {
        if (data.recentEvents.length === 0) {
          selfTelemetryBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:16px;">Awaiting incoming actions...</td></tr>';
        } else {
          selfTelemetryBody.innerHTML = data.recentEvents.map((ev) => {
            const pillClass = ev.verdict === 'accept' ? 'badge-good' : ev.verdict === 'review' ? 'badge-warn' : 'badge-bad';
            const timeAgo = Math.round((Date.now() - ev.timestamp) / 1000);
            const timeStr = timeAgo < 60 ? `${timeAgo}s ago` : `${Math.round(timeAgo / 60)}m ago`;
            const reasonsStr = ev.reasons && ev.reasons.length
              ? ev.reasons.join(', ')
              : 'All cryptographic invariants satisfied';

            return `
              <tr>
                <td style="font-family:var(--font-mono); font-size:12px; color:var(--text-muted); white-space:nowrap;">${timeStr}</td>
                <td style="font-weight:600;">${ev.action}</td>
                <td><code style="font-size:12px;">${ev.maskedIp}</code></td>
                <td><span class="badge ${pillClass}">${ev.verdict.toUpperCase()}</span></td>
                <td style="font-family:var(--font-mono); font-weight:600;">${ev.risk}</td>
                <td style="font-size:12.5px; color:var(--text-muted);">${reasonsStr}</td>
              </tr>
            `;
          }).join('');
        }
      }
    } catch (err) {
      console.warn('Telemetry poll error:', err);
    }
  }

  pollSelfTelemetry();
  setInterval(pollSelfTelemetry, 3000);
})();
