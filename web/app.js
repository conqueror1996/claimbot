/* ═══════════════════════════════════════
   Casino Bot — App Logic
   ═══════════════════════════════════════ */
(function () {
  'use strict';

  const $ = id => document.getElementById(id);

  let evtSource = null;
  let running   = false;

  // ── Init ──
  function init() {
    $('bot-form').addEventListener('submit', onStart);
    $('btn-clear').addEventListener('click', clearConsole);
  }

  // ── Start ──
  async function onStart(e) {
    e.preventDefault();
    if (running) return;

    const radio    = document.querySelector('input[name="domain"]:checked');
    const username = $('input-username').value.trim();
    const password = $('input-password').value.trim();
    const amount   = $('input-amount').value.trim();

    if (!radio || !username || !password || !amount) {
      addLine('error', 'Please fill in all fields');
      return;
    }

    clearConsole();
    setStatus('running');
    setBtn(true);
    connectSSE();

    try {
      const res = await fetch('/api/bot/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain_id: radio.value, amount, username, password }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
    } catch (err) {
      addLine('error', `Failed to start: ${err.message}`);
      setStatus('error');
      setBtn(false);
      closeSSE();
    }
  }

  // ── SSE ──
  function connectSSE() {
    closeSSE();
    evtSource = new EventSource('/api/bot/events');
    evtSource.onmessage = e => {
      try { handleEvent(JSON.parse(e.data)); } catch (_) {}
    };
    evtSource.onerror = () => {
      if (!running) closeSSE();
    };
  }

  function handleEvent(ev) {
    if (ev.type === 'log') {
      if (ev.level === 'section') addSection(ev.message);
      else addLine(ev.level || 'info', ev.message);
    } else if (ev.type === 'status') {
      if (ev.level === 'complete') {
        setStatus('complete'); setBtn(false);
        addLine('success', ev.message); closeSSE();
      } else if (ev.level === 'error') {
        setStatus('error'); setBtn(false);
        addLine('error', ev.message); closeSSE();
      }
    }
  }

  function closeSSE() {
    setTimeout(() => {
      if (evtSource) { evtSource.close(); evtSource = null; }
    }, 600);
  }

  // ── Console ──
  function clearConsole() {
    $('console-output').innerHTML = `
      <div class="empty-state" id="empty-state">
        <div class="empty-icon">♠ ♥ ♦ ♣</div>
        <div class="empty-title">Bot Ready</div>
        <div class="empty-sub">Fill in your details and press Run Bot</div>
      </div>`;
  }

  function rmEmpty() {
    const e = $('empty-state');
    if (e) e.remove();
  }

  function addSection(msg) {
    rmEmpty();
    const el = document.createElement('div');
    el.className = 'log-line section';
    el.innerHTML = `<span class="log-msg">${esc(msg)}</span>`;
    $('console-output').appendChild(el);
    scroll();
  }

  function addLine(level, msg) {
    if (!msg || !msg.trim()) return;
    rmEmpty();
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
    const el = document.createElement('div');
    el.className = `log-line ${level}`;
    el.innerHTML = `<span class="log-ts">${ts}</span><span class="log-msg">${esc(msg)}</span>`;
    $('console-output').appendChild(el);
    scroll();
  }

  function scroll() {
    const c = $('console-output');
    c.scrollTop = c.scrollHeight;
  }

  // ── Status ──
  function setStatus(state) {
    running = state === 'running';
    $('status-pill').className = `status-pill ${state}`;
    $('status-dot').className  = `status-dot`;
    const map = { idle: 'Idle', running: 'Running...', complete: 'Complete', error: 'Error' };
    $('status-text').textContent = map[state] || state;
  }

  // ── Button ──
  function setBtn(loading) {
    const btn  = $('btn-start');
    const icon = $('btn-icon');
    const txt  = $('btn-text');
    btn.disabled = loading;
    if (loading) {
      icon.textContent = '◌';
      icon.classList.add('spinning');
      txt.textContent = 'Running...';
    } else {
      icon.textContent = '▶';
      icon.classList.remove('spinning');
      txt.textContent = 'Run Bot';
    }
  }

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  document.addEventListener('DOMContentLoaded', init);
})();
