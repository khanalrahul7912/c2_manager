/**
 * Interactive terminal component for RemoteOps.
 * Used by both SSH host detail and reverse shell detail pages.
 *
 * Globals expected on the page:
 *   TERMINAL_CONFIG = {
 *     executeUrl:  '/api/ssh-execute/1'  or  '/api/shell-execute/1',
 *     statusUrl:   null                  or  '/api/shell-status/1',
 *     shellType:   'ssh' | 'reverse',
 *     promptLabel: 'root@host:~$',
 *     isConnected: true | false,
 *     csrfToken:   '...',
 *   }
 */

(function () {
  'use strict';

  /* ── DOM refs ── */
  const body       = document.getElementById('term-body');
  const input      = document.getElementById('term-input');
  const form       = document.getElementById('term-form');
  const statusDot  = document.getElementById('term-status-dot');
  const statusText = document.getElementById('term-status-text');
  const banner     = document.getElementById('term-disconnect-banner');

  if (!body || !input || !form) return;  // not on a terminal page

  const CFG = window.TERMINAL_CONFIG || {};

  /* ── State ── */
  let history     = [];
  let historyIdx  = -1;
  let connected   = CFG.isConnected;
  let executing   = false;

  /* ── Helpers ── */
  function esc(text) {
    const d = document.createElement('div');
    d.textContent = text;
    return d.innerHTML;
  }

  function scrollBottom() {
    body.scrollTop = body.scrollHeight;
  }

  function setConnected(val) {
    connected = val;
    if (statusDot)  statusDot.className  = 'term-dot ' + (val ? 'online' : 'offline');
    if (statusText) statusText.textContent = val ? 'Connected' : 'Disconnected';
    if (banner) banner.style.display = val ? 'none' : 'flex';
    if (input)  input.disabled = !val;
  }

  function appendLine(html) {
    const div = document.createElement('div');
    div.innerHTML = html;
    body.appendChild(div);
    scrollBottom();
  }

  function appendPrompt(cmd) {
    appendLine('<span class="term-prompt-label">' + esc(CFG.promptLabel || '$') + '</span> ' +
               '<span class="term-cmd">' + esc(cmd) + '</span>');
  }

  function appendStdout(text) {
    if (!text) return;
    appendLine('<span class="term-stdout">' + esc(text) + '</span>');
  }

  function appendStderr(text) {
    if (!text) return;
    appendLine('<span class="term-stderr">' + esc(text) + '</span>');
  }

  function appendError(text) {
    appendLine('<span class="term-stderr">Error: ' + esc(text) + '</span>');
  }

  function appendInfo(text) {
    appendLine('<span class="term-info">' + esc(text) + '</span>');
  }

  /* ── Execute command ── */
  async function execute(cmd) {
    if (executing) return;
    executing = true;
    appendPrompt(cmd);

    try {
      const resp = await fetch(CFG.executeUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': CFG.csrfToken,
        },
        body: JSON.stringify({ command: cmd }),
      });

      const data = await resp.json();

      if (resp.status === 503) {
        /* shell disconnected */
        setConnected(false);
        appendError(data.error || 'Shell disconnected');
      } else if (data.success) {
        if (data.stdout) appendStdout(data.stdout);
        if (data.stderr) appendStderr(data.stderr);
      } else {
        appendError(data.error || 'Command failed');
      }
    } catch (err) {
      appendError('Network error: ' + err.message);
    } finally {
      executing = false;
    }
  }

  /* ── Form submit ── */
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    const cmd = input.value.trim();
    if (!cmd) return;

    history.push(cmd);
    historyIdx = history.length;
    input.value = '';
    execute(cmd);
  });

  /* ── Keyboard: history, Ctrl-C, Ctrl-L ── */
  input.addEventListener('keydown', function (e) {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (historyIdx > 0) {
        historyIdx--;
        input.value = history[historyIdx];
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIdx < history.length - 1) {
        historyIdx++;
        input.value = history[historyIdx];
      } else {
        historyIdx = history.length;
        input.value = '';
      }
    } else if (e.key === 'c' && e.ctrlKey) {
      /* Ctrl-C: cancel current input */
      e.preventDefault();
      if (input.value) {
        appendPrompt(input.value + '^C');
        input.value = '';
        historyIdx = history.length;
      }
    } else if (e.key === 'l' && e.ctrlKey) {
      /* Ctrl-L: clear terminal */
      e.preventDefault();
      body.innerHTML = '';
    }
  });

  /* ── Click terminal body → focus input ── */
  body.addEventListener('click', function (e) {
    /* Only focus if user didn't select text */
    if (!window.getSelection().toString()) {
      input.focus();
    }
  });

  /* ── Status polling (reverse shells only) ── */
  if (CFG.statusUrl) {
    async function pollStatus() {
      try {
        const resp = await fetch(CFG.statusUrl);
        const data = await resp.json();
        const wasDisconnected = !connected;
        setConnected(data.connected);
        if (wasDisconnected && data.connected) {
          appendInfo('✓ Shell reconnected');
        }
      } catch (_) { /* ignore network hiccups */ }
    }

    setInterval(pollStatus, 5000);
  }

  /* ── Initial focus ── */
  if (connected && input) {
    input.focus();
  }

  /* ── Copy all output ── */
  window.copyTerminalOutput = function (btn) {
    const text = body.innerText;
    navigator.clipboard.writeText(text).then(function () {
      const orig = btn.textContent;
      btn.textContent = '✓ Copied!';
      setTimeout(function () { btn.textContent = orig; }, 1500);
    }).catch(function () {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    });
  };
})();
