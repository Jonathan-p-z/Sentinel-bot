/* Bastion Dashboard — App JS */

// ── Mobile sidebar toggle ─────────────────────────────
(function () {
  const toggle = document.getElementById('sidebar-toggle');
  const sidebar = document.querySelector('.sidebar');
  if (toggle && sidebar) {
    toggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
    document.addEventListener('click', (e) => {
      if (sidebar.classList.contains('open') &&
          !sidebar.contains(e.target) &&
          e.target !== toggle) {
        sidebar.classList.remove('open');
      }
    });
  }
})();

// ── Auto-dismiss alerts ───────────────────────────────
(function () {
  document.querySelectorAll('[data-autohide]').forEach(el => {
    const delay = parseInt(el.dataset.autohide) || 3000;
    setTimeout(() => {
      el.style.transition = 'opacity .4s';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 400);
    }, delay);
  });
})();

// ── Time-ago live update ──────────────────────────────
(function () {
  function timeAgo(ts) {
    const diff = (Date.now() / 1000) - ts;
    if (diff < 60)     return 'just now';
    if (diff < 3600)   return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400)  return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  }
  document.querySelectorAll('[data-ts]').forEach(el => {
    const ts = parseInt(el.dataset.ts);
    if (!isNaN(ts)) el.textContent = timeAgo(ts);
  });
})();

// ── Copy to clipboard ─────────────────────────────────
document.addEventListener('click', function (e) {
  const btn = e.target.closest('[data-copy]');
  if (!btn) return;
  const text = btn.dataset.copy;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
});
