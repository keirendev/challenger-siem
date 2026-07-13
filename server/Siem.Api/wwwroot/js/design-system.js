(() => {
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  document.querySelectorAll('[data-open-dialog]').forEach(button => {
    const targetId = button.getAttribute('data-open-dialog');
    const dialog = targetId ? document.getElementById(targetId) : null;
    if (!dialog || typeof dialog.showModal !== 'function') return;
    button.addEventListener('click', () => {
      dialog.dataset.returnFocus = button.id || '';
      dialog.showModal();
      const first = dialog.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
      if (first) first.focus();
    });
  });

  document.querySelectorAll('dialog [data-close-dialog]').forEach(button => {
    button.addEventListener('click', () => {
      const dialog = button.closest('dialog');
      if (!dialog) return;
      dialog.close();
      const returnFocusId = dialog.dataset.returnFocus;
      if (returnFocusId) document.getElementById(returnFocusId)?.focus();
    });
  });

  document.querySelectorAll('[data-tabs]').forEach(tablist => {
    const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));
    tabs.forEach((tab, index) => {
      tab.addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        let nextIndex = index;
        if (event.key === 'ArrowLeft') nextIndex = (index + tabs.length - 1) % tabs.length;
        if (event.key === 'ArrowRight') nextIndex = (index + 1) % tabs.length;
        if (event.key === 'Home') nextIndex = 0;
        if (event.key === 'End') nextIndex = tabs.length - 1;
        tabs[nextIndex]?.focus({ preventScroll: reducedMotion });
      });
    });
  });

  document.querySelectorAll('[data-copy-from]').forEach(button => {
    button.addEventListener('click', async () => {
      const target = document.getElementById(button.getAttribute('data-copy-from') || '');
      const value = target && 'value' in target ? target.value : target?.textContent;
      if (!value || !navigator.clipboard) return;
      try {
        await navigator.clipboard.writeText(value);
        button.setAttribute('data-copy-state', 'success');
        button.textContent = 'Copied';
        window.setTimeout(() => {
          button.removeAttribute('data-copy-state');
          button.textContent = 'Copy raw JSON';
        }, 1800);
      } catch (_) {
        button.setAttribute('data-copy-state', 'error');
        button.textContent = 'Copy unavailable';
      }
    });
  });
})();
