(function() {
  function showToast(msg) {
    let t = document.getElementById('toast');
    if (!t) { t = document.createElement('div'); t.id = 'toast'; t.className = 'toast'; document.body.appendChild(t); }
    t.innerHTML = '<span style="font-weight:700;color:#fff;">✓</span><span>' + msg + '</span>';
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 1800);
  }
  function copyText(text, label) {
    navigator.clipboard.writeText(text).then(() => showToast(label + ' copied')).catch(() => {
      const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); showToast(label + ' copied');
    });
  }
  window.copyCell = function(btn, label) {
    event.stopPropagation();
    const cell = btn.closest('td,th');
    const text = cell.querySelector('.cell-text, .preview-text')?.innerText || cell.innerText;
    copyText(text.trim(), label || 'Value');
    btn.classList.add('copied'); btn.innerText = '✓';
    setTimeout(() => { btn.classList.remove('copied'); btn.innerText = 'Copy'; }, 1200);
  };
  window.copyRow = function(btn) {
    event.stopPropagation();
    const row = btn.closest('tr');
    const texts = Array.from(row.querySelectorAll('td')).map(c => {
      const el = c.querySelector('.cell-text, .preview-text');
      return el ? el.innerText.trim() : c.innerText.trim();
    });
    copyText(texts.join('\t'), 'Row');
  };
  window.filterTable = function() {
    const q = document.getElementById('searchInput').value.toLowerCase();
    let visible = 0;
    document.querySelectorAll('tbody tr').forEach(row => {
      const match = row.innerText.toLowerCase().includes(q);
      row.style.display = match ? '' : 'none';
      if (match) visible++;
    });
    document.getElementById('visibleCount').innerText = visible;
  };
  let sortDir = {};
  window.sortTable = function(idx) {
    const tbody = document.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const ths = document.querySelectorAll('th');
    ths.forEach(th => th.classList.remove('sort-asc','sort-desc'));
    sortDir[idx] = !sortDir[idx];
    ths[idx].classList.add(sortDir[idx] ? 'sort-asc' : 'sort-desc');
    rows.sort((a,b) => {
      let av = a.cells[idx]?.innerText.trim() || '';
      let bv = b.cells[idx]?.innerText.trim() || '';
      const an = parseFloat(av), bn = parseFloat(bv);
      if (!isNaN(an) && !isNaN(bn) && av === String(an) && bv === String(bn)) return sortDir[idx] ? an - bn : bn - an;
      return sortDir[idx] ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    rows.forEach(r => tbody.appendChild(r));
  };

  // JSON syntax highlighting
  function highlightJSON(text) {
    // Escape HTML first
    let html = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    // Keys: "key":
    html = html.replace(/("(?:[^"\\]|\\.)*")(\s*:)/g, '<span class="json-key">$1</span><span class="json-string">$2</span>');
    // Strings: "value"
    html = html.replace(/: (\"(?:[^"\\]|\\.)*\")/g, ': <span class="json-string">$1</span>');
    // Numbers
    html = html.replace(/: (-?\d+\.?\d*)/g, ': <span class="json-number">$1</span>');
    // Booleans
    html = html.replace(/: (true|false)/g, ': <span class="json-boolean">$1</span>');
    // Null
    html = html.replace(/: (null)/g, ': <span class="json-null">$1</span>');
    return html;
  }

  function formatJSON(raw) {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch(e) {
      return raw;
    }
  }

  // Modal
  window.openModal = function(el, title, isJson) {
    let overlay = document.getElementById('jsonModal');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'jsonModal';
      overlay.className = 'modal-overlay';
      overlay.innerHTML = '<div class="modal-box"><div class="modal-header"><span class="modal-title"></span><div class="modal-header-actions"><button class="btn" id="modalToggleRaw" style="display:none;">Raw</button><button class="modal-close" onclick="closeModal()">✕</button></div></div><div class="modal-body"><pre id="modalPre"></pre></div><div class="modal-footer"><button class="btn" onclick="copyModalContent()">⎘ Copy</button><button class="btn btn-primary" onclick="closeModal()">Close</button></div></div>';
      overlay.onclick = function(e) { if (e.target === overlay) closeModal(); };
      document.body.appendChild(overlay);
    }
    const text = el.querySelector('.preview-text')?.innerText || el.innerText;
    overlay.dataset.raw = text;
    overlay.dataset.isJson = isJson ? '1' : '0';
    overlay.querySelector('.modal-title').innerText = title;

    const pre = document.getElementById('modalPre');
    const toggleBtn = document.getElementById('modalToggleRaw');

    if (isJson) {
      toggleBtn.style.display = '';
      overlay.dataset.formatted = '1';
      const formatted = formatJSON(text);
      pre.innerHTML = highlightJSON(formatted);
      toggleBtn.innerText = 'Raw';
      toggleBtn.classList.remove('active');
      toggleBtn.onclick = function() {
        if (overlay.dataset.formatted === '1') {
          pre.innerText = overlay.dataset.raw;
          overlay.dataset.formatted = '0';
          toggleBtn.innerText = 'Pretty';
          toggleBtn.classList.add('active');
        } else {
          pre.innerHTML = highlightJSON(formatJSON(overlay.dataset.raw));
          overlay.dataset.formatted = '1';
          toggleBtn.innerText = 'Raw';
          toggleBtn.classList.remove('active');
        }
      };
    } else {
      toggleBtn.style.display = 'none';
      pre.innerText = text;
    }

    overlay.classList.add('active');
    document.body.style.overflow = 'hidden';
  };
  window.closeModal = function() {
    const overlay = document.getElementById('jsonModal');
    if (overlay) { overlay.classList.remove('active'); document.body.style.overflow = ''; }
  };
  window.copyModalContent = function() {
    const overlay = document.getElementById('jsonModal');
    if (overlay && overlay.dataset.raw) copyText(overlay.dataset.raw, 'Content');
  };
  document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeModal(); });

  window.exportCSV = function() {
    const rows = document.querySelectorAll('table tr');
    const csv = Array.from(rows).map(row => {
      return Array.from(row.querySelectorAll('th,td')).map(c => {
        const el = c.querySelector('.cell-text, .preview-text');
        const text = el ? el.innerText.trim() : c.innerText.trim();
        return '"' + text.replace(/"/g, '""') + '"';
      }).join(',');
    }).join('\n');
    const blob = new Blob([csv], {type:'text/csv'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url;
    a.download = 'cucks_' + new Date().toISOString().slice(0,19).replace(/:/g,'-') + '.csv';
    a.click(); URL.revokeObjectURL(url); showToast('CSV exported');
  };
  let refreshInt;
  window.toggleRefresh = function(btn) {
    if (refreshInt) { clearInterval(refreshInt); refreshInt = null; btn.classList.remove('btn-primary'); btn.innerHTML = '⟳ Auto'; showToast('Auto refresh off'); }
    else { refreshInt = setInterval(() => location.reload(), 30000); btn.classList.add('btn-primary'); btn.innerHTML = '⏸ Auto (30s)'; showToast('Auto refresh on'); }
  };
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('totalCount').innerText = document.querySelectorAll('tbody tr').length;
    document.getElementById('visibleCount').innerText = document.querySelectorAll('tbody tr').length;
  });
})();
