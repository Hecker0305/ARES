package ransomware

import (
	"github.com/ares/engine/internal/uuid"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type RansomwareFamily struct {
	Name               string   `json:"name"`
	Aliases            []string `json:"aliases,omitempty"`
	FirstSeen          string   `json:"first_seen"`
	LastSeen           string   `json:"last_seen"`
	Type               string   `json:"type"`
	Platform           string   `json:"platform"`
	Extensions         []string `json:"extensions,omitempty"`
	RansomNote         string   `json:"ransom_note,omitempty"`
	RansomAmount       string   `json:"ransom_amount,omitempty"`
	WalletAddresses    []string `json:"wallet_addresses,omitempty"`
	DecryptorAvailable bool     `json:"decryptor_available"`
	DecryptorURL       string   `json:"decryptor_url,omitempty"`
	CVE                []string `json:"cve,omitempty"`
	IOCs               []IOC    `json:"iocs,omitempty"`
}

type IOC struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context,omitempty"`
}

type RansomwareReport struct {
	ID              string    `json:"id"`
	SampleHash      string    `json:"sample_hash"`
	Family          string    `json:"family"`
	Confidence      float64   `json:"confidence"`
	DetectedExts    []string  `json:"detected_extensions,omitempty"`
	RansomNotePath  string    `json:"ransom_note_path,omitempty"`
	RansomNoteText  string    `json:"ransom_note_text,omitempty"`
	WalletAddresses []string  `json:"wallet_addresses,omitempty"`
	EncryptionKey   string    `json:"encryption_key,omitempty"`
	DecryptorStatus string    `json:"decryptor_status"`
	IOCs            []IOC     `json:"iocs,omitempty"`
	MITRETechniques []string  `json:"mitre_techniques,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type Engine struct {
	mu       sync.RWMutex
	families map[string]*RansomwareFamily
	reports  map[string]*RansomwareReport
}

func New() *Engine {
	e := &Engine{
		families: make(map[string]*RansomwareFamily),
		reports:  make(map[string]*RansomwareReport),
	}
	e.seedFamilies()
	return e
}

func (e *Engine) seedFamilies() {
	e.families["wannacry"] = &RansomwareFamily{
		Name: "WannaCry", Aliases: []string{"WannaCrypt", "WanaDecryptor"},
		FirstSeen: "2017-05-12", LastSeen: "2023-01-01",
		Type: "crypto", Platform: "Windows",
		Extensions:         []string{".wncry", ".wncryt", ".wcry"},
		RansomNote:         "@Please_Read_Me@.txt",
		RansomAmount:       "$300 in Bitcoin",
		WalletAddresses:    []string{"13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94"},
		DecryptorAvailable: true, DecryptorURL: "https://www.nomoreransom.org",
		CVE: []string{"CVE-2017-0144", "CVE-2017-0145"},
		IOCs: []IOC{
			{Type: "domain", Value: "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"},
			{Type: "sha256", Value: "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"},
		},
	}
	e.families["ryuk"] = &RansomwareFamily{
		Name: "Ryuk", Aliases: []string{"Ryuk", "Hermes"},
		FirstSeen: "2018-08-01", LastSeen: "2024-01-01",
		Type: "crypto", Platform: "Windows",
		Extensions:         []string{".ryk", ".rkw"},
		RansomNote:         "RyukReadMe.txt",
		RansomAmount:       "$500,000+ custom per victim",
		DecryptorAvailable: false,
		CVE:                []string{},
		IOCs: []IOC{
			{Type: "ip", Value: "185.141.63.120"},
			{Type: "domain", Value: "ryukcc.xyz"},
		},
	}
	e.families["lockbit"] = &RansomwareFamily{
		Name: "LockBit", Aliases: []string{"LockBit", "ABCD"},
		FirstSeen: "2019-09-01", LastSeen: "2025-01-01",
		Type: "crypto", Platform: "Windows/Linux",
		Extensions:         []string{".lockbit", ".abcd", ".lockbit3"},
		RansomNote:         "README.txt",
		RansomAmount:       "Variable, up to $80M",
		DecryptorAvailable: false,
		CVE:                []string{"CVE-2021-31207", "CVE-2023-27532"},
		IOCs: []IOC{
			{Type: "domain", Value: "lockbit7z2jvrl7t7eklqv3o3y5q7z7xvkzqz7z2jvrl7t7eklqv3.onion"},
		},
	}
	e.families["blackcat"] = &RansomwareFamily{
		Name: "BlackCat/ALPHV", Aliases: []string{"ALPHV", "BlackCat", "Noberus"},
		FirstSeen: "2021-11-01", LastSeen: "2025-01-01",
		Type: "crypto", Platform: "Windows/Linux",
		Extensions:         []string{".alphv", ".blackcat"},
		RansomNote:         "README.alphv.txt",
		RansomAmount:       "$500K-$5M+",
		DecryptorAvailable: false,
		CVE:                []string{"CVE-2022-24521"},
		IOCs: []IOC{
			{Type: "domain", Value: "alphvmmmbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion"},
		},
	}
	e.families["clop"] = &RansomwareFamily{
		Name: "Clop", Aliases: []string{"Clop", "Cl0p"},
		FirstSeen: "2019-02-01", LastSeen: "2024-06-01",
		Type: "crypto", Platform: "Windows",
		Extensions:         []string{".clop", ".ciop"},
		RansomNote:         "ClopReadMe.txt",
		RansomAmount:       "Variable",
		DecryptorAvailable: false,
		CVE:                []string{"CVE-2023-34362", "CVE-2020-1472"},
		IOCs: []IOC{
			{Type: "ip", Value: "45.155.205.233"},
			{Type: "domain", Value: "cloprrrrcpflxqz7v2jrlr7t7eklqv3o3y5q7z7xvkzqz7z2jvrl7t7eklqv3.onion"},
		},
	}
	e.families["conti"] = &RansomwareFamily{
		Name: "Conti", Aliases: []string{"Conti"},
		FirstSeen: "2020-05-01", LastSeen: "2023-06-01",
		Type: "crypto", Platform: "Windows",
		Extensions:         []string{".conti"},
		RansomNote:         "CONTITECH.txt",
		RansomAmount:       "$500K-$10M+",
		DecryptorAvailable: false,
		CVE:                []string{},
		IOCs: []IOC{
			{Type: "domain", Value: "continewsnv5otx5kaoje7krkps2maz2fq3p7c3i6e5a4q5x5y5z5.onion"},
		},
	}
}

func (e *Engine) AnalyzeSample(sampleHash string, extensions []string, noteText string, addresses []string) *RansomwareReport {
	report := &RansomwareReport{
		ID:              uuid.New(),
		SampleHash:      sampleHash,
		Confidence:      0.0,
		DecryptorStatus: "unknown",
		CreatedAt:       time.Now(),
	}

	if len(extensions) > 0 {
		report.DetectedExts = extensions
	}
	if noteText != "" {
		report.RansomNoteText = noteText
	}
	if len(addresses) > 0 {
		report.WalletAddresses = addresses
	}

	var bestFamily *RansomwareFamily
	var bestScore float64

	e.mu.RLock()
	for _, family := range e.families {
		score := e.matchFamily(family, extensions, noteText, addresses)
		if score > bestScore {
			bestScore = score
			bestFamily = family
		}
	}
	e.mu.RUnlock()

	if bestFamily != nil && bestScore > 0.3 {
		report.Family = bestFamily.Name
		report.Confidence = bestScore
		report.IOCs = bestFamily.IOCs
		report.MITRETechniques = []string{"T1486", "T1490"}
		if bestFamily.DecryptorAvailable {
			report.DecryptorStatus = "available"
		} else {
			report.DecryptorStatus = "unavailable"
		}
	} else {
		report.Family = "unknown"
		report.Confidence = bestScore
	}

	e.mu.Lock()
	e.reports[report.ID] = report
	e.mu.Unlock()
	return report
}

func (e *Engine) matchFamily(family *RansomwareFamily, extensions []string, noteText string, addresses []string) float64 {
	var score float64

	for _, ext := range extensions {
		for _, famExt := range family.Extensions {
			if strings.EqualFold(ext, famExt) {
				score += 0.25
			}
		}
	}

	if noteText != "" {
		familyWords := strings.ToLower(family.RansomNote)
		noteWords := strings.ToLower(noteText)
		words := strings.Fields(familyWords)
		for _, w := range words {
			if len(w) > 3 && strings.Contains(noteWords, w) {
				score += 0.05
			}
		}
	}

	for _, addr := range addresses {
		for _, famAddr := range family.WalletAddresses {
			if strings.EqualFold(addr, famAddr) {
				score += 0.3
			}
		}
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

func (e *Engine) GetFamily(name string) *RansomwareFamily {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.families[strings.ToLower(name)]
}

func (e *Engine) ListFamilies() []*RansomwareFamily {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*RansomwareFamily, 0, len(e.families))
	for _, f := range e.families {
		result = append(result, f)
	}
	return result
}

func (e *Engine) GetReport(id string) *RansomwareReport {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.reports[id]
}

func (e *Engine) ListReports() []*RansomwareReport {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*RansomwareReport, 0, len(e.reports))
	for _, r := range e.reports {
		result = append(result, r)
	}
	return result
}

func (e *Engine) SearchDecryptor(family string) *DecryptorResult {
	result := &DecryptorResult{Family: family}

	e.mu.RLock()
	f, ok := e.families[strings.ToLower(family)]
	e.mu.RUnlock()

	if !ok {
		result.Status = "unknown"
		return result
	}

	if f.DecryptorAvailable {
		result.Status = "available"
		result.URL = f.DecryptorURL
		result.Tools = []string{
			"Avast Decryptor", "Kaspersky RakhniDecryptor",
			"Trend Micro Ransomware Decryptor", "NoMoreRansom Project",
		}
	} else {
		result.Status = "unavailable"
		result.Notes = fmt.Sprintf("No public decryptor available for %s. Check NoMoreRansom regularly.", family)
	}

	return result
}

type DecryptorResult struct {
	Family string   `json:"family"`
	Status string   `json:"status"`
	URL    string   `json:"url,omitempty"`
	Tools  []string `json:"tools,omitempty"`
	Notes  string   `json:"notes,omitempty"`
}

func RegisterHandlers(mux *http.ServeMux, engine *Engine) {
	mux.HandleFunc("/api/ransomware/families", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(engine.ListFamilies())
	})
	mux.HandleFunc("/api/ransomware/families/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		name := strings.TrimPrefix(r.URL.Path, "/api/ransomware/families/")
		f := engine.GetFamily(name)
		if f == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(f)
	})
	mux.HandleFunc("/api/ransomware/analyze", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Hash       string   `json:"hash"`
			Extensions []string `json:"extensions"`
			NoteText   string   `json:"note_text"`
			Addresses  []string `json:"wallet_addresses"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		report := engine.AnalyzeSample(req.Hash, req.Extensions, req.NoteText, req.Addresses)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(report)
	})
	mux.HandleFunc("/api/ransomware/reports", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(engine.ListReports())
	})
	mux.HandleFunc("/api/ransomware/decryptor", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		family := r.URL.Query().Get("family")
		if family == "" {
			http.Error(w, `{"error":"family required"}`, http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(engine.SearchDecryptor(family))
	})
}
