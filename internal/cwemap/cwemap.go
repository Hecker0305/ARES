package cwemap

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const CWEVersion = "4.17"
const CWEVersionDate = "2025-04-17"

type CWEEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Deprecated  bool   `json:"deprecated,omitempty"`
	ReplacedBy  string `json:"replaced_by,omitempty"`
	AddedDate   string `json:"added_date,omitempty"`
	LastUpdated string `json:"last_updated,omitempty"`
}

type CWEManifest struct {
	Version     string    `json:"version"`
	VersionDate string    `json:"version_date"`
	LastChecked time.Time `json:"last_checked"`
	ExternalDB  string    `json:"external_db,omitempty"`
	EntryCount  int       `json:"entry_count"`
}

var (
	cweMu    sync.RWMutex
	cweMap   = buildDefaultCWEMap()
	cweVer   = CWEVersion
	cweDate  = CWEVersionDate
	manifest = CWEManifest{
		Version:     CWEVersion,
		VersionDate: CWEVersionDate,
		LastChecked: time.Now(),
		EntryCount:  len(buildDefaultCWEMap()),
	}
)

func buildDefaultCWEMap() map[string]CWEEntry {
	return map[string]CWEEntry{
		"sqli": {
			ID:          "CWE-89",
			Name:        "Improper Neutralization of Special Elements used in an SQL Command",
			Description: "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
			URL:         "https://cwe.mitre.org/data/definitions/89.html",
			LastUpdated: CWEVersionDate,
		},
		"xss": {
			ID:          "CWE-79",
			Name:        "Improper Neutralization of Input During Web Page Generation",
			Description: "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
			URL:         "https://cwe.mitre.org/data/definitions/79.html",
			LastUpdated: CWEVersionDate,
		},
		"ssrf": {
			ID:          "CWE-918",
			Name:        "Server-Side Request Forgery",
			Description: "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
			URL:         "https://cwe.mitre.org/data/definitions/918.html",
			LastUpdated: CWEVersionDate,
		},
		"rce": {
			ID:          "CWE-94",
			Name:        "Improper Control of Generation of Code",
			Description: "The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.",
			URL:         "https://cwe.mitre.org/data/definitions/94.html",
			LastUpdated: CWEVersionDate,
		},
		"idor": {
			ID:          "CWE-639",
			Name:        "Authorization Bypass Through User-Controlled Key",
			Description: "The system's authorization functionality does not prevent one user from gaining access to another user's resource or record by modifying a key value which identifies the resource.",
			URL:         "https://cwe.mitre.org/data/definitions/639.html",
			LastUpdated: CWEVersionDate,
		},
		"csrf": {
			ID:          "CWE-352",
			Name:        "Cross-Site Request Forgery",
			Description: "The web application does not, or cannot, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
			URL:         "https://cwe.mitre.org/data/definitions/352.html",
			LastUpdated: CWEVersionDate,
		},
		"lfi": {
			ID:          "CWE-98",
			Name:        "Improper Control of Filename for Include/Require Statement",
			Description: "The software receives input from an upstream component that specifies the name of a file that should be included, but it does not properly neutralize special elements that can cause the inclusion of an unintended file.",
			URL:         "https://cwe.mitre.org/data/definitions/98.html",
			LastUpdated: CWEVersionDate,
		},
		"rfi": {
			ID:          "CWE-98",
			Name:        "Improper Control of Filename for Include/Require Statement",
			Description: "The software receives input from an upstream component that specifies the name of a file that should be included, but it does not properly neutralize special elements that can cause the inclusion of an unintended remote file.",
			URL:         "https://cwe.mitre.org/data/definitions/98.html",
			LastUpdated: CWEVersionDate,
		},
		"xxe": {
			ID:          "CWE-611",
			Name:        "Improper Restriction of XML External Entity Reference",
			Description: "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.",
			URL:         "https://cwe.mitre.org/data/definitions/611.html",
			LastUpdated: CWEVersionDate,
		},
		"ssti": {
			ID:          "CWE-94",
			Name:        "Improper Control of Generation of Code",
			Description: "The software constructs all or part of a code segment using externally-influenced input from an upstream component during template rendering, but it does not neutralize or incorrectly neutralizes special elements.",
			URL:         "https://cwe.mitre.org/data/definitions/94.html",
			LastUpdated: CWEVersionDate,
		},
		"nosqli": {
			ID:          "CWE-943",
			Name:        "Improper Neutralization of Special Elements in Data Query Logic",
			Description: "The software constructs a data query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended query.",
			URL:         "https://cwe.mitre.org/data/definitions/943.html",
			LastUpdated: CWEVersionDate,
		},
		"deserial": {
			ID:          "CWE-502",
			Name:        "Deserialization of Untrusted Data",
			Description: "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
			URL:         "https://cwe.mitre.org/data/definitions/502.html",
			LastUpdated: CWEVersionDate,
		},
		"traversal": {
			ID:          "CWE-22",
			Name:        "Improper Limitation of a Pathname to a Restricted Directory",
			Description: "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname.",
			URL:         "https://cwe.mitre.org/data/definitions/22.html",
			LastUpdated: CWEVersionDate,
		},
		"oauth": {
			ID:          "CWE-284",
			Name:        "Improper Access Control",
			Description: "The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.",
			URL:         "https://cwe.mitre.org/data/definitions/284.html",
			LastUpdated: CWEVersionDate,
		},
		"prototype_pollution": {
			ID:          "CWE-915",
			Name:        "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
			Description: "The software receives input from an upstream component that specifies attributes that are to be initialized or updated in an object, but it does not properly control modifications of attributes of the object prototype.",
			URL:         "https://cwe.mitre.org/data/definitions/915.html",
			LastUpdated: CWEVersionDate,
		},
		"open_redirect": {
			ID:          "CWE-601",
			Name:        "URL Redirection to Untrusted Site",
			Description: "The web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a redirect.",
			URL:         "https://cwe.mitre.org/data/definitions/601.html",
			LastUpdated: CWEVersionDate,
		},
		"auth_bypass": {
			ID:          "CWE-287",
			Name:        "Improper Authentication",
			Description: "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
			URL:         "https://cwe.mitre.org/data/definitions/287.html",
			LastUpdated: CWEVersionDate,
		},
		"race_condition": {
			ID:          "CWE-362",
			Name:        "Concurrent Execution using Shared Resource with Improper Synchronization",
			Description: "The software contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence.",
			URL:         "https://cwe.mitre.org/data/definitions/362.html",
			LastUpdated: CWEVersionDate,
		},
		"smuggling": {
			ID:          "CWE-444",
			Name:        "Inconsistent Interpretation of HTTP Requests",
			Description: "The software receives data from an upstream component that specifies multiple, conflicting values for the same header, but it does not handle the inconsistency properly.",
			URL:         "https://cwe.mitre.org/data/definitions/444.html",
			LastUpdated: CWEVersionDate,
		},
		"bizlogic": {
			ID:          "CWE-840",
			Name:        "Business Logic Errors",
			Description: "The product contains a segment that is error-prone and represents potentially faulty business logic.",
			URL:         "https://cwe.mitre.org/data/definitions/840.html",
			LastUpdated: CWEVersionDate,
		},
		"dom_xss": {
			ID:          "CWE-79",
			Name:        "Improper Neutralization of Input During Web Page Generation",
			Description: "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users, via DOM manipulation.",
			URL:         "https://cwe.mitre.org/data/definitions/79.html",
			LastUpdated: CWEVersionDate,
		},
		"graphql": {
			ID:          "CWE-939",
			Name:        "Improper Authorization in Handler for Custom URL Scheme",
			Description: "The software does not properly authorize access to GraphQL introspection or mutation endpoints.",
			URL:         "https://cwe.mitre.org/data/definitions/939.html",
			LastUpdated: CWEVersionDate,
		},
		"cloud": {
			ID:          "CWE-284",
			Name:        "Improper Access Control",
			Description: "Cloud infrastructure misconfiguration leads to improper access control of resources.",
			URL:         "https://cwe.mitre.org/data/definitions/284.html",
			LastUpdated: CWEVersionDate,
		},
		"container_escape": {
			ID:          "CWE-250",
			Name:        "Execution with Unnecessary Privileges",
			Description: "The software performs an execution at a privilege level that is higher than the minimum level required, enabling container escape.",
			URL:         "https://cwe.mitre.org/data/definitions/250.html",
			LastUpdated: CWEVersionDate,
		},
		"second_order": {
			ID:          "CWE-94",
			Name:        "Improper Control of Generation of Code",
			Description: "The software stores user-controllable input that is later used in a security-critical operation without proper validation.",
			URL:         "https://cwe.mitre.org/data/definitions/94.html",
			LastUpdated: CWEVersionDate,
		},
		"blindsqli": {
			ID:          "CWE-89",
			Name:        "Improper Neutralization of Special Elements used in an SQL Command",
			Description: "Blind SQL injection where the application does not return error messages but the attacker can infer information through boolean or time-based techniques.",
			URL:         "https://cwe.mitre.org/data/definitions/89.html",
			LastUpdated: CWEVersionDate,
		},
		"websocket": {
			ID:          "CWE-346",
			Name:        "Origin Validation Error",
			Description: "The software does not properly validate the origin of WebSocket connections, allowing cross-origin attacks.",
			URL:         "https://cwe.mitre.org/data/definitions/346.html",
			LastUpdated: CWEVersionDate,
		},
		"info_disclosure": {
			ID:          "CWE-200",
			Name:        "Information Exposure",
			Description: "The software exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
			URL:         "https://cwe.mitre.org/data/definitions/200.html",
			LastUpdated: CWEVersionDate,
		},
		"hardcoded_secret": {
			ID:          "CWE-798",
			Name:        "Use of Hard-coded Credentials",
			Description: "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication, or data encryption.",
			URL:         "https://cwe.mitre.org/data/definitions/798.html",
			LastUpdated: CWEVersionDate,
		},
		"weak_crypto": {
			ID:          "CWE-327",
			Name:        "Use of a Broken or Risky Cryptographic Algorithm",
			Description: "The software uses a broken or risky cryptographic algorithm or protocol.",
			URL:         "https://cwe.mitre.org/data/definitions/327.html",
			LastUpdated: CWEVersionDate,
		},
	}
}

func Lookup(findingType string) CWEEntry {
	cweMu.RLock()
	defer cweMu.RUnlock()

	key := strings.ToLower(findingType)

	if entry, ok := cweMap[key]; ok {
		if entry.Deprecated {
			if entry.ReplacedBy != "" {
				if replacement, ok := cweMap[entry.ReplacedBy]; ok {
					return replacement
				}
			}
		}
		return entry
	}

	for k, entry := range cweMap {
		if strings.Contains(key, k) || strings.Contains(k, key) {
			if entry.Deprecated && entry.ReplacedBy != "" {
				if replacement, ok := cweMap[entry.ReplacedBy]; ok {
					return replacement
				}
			}
			return entry
		}
	}

	return CWEEntry{
		ID:          "CWE-676",
		Name:        "Use of Potentially Dangerous Function",
		Description: "The software uses a function that can introduce a vulnerability if it is used incorrectly.",
		URL:         "https://cwe.mitre.org/data/definitions/676.html",
		LastUpdated: CWEVersionDate,
	}
}

func LookupByID(cweID string) CWEEntry {
	cweMu.RLock()
	defer cweMu.RUnlock()

	for _, entry := range cweMap {
		if entry.ID == cweID {
			if entry.Deprecated && entry.ReplacedBy != "" {
				for _, alt := range cweMap {
					if alt.ID == entry.ReplacedBy {
						return alt
					}
				}
			}
			return entry
		}
	}
	return CWEEntry{}
}

func AllCWEs() []CWEEntry {
	cweMu.RLock()
	defer cweMu.RUnlock()

	var entries []CWEEntry
	for _, entry := range cweMap {
		entries = append(entries, entry)
	}
	return entries
}

func FindingsWithCWE(findings []FindingWithCWE) []FindingWithCWE {
	for i := range findings {
		if findings[i].CWE == "" {
			cwe := Lookup(findings[i].Type)
			findings[i].CWE = cwe.ID
			findings[i].CWEName = cwe.Name
		}
	}
	return findings
}

type FindingWithCWE struct {
	Type    string `json:"type"`
	CWE     string `json:"cwe"`
	CWEName string `json:"cwe_name"`
}

func GetVersion() string {
	cweMu.RLock()
	defer cweMu.RUnlock()
	return cweVer
}

func GetVersionDate() string {
	cweMu.RLock()
	defer cweMu.RUnlock()
	return cweDate
}

func IsUpToDate() bool {
	cweMu.RLock()
	defer cweMu.RUnlock()
	return manifest.LastChecked.After(time.Now().AddDate(0, -3, 0))
}

func GetManifest() CWEManifest {
	cweMu.RLock()
	defer cweMu.RUnlock()
	return manifest
}

func LoadExternalCWE(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read external CWE database: %w", err)
	}

	var externalMap map[string]CWEEntry
	if err := json.Unmarshal(data, &externalMap); err != nil {
		return fmt.Errorf("failed to parse external CWE database: %w", err)
	}

	cweMu.Lock()
	defer cweMu.Unlock()

	for k, v := range externalMap {
		if v.ID == "" {
			continue
		}
		if v.LastUpdated == "" {
			v.LastUpdated = time.Now().Format("2006-01-02")
		}
		cweMap[k] = v
	}

	manifest.ExternalDB = path
	manifest.EntryCount = len(cweMap)
	manifest.LastChecked = time.Now()

	return nil
}

func MarkDeprecated(findingType, replacedBy string) error {
	cweMu.Lock()
	defer cweMu.Unlock()

	entry, ok := cweMap[findingType]
	if !ok {
		return fmt.Errorf("CWE entry not found: %s", findingType)
	}

	entry.Deprecated = true
	entry.ReplacedBy = replacedBy
	cweMap[findingType] = entry
	return nil
}

func AddCWEEntry(findingType string, entry CWEEntry) {
	cweMu.Lock()
	defer cweMu.Unlock()

	if entry.LastUpdated == "" {
		entry.LastUpdated = time.Now().Format("2006-01-02")
	}
	cweMap[findingType] = entry
	manifest.EntryCount = len(cweMap)
}

func CheckVersion() (string, error) {
	cweMu.RLock()
	defer cweMu.RUnlock()

	if !manifest.LastChecked.After(time.Now().AddDate(0, -3, 0)) {
		return "", fmt.Errorf("CWE database version %s (%s) is older than 3 months; update recommended", cweVer, cweDate)
	}
	return fmt.Sprintf("CWE %s (%s)", cweVer, cweDate), nil
}
