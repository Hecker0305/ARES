package pwcracking

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type hashPattern struct {
	Name       string
	Pattern    *regexp.Regexp
	HashcatMod int
	JohnFormat string
}

var hashPatterns = []hashPattern{
	{Name: "MD5", Pattern: regexp.MustCompile(`^[a-f0-9]{32}$`), HashcatMod: 0, JohnFormat: "raw-md5"},
	{Name: "SHA1", Pattern: regexp.MustCompile(`^[a-f0-9]{40}$`), HashcatMod: 100, JohnFormat: "raw-sha1"},
	{Name: "SHA256", Pattern: regexp.MustCompile(`^[a-f0-9]{64}$`), HashcatMod: 1400, JohnFormat: "raw-sha256"},
	{Name: "SHA512", Pattern: regexp.MustCompile(`^[a-f0-9]{128}$`), HashcatMod: 1700, JohnFormat: "raw-sha512"},
	{Name: "NTLM", Pattern: regexp.MustCompile(`^[a-f0-9]{32}$`), HashcatMod: 1000, JohnFormat: "nt"},
	{Name: "LM", Pattern: regexp.MustCompile(`^[a-f0-9]{16}$`), HashcatMod: 3000, JohnFormat: "lm"},
	{Name: "NetNTLMv1", Pattern: regexp.MustCompile(`^[^:]+:[^:]+:[a-f0-9]{48}:[a-f0-9]{48}$`), HashcatMod: 5500, JohnFormat: "netntlm"},
	{Name: "NetNTLMv2", Pattern: regexp.MustCompile(`^[^:]+:[^:]+:[a-f0-9]{32}:[a-f0-9]+$`), HashcatMod: 5600, JohnFormat: "netntlmv2"},
	{Name: "bcrypt", Pattern: regexp.MustCompile(`^\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}$`), HashcatMod: 3200, JohnFormat: "bcrypt"},
	{Name: "SHA512Crypt", Pattern: regexp.MustCompile(`^\$6\$\w+\$[a-zA-Z0-9./]{86}$`), HashcatMod: 1800, JohnFormat: "sha512crypt"},
	{Name: "MD5Crypt", Pattern: regexp.MustCompile(`^\$1\$\w+\$[a-zA-Z0-9./]{22}$`), HashcatMod: 500, JohnFormat: "md5crypt"},
	{Name: "MySQL", Pattern: regexp.MustCompile(`^\*[a-f0-9]{40}$`), HashcatMod: 300, JohnFormat: "mysql-sha1"},
	{Name: "MySQL_old", Pattern: regexp.MustCompile(`^[a-f0-9]{16}$`), HashcatMod: 200, JohnFormat: "mysql"},
	{Name: "PostgreSQL", Pattern: regexp.MustCompile(`^md5[a-f0-9]{32}$`), HashcatMod: 0, JohnFormat: "dynamic_1034"},
	{Name: "MSSQL", Pattern: regexp.MustCompile(`^0x0100[a-f0-9]{80}$`), HashcatMod: 132, JohnFormat: "mssql"},
	{Name: "Oracle", Pattern: regexp.MustCompile(`^[a-f0-9]{16}:[a-f0-9]{16}$`), HashcatMod: 3100, JohnFormat: "oracle"},
	{Name: "AS-REP", Pattern: regexp.MustCompile(`^\$krb5asrep\$`), HashcatMod: 18200, JohnFormat: "krb5asrep"},
	{Name: "KerberosTGS", Pattern: regexp.MustCompile(`^\$krb5tgs\$`), HashcatMod: 13100, JohnFormat: "krb5tgs"},
	{Name: "KeePass", Pattern: regexp.MustCompile(`^\$keepass\$`), HashcatMod: 13400, JohnFormat: "keepass"},
	{Name: "PDF", Pattern: regexp.MustCompile(`^\$pdf\$`), HashcatMod: 10500, JohnFormat: "pdf"},
	{Name: "ZIP", Pattern: regexp.MustCompile(`^\$zip\d+\$`), HashcatMod: 17200, JohnFormat: "zip"},
	{Name: "RAR", Pattern: regexp.MustCompile(`^\$rar\d+\$`), HashcatMod: 13000, JohnFormat: "rar"},
	{Name: "Bitcoin", Pattern: regexp.MustCompile(`^[a-km-zA-HJ-NP-Z1-9]{27,34}$`), HashcatMod: 11300, JohnFormat: "bitcoin"},
	{Name: "Ethereum", Pattern: regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`), HashcatMod: 0, JohnFormat: ""},
}

func IdentifyHash(hashString string) (string, error) {
	for _, hp := range hashPatterns {
		if hp.Pattern.MatchString(hashString) {
			return hp.Name, nil
		}
	}
	return "", fmt.Errorf("unknown hash type: %s", hashString)
}

func IdentifyHashFromFile(filePath string) (map[string][]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string][]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hashType, err := IdentifyHash(line)
		if err != nil {
			continue
		}
		result[hashType] = append(result[hashType], line)
	}
	return result, scanner.Err()
}

func GetHashcatMode(hashType string) (int, error) {
	for _, hp := range hashPatterns {
		if strings.EqualFold(hp.Name, hashType) {
			return hp.HashcatMod, nil
		}
	}
	return 0, fmt.Errorf("no hashcat mode for %s", hashType)
}

func GetJohnFormat(hashType string) (string, error) {
	for _, hp := range hashPatterns {
		if strings.EqualFold(hp.Name, hashType) {
			return hp.JohnFormat, nil
		}
	}
	return "", fmt.Errorf("no john format for %s", hashType)
}

func SuggestAttackMode(hashType string) []string {
	modes := []string{"straight"}
	for _, hp := range hashPatterns {
		if strings.EqualFold(hp.Name, hashType) {
			if hp.HashcatMod == 3200 || hp.HashcatMod == 1800 {
				modes = append(modes, "rules", "mask")
			} else {
				modes = append(modes, "rules", "mask", "incremental")
			}
			break
		}
	}
	return modes
}

func FormatHashForHashcat(hashString, hashType string) (string, error) {
	hashType = strings.ToLower(hashType)
	switch hashType {
	case "ntlm":
		return strings.ToUpper(hashString), nil
	case "netntlmv2":
		return hashString, nil
	case "bcrypt":
		return hashString, nil
	default:
		return hashString, nil
	}
}

func FormatHashForJohn(hashString, hashType string) (string, error) {
	return hashString, nil
}
