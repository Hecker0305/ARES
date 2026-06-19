package pwcracking

import (
	"fmt"
	"strings"
)

func JohnCrack(hashFile string) (string, error) {
	return runCommand("john", "--wordlist=rockyou.txt", hashFile)
}

func JohnCrackWithRules(hashFile, wordlist, rules string) (string, error) {
	return runCommand("john", fmt.Sprintf("--wordlist=%s", wordlist), fmt.Sprintf("--rules=%s", rules), hashFile)
}

func JohnCrackWithFormat(hashFile, format string) (string, error) {
	return runCommand("john", fmt.Sprintf("--format=%s", format), "--wordlist=rockyou.txt", hashFile)
}

func JohnCrackIncremental(hashFile string) (string, error) {
	return runCommand("john", "--incremental", hashFile)
}

func JohnCrackSingle(hashFile string) (string, error) {
	return runCommand("john", "--single", hashFile)
}

func JohnCrackNT(hashFile string) (string, error) {
	return runCommand("john", "--format=nt", "--wordlist=rockyou.txt", hashFile)
}

func JohnCrackLM(hashFile string) (string, error) {
	return runCommand("john", "--format=lm", "--wordlist=rockyou.txt", hashFile)
}

func JohnCrackNetNTLMv2(hashFile string) (string, error) {
	return runCommand("john", "--format=netntlmv2", "--wordlist=rockyou.txt", hashFile)
}

func JohnCrackSSHA(hashFile string) (string, error) {
	return runCommand("john", "--format=ssh", "--wordlist=rockyou.txt", hashFile)
}

func JohnCrackKeePass(hashFile string) (string, error) {
	return runCommand("john", "--format=keepass", "--wordlist=rockyou.txt", hashFile)
}

func JohnCrackPDF(hashFile string) (string, error) {
	return runCommand("john", "--format=pdf", "--wordlist=rockyou.txt", hashFile)
}

func JohnCrackZIP(hashFile string) (string, error) {
	return runCommand("john", "--format=zip", "--wordlist=rockyou.txt", hashFile)
}

func JohnCrackRAR(hashFile string) (string, error) {
	return runCommand("john", "--format=rar", "--wordlist=rockyou.txt", hashFile)
}

func JohnShowResults(hashFile string) (string, error) {
	return runCommand("john", "--show", hashFile)
}

func JohnParseResults(hashFile string) (*JohnResult, error) {
	out, err := JohnShowResults(hashFile)
	if err != nil {
		return nil, err
	}
	result := &JohnResult{
		HashFile:         hashFile,
		CrackedPasswords: make(map[string]string),
	}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, ":") && !strings.HasPrefix(line, "#") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.CrackedPasswords[parts[0]] = strings.TrimSpace(parts[1])
				result.Cracked++
			}
		}
	}
	return result, nil
}

func JohnBenchmark() (string, error) {
	return runCommand("john", "--test")
}
