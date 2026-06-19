package pwcracking

import (
	"fmt"
	"os"
	"strings"
)

func HashcatCrack(hashFile, mode string) (string, error) {
	return runCommand("hashcat", "-m", mode, "-a", "0", hashFile, "rockyou.txt")
}

func HashcatCrackWithRules(hashFile, mode, wordlist, rules string) (string, error) {
	return runCommand("hashcat", "-m", mode, "-a", "0", hashFile, wordlist, "-r", rules)
}

func HashcatCrackWithDevice(hashFile, mode, device string) (string, error) {
	return runCommand("hashcat", "-m", mode, "-a", "0", hashFile, "rockyou.txt", "-D", device)
}

func HashcatBruteForce(hashFile, mode, mask string) (string, error) {
	return runCommand("hashcat", "-m", mode, "-a", "3", hashFile, mask)
}

func HashcatCombinator(hashFile, mode, wordlist1, wordlist2 string) (string, error) {
	return runCommand("hashcat", "-m", mode, "-a", "1", hashFile, wordlist1, wordlist2)
}

func HashcatAssociation(hashFile, mode string) (string, error) {
	return runCommand("hashcat", "-m", mode, "-a", "9", hashFile)
}

func HashcatToggleCase(hashFile, mode, wordlist string) (string, error) {
	return runCommand("hashcat", "-m", mode, "-a", "0", hashFile, wordlist, "--toggle-case")
}

func HashcatPRINCE(hashFile, mode, wordlist string) (string, error) {
	return runCommand("hashcat", "-m", mode, "-a", "8", hashFile, wordlist)
}

func HashcatNTLM(hashFile, wordlist string) (string, error) {
	return runCommand("hashcat", "-m", "1000", "-a", "0", hashFile, wordlist, "-O")
}

func HashcatNetNTLMv2(hashFile, wordlist string) (string, error) {
	return runCommand("hashcat", "-m", "5600", "-a", "0", hashFile, wordlist, "-O")
}

func HashcatKerberosASREP(hashFile, wordlist string) (string, error) {
	return runCommand("hashcat", "-m", "18200", "-a", "0", hashFile, wordlist)
}

func HashcatKerberosTGS(hashFile, wordlist string) (string, error) {
	return runCommand("hashcat", "-m", "13100", "-a", "0", hashFile, wordlist)
}

func HashcatBCrypt(hashFile, wordlist string) (string, error) {
	return runCommand("hashcat", "-m", "3200", "-a", "0", hashFile, wordlist)
}

func HashcatSHA512(hashFile, wordlist string) (string, error) {
	return runCommand("hashcat", "-m", "1800", "-a", "0", hashFile, wordlist)
}

func HashcatMD5(hashFile, wordlist string) (string, error) {
	return runCommand("hashcat", "-m", "500", "-a", "0", hashFile, wordlist)
}

func HashcatShowResults(hashFile string) (string, error) {
	return runCommand("hashcat", "--show", hashFile)
}

func HashcatBenchmark(mode string) (string, error) {
	return runCommand("hashcat", "-b", "-m", mode)
}

func HashcatBenchmarkAll() (string, error) {
	return runCommand("hashcat", "-b")
}

func HashcatIdentifyHash(hashString string) (string, error) {
	detected, err := IdentifyHash(hashString)
	if err != nil {
		return "", err
	}
	mode, err := GetHashcatMode(detected)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s (mode %d)", detected, mode), nil
}

func HashcatParsePotfile(potfilePath string) (map[string]string, error) {
	data, err := os.ReadFile(potfilePath)
	if err != nil {
		return nil, err
	}
	results := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			results[parts[0]] = parts[1]
		}
	}
	return results, nil
}
