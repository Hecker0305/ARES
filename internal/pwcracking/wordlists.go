package pwcracking

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func GetCommonWordlists() []string {
	return []string{
		"/usr/share/wordlists/rockyou.txt",
		"/usr/share/wordlists/rockyou.txt.gz",
		"/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
		"/usr/share/seclists/Passwords/darkweb2017-top1000.txt",
		"/usr/share/wordlists/fasttrack.txt",
		"/usr/share/dict/words",
	}
}

func GenerateWordlistFromTarget(target string) (string, error) {
	words := strings.Split(target, ".")
	tmpFile := filepath.Join(os.TempDir(), "target_wordlist.txt")
	f, err := os.Create(tmpFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	seen := make(map[string]bool)
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" || seen[w] {
			continue
		}
		seen[w] = true
		fmt.Fprintln(f, w)
		fmt.Fprintln(f, strings.ToUpper(w))
		fmt.Fprintln(f, strings.ToLower(w))
		fmt.Fprintln(f, strings.Title(w))
	}
	return tmpFile, nil
}

func CombineWordlists(paths []string, output string) error {
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	seen := make(map[string]bool)
	for _, path := range paths {
		rf, err := os.Open(path)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(rf)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || seen[line] {
				continue
			}
			seen[line] = true
			fmt.Fprintln(f, line)
		}
		rf.Close()
	}
	return nil
}

func ApplyRules(inputWordlist, outputWordlist, rulesFile string) (string, error) {
	return runCommand("john", "--wordlist="+inputWordlist, "--rules="+rulesFile, "--stdout", ">", outputWordlist)
}

func GenerateRuleBasedWordlist(baseWords []string, outputFile string) (string, error) {
	f, err := os.Create(outputFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	mutations := []func(string) string{
		func(s string) string { return s },
		func(s string) string { return strings.ToUpper(s) },
		func(s string) string { return strings.ToLower(s) },
		func(s string) string { return strings.Title(s) },
		func(s string) string { return s + "123" },
		func(s string) string { return s + "!" },
		func(s string) string { return s + "@" },
		func(s string) string { return s + "#" },
		func(s string) string { return s + "2024" },
		func(s string) string { return s + "2025" },
		func(s string) string { return s + "1" },
		func(s string) string { return strings.Title(s) + "123" },
		func(s string) string { return s + "!" + "123" },
		func(s string) string { return strings.ToUpper(s[:1]) + s[1:] + "!" },
		func(s string) string { return s + s },
		func(s string) string { return string(s[0]) + string(s[len(s)-1]) + "123" },
		func(s string) string { return "!" + s },
		func(s string) string { return "2025" + s },
		func(s string) string { return s + "admin" },
		func(s string) string { return "admin" + s },
	}

	seen := make(map[string]bool)
	for _, word := range baseWords {
		for _, mutate := range mutations {
			result := mutate(word)
			if !seen[result] {
				seen[result] = true
				fmt.Fprintln(f, result)
			}
		}
	}
	return outputFile, nil
}
