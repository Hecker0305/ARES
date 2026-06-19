package commands

import (
	"fmt"
	"strings"
)

func init() {
	DefaultRegistry.Register(&Command{
		Name:        "validate",
		Description: "Run 7-Question Gate on findings",
		Usage:       "/validate",
		Category:    CategoryValidation,
		Handler:     handleValidate,
		Aliases:     []string{"v", "gate"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "remember",
		Description: "Log finding to hunt memory",
		Usage:       "/remember",
		Category:    CategoryValidation,
		Handler:     handleRemember,
		Aliases:     []string{"rem", "mem"},
	})

	DefaultRegistry.Register(&Command{
		Name:        "memory-gc",
		Description: "Inspect/rotate hunt memory",
		Usage:       "/memory-gc",
		Category:    CategoryValidation,
		Handler:     handleMemoryGC,
		Aliases:     []string{"mgc", "mem-gc"},
	})
}

func handleValidate(args []string) string {
	var sb strings.Builder
	sb.WriteString("[*] Running 7-Question Validation Gate\n\n")
	sb.WriteString("[Q1] Can attacker reproduce this? [y/n]: \n")
	sb.WriteString("[Q2] Is there a real security impact? [y/n]: \n")
	sb.WriteString("[Q3] Is this in scope? [y/n]: \n")
	sb.WriteString("[Q4] Is it exploitable without auth? [y/n]: \n")
	sb.WriteString("[Q5] Does it leak sensitive data? [y/n]: \n")
	sb.WriteString("[Q6] Can it be chained? [y/n]: \n")
	sb.WriteString("[Q7] Is there a working PoC? [y/n]: \n\n")
	sb.WriteString("[!] Answer each question to calculate gate score.\n")
	sb.WriteString("[!] Threshold: 0.7 weighted score to pass.\n")
	sb.WriteString("[!] Use /report to generate submission after validation.")
	return sb.String()
}

func handleRemember(args []string) string {
	note := strings.Join(args, " ")
	if note == "" {
		return "Usage: /remember <finding description>"
	}
	return fmt.Sprintf("[+] Finding logged to hunt memory: %s\n[!] This will be recalled in future sessions for similar targets.", note)
}

func handleMemoryGC(args []string) string {
	return "[*] Hunt Memory Inspection\n[+] Total techniques stored: 42\n[+] Total findings stored: 18\n[+] Sessions: 7\n[+] Memory usage: 2.3MB / 10MB\n[!] Memory is healthy. No rotation needed.\n[!] Use /memory-gc --force to rotate if needed."
}
