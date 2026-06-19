package packetanalysis

import (
	"fmt"
	"strconv"
	"strings"
)

func FindAnomalies(pcapFile string) (string, error) {
	var results []string

	scanOut, err := DetectPortScan(pcapFile)
	if err == nil && scanOut != "" {
		results = append(results, "Port Scan Detected:\n"+scanOut)
	}

	dnsOut, err := DetectDNSTunneling(pcapFile)
	if err == nil && dnsOut != "" {
		results = append(results, "DNS Tunneling Detected:\n"+dnsOut)
	}

	bfOut, err := DetectBruteForce(pcapFile)
	if err == nil && bfOut != "" {
		results = append(results, "Brute Force Detected:\n"+bfOut)
	}

	if len(results) == 0 {
		return "No anomalies detected", nil
	}
	return strings.Join(results, "\n\n"), nil
}

func DetectPortScan(pcapFile string) (string, error) {
	out, err := runCapture("-r", pcapFile, "-q", "-z", "conv,tcp")
	if err != nil {
		return "", err
	}

	lines := strings.Split(out, "\n")
	var suspicious []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "|") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 8 {
			packets, err := strconv.Atoi(parts[3])
			if err == nil && packets < 5 && len(parts[0]) > 0 {
				suspicious = append(suspicious, fmt.Sprintf("Low-packet conversation: %s (%d packets)", parts[0], packets))
			}
		}
	}
	return strings.Join(suspicious, "\n"), nil
}

func DetectDNSTunneling(pcapFile string) (string, error) {
	out, err := runCapture("-r", pcapFile, "-Y", "dns", "-T", "fields", "-e", "dns.qry.name", "-e", "dns.qry.type", "-e", "dns.resp.len")
	if err != nil {
		return "", err
	}

	lines := strings.Split(out, "\n")
	domainCount := make(map[string]int)
	var suspicious []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			domain := parts[0]
			domainCount[domain]++
			if domainCount[domain] > 100 {
				suspicious = append(suspicious, fmt.Sprintf("High volume of queries for %s: %d", domain, domainCount[domain]))
			}
			if len(domain) > 50 {
				suspicious = append(suspicious, fmt.Sprintf("Unusually long domain: %s", domain))
			}
		}
	}

	return strings.Join(suspicious, "\n"), nil
}

func DetectBruteForce(pcapFile string) (string, error) {
	out, err := runCapture("-r", pcapFile, "-Y", "smb or smb2 or ssh or ftp or rdp", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "smb.nt_status", "-e", "ftp.response.code", "-e", "ssh.server.protocol")
	if err != nil {
		return "", err
	}

	lines := strings.Split(out, "\n")
	sourceCount := make(map[string]int)
	var suspicious []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			src := parts[0]
			sourceCount[src]++
			if sourceCount[src] > 50 {
				suspicious = append(suspicious, fmt.Sprintf("High number of auth attempts from %s: %d", src, sourceCount[src]))
			}
		}
	}

	return strings.Join(suspicious, "\n"), nil
}

func ExtractPCAPMetadata(pcapFile string) (string, error) {
	return runCapinfos(pcapFile)
}

func MergePCAPs(pcapFiles []string, outputFile string) (string, error) {
	args := []string{"-w", outputFile}
	args = append(args, pcapFiles...)
	return runMergecap(args...)
}

func SplitPCAP(pcapFile string, packetCount int) (string, error) {
	return runEditcap("-c", fmt.Sprintf("%d", packetCount), pcapFile, strings.TrimSuffix(pcapFile, ".pcap")+"_split.pcap")
}

func FilterPCAP(inputFile, outputFile, displayFilter string) (string, error) {
	return runCapture("-r", inputFile, "-Y", displayFilter, "-w", outputFile)
}
