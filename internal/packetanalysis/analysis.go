package packetanalysis

import (
	"fmt"
	"strconv"
	"strings"
)

func AnalyzePcap(pcapFile string) (*TrafficSummary, error) {
	out, err := runCapture("-r", pcapFile, "-q", "-z", "io,stat,1")
	if err != nil {
		return nil, err
	}

	summary := &TrafficSummary{
		Protocols: make(map[string]int),
	}

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Packets:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				summary.TotalPackets, _ = strconv.Atoi(parts[1])
			}
		}
		if strings.Contains(line, "Bytes:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				summary.TotalBytes, _ = strconv.ParseInt(parts[1], 10, 64)
			}
		}
		if strings.Contains(line, "Duration:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				summary.Duration = parts[1]
			}
		}
	}

	protoOut, err := AnalyzeProtocols(pcapFile)
	if err == nil {
		summary.Protocols = protoOut
	}

	return summary, nil
}

func AnalyzeProtocols(pcapFile string) (map[string]int, error) {
	out, err := runCapture("-r", pcapFile, "-q", "-z", "io,phs")
	if err != nil {
		return nil, err
	}

	protocols := make(map[string]int)
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Protocol") || strings.HasPrefix(line, "=") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			name := strings.TrimRight(parts[0], ":")
			count, err := strconv.Atoi(parts[len(parts)-1])
			if err == nil {
				protocols[name] = count
			}
		}
	}
	return protocols, nil
}

func AnalyzeConversations(pcapFile string) (string, error) {
	tcpOut, err := runCapture("-r", pcapFile, "-q", "-z", "conv,tcp")
	if err != nil {
		return "", err
	}
	udpOut, err := runCapture("-r", pcapFile, "-q", "-z", "conv,udp")
	if err != nil {
		return tcpOut, nil
	}
	return fmt.Sprintf("TCP Conversations:\n%s\n\nUDP Conversations:\n%s", tcpOut, udpOut), nil
}

func AnalyzeEndpoints(pcapFile string) (string, error) {
	return runCapture("-r", pcapFile, "-q", "-z", "endpoints,ip")
}

func AnalyzeDNS(pcapFile string) (string, error) {
	return runCapture("-r", pcapFile, "-Y", "dns", "-T", "fields", "-e", "dns.qry.name")
}

func AnalyzeHTTP(pcapFile string) (string, error) {
	return runCapture("-r", pcapFile, "-Y", "http.request", "-T", "fields", "-e", "http.host", "-e", "http.request.uri")
}

func AnalyzeTLS(pcapFile string) (string, error) {
	return runCapture("-r", pcapFile, "-Y", "tls.handshake.type == 1", "-T", "fields", "-e", "tls.handshake.ciphersuite", "-e", "tls.handshake.extensions_server_name")
}

func AnalyzeSMB(pcapFile string) (string, error) {
	return runCapture("-r", pcapFile, "-Y", "smb or smb2", "-T", "fields", "-e", "smb.cmd", "-e", "smb2.cmd")
}

func AnalyzeKerberos(pcapFile string) (string, error) {
	return runCapture("-r", pcapFile, "-Y", "kerberos", "-T", "fields", "-e", "kerberos.msg_type", "-e", "kerberos.CNameString", "-e", "kerberos.SNameString")
}

func AnalyzeARP(pcapFile string) (string, error) {
	return runCapture("-r", pcapFile, "-Y", "arp", "-T", "fields", "-e", "arp.src.proto_ipv4", "-e", "arp.opcode")
}

func ExtractCredentials(pcapFile string) (string, error) {
	return runCapture("-r", pcapFile, "-Y", "ftp.request.command == USER or ftp.request.command == PASS or http.authbasic or telnet.data or smtp.auth", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "ftp.request.command", "-e", "ftp.request.arg", "-e", "http.authbasic", "-e", "telnet.data", "-e", "smtp.auth.username")
}

func ExtractFiles(pcapFile string, outputDir string) (string, error) {
	args := []string{"-r", pcapFile, "--export-objects", fmt.Sprintf("http,%s", outputDir)}
	out, err := runCapture(args...)
	if err != nil {
		args2 := []string{"-r", pcapFile, "--export-objects", fmt.Sprintf("smb,%s", outputDir)}
		out2, err2 := runCapture(args2...)
		if err2 != nil {
			return out + "\n" + out2, nil
		}
		return out2, nil
	}
	return out, nil
}
