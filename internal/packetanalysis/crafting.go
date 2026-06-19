package packetanalysis

import (
	"fmt"
	"os"
	"path/filepath"
)

func CraftARPPacket(srcIP, dstIP, srcMAC, dstMAC string) (string, error) {
	pcapFile := filepath.Join(os.TempDir(), "arp_packet.pcap")
	args := []string{"--arp", fmt.Sprintf("srcip=%s", srcIP), fmt.Sprintf("dstip=%s", dstIP), fmt.Sprintf("srcmac=%s", srcMAC), fmt.Sprintf("dstmac=%s", dstMAC), "-w", pcapFile}
	return runTcpreplay(args...)
}

func CraftDNSPacket(domain, queryType, srcIP, dstIP string) (string, error) {
	pcapFile := filepath.Join(os.TempDir(), "dns_packet.pcap")
	args := []string{"--dns", fmt.Sprintf("qname=%s", domain), fmt.Sprintf("qtype=%s", queryType), fmt.Sprintf("srcip=%s", srcIP), fmt.Sprintf("dstip=%s", dstIP), "-w", pcapFile}
	return runTcpreplay(args...)
}

func CraftHTTPPacket(method, host, path string) (string, error) {
	pcapFile := filepath.Join(os.TempDir(), "http_packet.pcap")
	args := []string{"--http", fmt.Sprintf("method=%s", method), fmt.Sprintf("host=%s", host), fmt.Sprintf("path=%s", path), "-w", pcapFile}
	return runTcpreplay(args...)
}

func CraftSYNPacket(srcIP, dstIP, port string) (string, error) {
	pcapFile := filepath.Join(os.TempDir(), "syn_packet.pcap")
	args := []string{"--tcp", "-S", fmt.Sprintf("srcip=%s", srcIP), fmt.Sprintf("dstip=%s", dstIP), fmt.Sprintf("dstport=%s", port), "-w", pcapFile}
	return runTcpreplay(args...)
}

func CraftRSTPacket(srcIP, dstIP, port string) (string, error) {
	pcapFile := filepath.Join(os.TempDir(), "rst_packet.pcap")
	args := []string{"--tcp", "-R", fmt.Sprintf("srcip=%s", srcIP), fmt.Sprintf("dstip=%s", dstIP), fmt.Sprintf("dstport=%s", port), "-w", pcapFile}
	return runTcpreplay(args...)
}

func SendPacket(packetFile string, interfaceName string) (string, error) {
	return runTcpreplay("-i", interfaceName, packetFile)
}

func PacketTemplate(templateName string) (string, error) {
	templates := map[string]string{
		"arp_request":   "nping --arp --arp-type ARP-request --src-ip 192.168.1.100 --dest-ip 192.168.1.1",
		"arp_reply":     "nping --arp --arp-type ARP-reply --src-ip 192.168.1.1 --dest-ip 192.168.1.100",
		"syn_flood":     "nping --tcp -S --flags syn --dest-ip TARGET --dest-port 80 --rate 1000",
		"dns_query":     "nping --udp --dest-ip DNS_SERVER --dest-port 53 --data \"DNS_QUERY_HEX\"",
		"http_get":      "nping --tcp --dest-ip TARGET --dest-port 80 --data \"GET / HTTP/1.1\\r\\nHost: TARGET\\r\\n\\r\\n\"",
		"ping_sweep":    "nping --icmp --icmp-type echo-request --dest-ip SUBNET/24",
		"tcp_connect":   "nping --tcp -A --flags syn --dest-ip TARGET --dest-port PORT",
		"tls_client_hello": "nping --tcp --dest-ip TARGET --dest-port 443 --data \"TLS_CLIENT_HELLO_HEX\"",
	}

	tmpl, ok := templates[templateName]
	if !ok {
		return "", fmt.Errorf("template %q not found", templateName)
	}
	return tmpl, nil
}
