package openvas

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type OpenVASConfig struct {
	Host       string
	Port       int
	Username   string
	Password   string
	UseTLS     bool
	GMPVersion string
}

type OpenVASTask struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Progress    int       `json:"progress"`
	Target      string    `json:"target"`
	StartTime   time.Time `json:"start_time,omitempty"`
	EndTime     time.Time `json:"end_time,omitempty"`
	ReportID    string    `json:"report_id,omitempty"`
}

type OpenVASTarget struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Hosts       []string `json:"hosts"`
	Ports       string   `json:"ports"`
	AliveTest   string   `json:"alive_test"`
	Credentials []string `json:"credentials,omitempty"`
}

type OpenVASReport struct {
	ID          string         `json:"id"`
	TaskID      string         `json:"task_id"`
	Format      string         `json:"format"`
	ResultCount int            `json:"result_count"`
	Results     []OpenVASResult `json:"results,omitempty"`
}

type OpenVASResult struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	Host        string  `json:"host"`
	Port        string  `json:"port"`
	Protocol    string  `json:"protocol"`
	Description string  `json:"description"`
	Solution    string  `json:"solution"`
	NVTName     string  `json:"nvt_name"`
	QoD         string  `json:"qod"`
}

type OpenVASNVT struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Family   string `json:"family"`
	Category string `json:"category"`
	CVSS     float64 `json:"cvss"`
	Summary  string `json:"summary"`
	Solution string `json:"solution"`
	Tags     string `json:"tags"`
}

type OpenVASEngine struct {
	config    OpenVASConfig
	conn      net.Conn
	sshClient *ssh.Client
	tlsConn   *tls.Conn
	token     string
	connected bool
	mu        sync.RWMutex
}

func NewOpenVASEngine(config OpenVASConfig) *OpenVASEngine {
	if config.Port == 0 {
		config.Port = 9390
	}
	if config.GMPVersion == "" {
		config.GMPVersion = "9.0"
	}
	return &OpenVASEngine{
		config: config,
	}
}

func (e *OpenVASEngine) Connect() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", e.config.Host, e.config.Port)

	if e.config.UseTLS {
		tlsConn, err := tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return fmt.Errorf("openvas tls connect failed: %w", err)
		}
		e.tlsConn = tlsConn
	} else {
		sshConfig := &ssh.ClientConfig{
			User:            e.config.Username,
			Auth:            []ssh.AuthMethod{ssh.Password(e.config.Password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         30 * time.Second,
		}
		sshClient, err := ssh.Dial("tcp", addr, sshConfig)
		if err != nil {
			return fmt.Errorf("openvas ssh connect failed: %w", err)
		}
		e.sshClient = sshClient

		session, err := sshClient.NewSession()
		if err != nil {
			return fmt.Errorf("openvas ssh session failed: %w", err)
		}
		defer session.Close()

		pipe, err := session.StdinPipe()
		if err != nil {
			return fmt.Errorf("openvas ssh pipe failed: %w", err)
		}
		defer pipe.Close()
	}

	e.connected = true
	return nil
}

func (e *OpenVASEngine) Authenticate() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	cmd := fmt.Sprintf(`<authenticate>
  <credentials>
    <username>%s</username>
    <password>%s</password>
  </credentials>
</authenticate>`, e.config.Username, e.config.Password)

	resp, err := e.sendCommandRaw(cmd)
	if err != nil {
		return fmt.Errorf("openvas authenticate failed: %w", err)
	}

	if resp == "" {
		return fmt.Errorf("openvas authenticate returned empty response")
	}

	return nil
}

func (e *OpenVASEngine) Disconnect() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.sshClient != nil {
		e.sshClient.Close()
		e.sshClient = nil
	}
	if e.tlsConn != nil {
		e.tlsConn.Close()
		e.tlsConn = nil
	}
	if e.conn != nil {
		e.conn.Close()
		e.conn = nil
	}
	e.connected = false
	return nil
}

func (e *OpenVASEngine) IsConnected() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.connected
}

func (e *OpenVASEngine) sendCommandRaw(cmd string) (string, error) {
	if e.tlsConn != nil {
		_, err := e.tlsConn.Write([]byte(cmd + "\n"))
		if err != nil {
			return "", fmt.Errorf("openvas send tls command failed: %w", err)
		}
		buf := make([]byte, 65536)
		n, err := e.tlsConn.Read(buf)
		if err != nil {
			return "", fmt.Errorf("openvas read tls response failed: %w", err)
		}
		return string(buf[:n]), nil
	}

	if e.sshClient != nil {
		session, err := e.sshClient.NewSession()
		if err != nil {
			return "", fmt.Errorf("openvas ssh session failed: %w", err)
		}
		defer session.Close()

		out, err := session.CombinedOutput(cmd)
		if err != nil {
			return "", fmt.Errorf("openvas ssh command failed: %w", err)
		}
		return string(out), nil
	}

	return "", fmt.Errorf("openvas not connected")
}
