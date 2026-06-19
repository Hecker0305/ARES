package forensics

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// J1 — Volatility / Memory Forensics
type MemoryForensicEngine struct{}

func NewMemoryForensicEngine() *MemoryForensicEngine {
	return &MemoryForensicEngine{}
}

func (m *MemoryForensicEngine) AcquireMemory(outputPath string) error {
	cmd := exec.Command("winpmem", outputPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Fallback to /proc/kcore on Linux
		cmd = exec.Command("sh", "-c", "dd if=/proc/kcore of="+outputPath+" bs=1M 2>/dev/null")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("memory acquisition: %w", err)
		}
	}
	return nil
}

func (m *MemoryForensicEngine) RunVolatilityPlugin(memoryImage, plugin string, args []string) (string, error) {
	cmdArgs := append([]string{"-f", memoryImage, plugin}, args...)
	cmd := exec.Command("volatility3", cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("volatility: %w", err)
	}
	return stdout.String(), nil
}

func (m *MemoryForensicEngine) ExtractProcessList(memoryImage string) (string, error) {
	return m.RunVolatilityPlugin(memoryImage, "windows.pslist.PsList", nil)
}

func (m *MemoryForensicEngine) ExtractNetworkConns(memoryImage string) (string, error) {
	return m.RunVolatilityPlugin(memoryImage, "windows.netscan.NetScan", nil)
}

func (m *MemoryForensicEngine) ExtractRegistry(memoryImage string) (string, error) {
	return m.RunVolatilityPlugin(memoryImage, "windows.registry.hivelist.HiveList", nil)
}

// J2 — Disk Image Analysis
type DiskForensicEngine struct{}

func NewDiskForensicEngine() *DiskForensicEngine {
	return &DiskForensicEngine{}
}

func (d *DiskForensicEngine) AnalyzeImage(imagePath string) error {
	cmd := exec.Command("fsstat", imagePath)
	cmd.Stdout = nil
	return cmd.Run()
}

func (d *DiskForensicEngine) ExtractDeletedFiles(imagePath, outputDir string) error {
	cmd := exec.Command("foremost", "-i", imagePath, "-o", outputDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("foremost: %w\n%s", err, stderr.String())
	}
	return nil
}

// J3 — Log Tampering Detection
type LogForensicEngine struct{}

func NewLogForensicEngine() *LogForensicEngine {
	return &LogForensicEngine{}
}

func (l *LogForensicEngine) DetectWindowsLogClearing() ([]string, error) {
	cmd := exec.Command("powershell", "-NoP", "-NonI", "-C",
		`Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102,104} -MaxEvents 10 | Select-Object TimeCreated,Id,Message | Format-Table -Auto`)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("event log check: %w", err)
	}
	lines := strings.Split(stdout.String(), "\n")
	var events []string
	for _, l := range lines {
		if strings.Contains(l, "1102") || strings.Contains(l, "104") {
			events = append(events, l)
		}
	}
	return events, nil
}

func (l *LogForensicEngine) CheckLogContinuity(logPath string) (bool, error) {
	info, err := os.Stat(logPath)
	if err != nil {
		return false, fmt.Errorf("stat log: %w", err)
	}
	modTime := info.ModTime()
	if time.Since(modTime) > 24*time.Hour {
		return false, fmt.Errorf("log modification time gap detected: %v", modTime)
	}
	return true, nil
}

// J4 — Forensic Timeline Automation
type TimelineBuilder struct {
	entries []TimelineEntry
}

type TimelineEntry struct {
	Timestamp   time.Time
	Source      string
	EventType   string
	Description string
	Artifact    string
}

func NewTimelineBuilder() *TimelineBuilder {
	return &TimelineBuilder{entries: make([]TimelineEntry, 0)}
}

func (t *TimelineBuilder) AddEntry(source, eventType, description, artifact string) {
	t.entries = append(t.entries, TimelineEntry{
		Timestamp:   time.Now(),
		Source:      source,
		EventType:   eventType,
		Description: description,
		Artifact:    artifact,
	})
}

func (t *TimelineBuilder) BuildTimeline() string {
	var buf bytes.Buffer
	buf.WriteString("Timestamp,Source,EventType,Description,Artifact\n")
	for _, e := range t.entries {
		buf.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s\n",
			e.Timestamp.Format(time.RFC3339),
			e.Source, e.EventType, e.Description, e.Artifact))
	}
	return buf.String()
}
