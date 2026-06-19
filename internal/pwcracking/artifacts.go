package pwcracking

type ArtifactType int

const (
	ArtifactEventLog   ArtifactType = iota
	ArtifactRegistry   ArtifactType = iota
	ArtifactFileSystem ArtifactType = iota
	ArtifactNetwork    ArtifactType = iota
	ArtifactMemory     ArtifactType = iota
	ArtifactProcess    ArtifactType = iota
)

func (a ArtifactType) String() string {
	switch a {
	case ArtifactEventLog:
		return "EventLog"
	case ArtifactRegistry:
		return "Registry"
	case ArtifactFileSystem:
		return "FileSystem"
	case ArtifactNetwork:
		return "Network"
	case ArtifactMemory:
		return "Memory"
	case ArtifactProcess:
		return "Process"
	default:
		return "Unknown"
	}
}

type ForensicArtifact struct {
	Type        ArtifactType
	Description string
	Location    string
	Notes       string
}

func GetHydraArtifacts() []ForensicArtifact {
	return []ForensicArtifact{
		{Type: ArtifactNetwork, Description: "Rapid successive connection attempts to target service", Location: "Target IP:Port", Notes: "Multiple TCP connections in short timeframe"},
		{Type: ArtifactEventLog, Description: "Failed logon events from brute force", Location: "Event ID 4625 (Windows Security Log)", Notes: "Multiple failed logon attempts from same source IP"},
		{Type: ArtifactEventLog, Description: "Account lockout events", Location: "Event ID 4740 (Account Locked Out)", Notes: "Threshold-based account lockout triggered"},
		{Type: ArtifactNetwork, Description: "IDS/IPS signature match for brute force", Location: "Network IDS alerts", Notes: "Signature patterns: multiple auth failures, rapid connections"},
		{Type: ArtifactFileSystem, Description: "Hydra session file", Location: "hydra.restore", Notes: "Restore file created during brute force sessions"},
		{Type: ArtifactProcess, Description: "Hydra process execution", Location: "Process list (hydra.exe on Windows, hydra on Linux)", Notes: "High CPU usage during brute force"},
	}
}

func GetJohnArtifacts() []ForensicArtifact {
	return []ForensicArtifact{
		{Type: ArtifactFileSystem, Description: "John session file", Location: "$HOME/.john/john.log", Notes: "Session progress and configuration logged"},
		{Type: ArtifactFileSystem, Description: "John pot file", Location: "$HOME/.john/john.pot", Notes: "Contains all cracked passwords in plaintext"},
		{Type: ArtifactProcess, Description: "John process execution", Location: "Process list (john.exe or john)", Notes: "CPU-intensive process; multiple cores utilized"},
		{Type: ArtifactMemory, Description: "High CPU utilization during cracking", Location: "System performance counters", Notes: "Near 100% CPU on all available cores"},
		{Type: ArtifactEventLog, Description: "Resource exhaustion warnings", Location: "System Event Log", Notes: "Potential scheduling or resource contention"},
		{Type: ArtifactFileSystem, Description: "Temporary hash files", Location: "Temp directory", Notes: "Copies of hash files may persist in temp"},
		{Type: ArtifactNetwork, Description: "No network activity (offline cracking)", Location: "N/A", Notes: "John is an offline tool; absence of network activity is normal"},
	}
}

func GetHashcatArtifacts() []ForensicArtifact {
	return []ForensicArtifact{
		{Type: ArtifactFileSystem, Description: "Hashcat potfile with cracked hashes", Location: "$HOME/.hashcat/hashcat.potfile", Notes: "Contains hash:plaintext pairs for all cracked hashes"},
		{Type: ArtifactFileSystem, Description: "Hashcat restore file", Location: "hashcat.restore", Notes: "Created when hashcat is interrupted"},
		{Type: ArtifactProcess, Description: "Hashcat process with GPU utilization", Location: "Process list (hashcat.exe or hashcat)", Notes: "High GPU memory and compute usage"},
		{Type: ArtifactMemory, Description: "GPU kernel execution during cracking", Location: "GPU driver logs", Notes: "OpenCL/CUDA kernels executing on GPU"},
		{Type: ArtifactEventLog, Description: "Driver timeout events", Location: "Event ID 4101 (Display Driver Crash)", Notes: "GPU-intensive loads may trigger TDR events"},
		{Type: ArtifactFileSystem, Description: "Temp files in working directory", Location: "Current directory", Notes: "Hashcat may write temp files during cracking"},
		{Type: ArtifactEventLog, Description: "Thermal throttling events", Location: "System Event Log / GPU driver log", Notes: "Extended GPU load may cause thermal stress"},
	}
}

func GetDetectionIndicators() []ForensicArtifact {
	return []ForensicArtifact{
		{Type: ArtifactEventLog, Description: "Multiple account lockouts across domain", Location: "Event ID 4740 (multiple sources)", Notes: "Coordinated brute force across multiple accounts"},
		{Type: ArtifactEventLog, Description: "Failed logon event spike", Location: "Event ID 4625 with LogonType 3 (Network)", Notes: "High volume of logon failures from single IP"},
		{Type: ArtifactEventLog, Description: "Kerberos pre-authentication failures", Location: "Event ID 4771", Notes: "AS-REP roasting or Kerberoasting activity"},
		{Type: ArtifactNetwork, Description: "High rate of SMB/SSH/RDP connection attempts", Location: "Network flow data", Notes: "Connection rate exceeds baseline"},
		{Type: ArtifactEventLog, Description: "User account enumeration via timing", Location: "Event ID 4625 with different usernames", Notes: "Many different usernames from single source"},
		{Type: ArtifactFileSystem, Description: "Wordlist files on disk", Location: "Temp or working directories", Notes: "Large text files of passwords stored locally"},
		{Type: ArtifactProcess, Description: "Cracking tool process detection", Location: "Process name monitoring", Notes: "Known process names: hydra, john, hashcat, medusa, ncrack"},
	}
}
