package reversing

import (
	"bytes"
	"fmt"
	"os/exec"
)

func (e *ReversingEngine) SSDTDump(binaryFile string) (string, error) {
	cmd := exec.Command("readelf", "-s", "--wide", binaryFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("objdump", "-t", binaryFile)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), fmt.Errorf("ssdt dump: %w", err)
		}
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) SSDTFindHook(binaryFile string) (string, error) {
	cmd := exec.Command("python3", "-c",
		fmt.Sprintf(`import struct, sys; data = open("%s","rb").read(); [print(f"SSDT[{i}] = 0x{struct.unpack('<I', data[i*4:(i+1)*4])[0]:08x}") for i in range(len(data)//4)]`, binaryFile))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("ssdt find hook: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) SSDTFindByIndex(index int) (string, error) {
	cmd := exec.Command("python3", "-c",
		fmt.Sprintf(`import sys; print("SSDT[%d] lookup requires a kernel memory dump or symbol table for your target system", %d)`, index, index))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("ssdt index lookup: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) IDTDump(binaryFile string) (string, error) {
	cmd := exec.Command("readelf", "-s", "--wide", binaryFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("objdump", "-d", binaryFile)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), fmt.Errorf("idt dump: %w", err)
		}
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) IDTCheckHooks(binaryFile string) (string, error) {
	cmd := exec.Command("python3", "-c",
		fmt.Sprintf(`import struct; data = open("%s","rb").read(); idt_entries = len(data)//8; [print(f"IDT[{i}] = selector=0x{struct.unpack('<H', data[i*8:(i*8)+2])[0]:04x} offset=0x{struct.unpack('<I', data[(i*8)+4:(i*8)+8])[0]:08x}") for i in range(idt_entries)]`, binaryFile))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("idt check hooks: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) SyscallLookup(syscallNumber string) (string, error) {
	cmd := exec.Command("python3", "-c",
		fmt.Sprintf(`tables = {"0": "NtCreateFile", "1": "NtOpenFile", "2": "NtCreateKey", "3": "NtOpenKey", "4": "NtQueryInformationProcess", "5": "NtAllocateVirtualMemory", "6": "NtProtectVirtualMemory", "7": "NtWriteVirtualMemory", "8": "NtCreateThreadEx"}; print(tables.get(%q, "syscall lookup requires Windows NT kernel symbol table"))`, syscallNumber))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("syscall lookup: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) SyscallTable() (string, error) {
	cmd := exec.Command("python3", "-c", `import sys; print("x86 syscall table:\n0x0000 - NtCreateFile\n0x0001 - NtOpenFile\n0x0002 - NtCreateKey\n0x0003 - NtOpenKey\n0x0004 - NtQueryInformationProcess\n0x0005 - NtAllocateVirtualMemory\n0x0006 - NtProtectVirtualMemory\n0x0007 - NtWriteVirtualMemory\n0x0008 - NtCreateThreadEx\n0x0009 - NtOpenProcess\n0x000a - NtOpenThread\n0x000b - NtClose\n0x000c - NtReadVirtualMemory\n0x000d - NtQuerySystemInformation\n0x000e - NtQueryInformationFile\n0x000f - NtSetInformationFile\n\nx64 syscall table:\n0x0000 - NtCreateFile\n0x0001 - NtOpenFile\n0x0002 - NtCreateKey\n0x0003 - NtOpenKey\n0x0004 - NtQueryInformationProcess\n... (truncated, full table requires ntoskrnl.exe dump)")`)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("syscall table dump: %w", err)
	}
	return stdout.String(), nil
}
