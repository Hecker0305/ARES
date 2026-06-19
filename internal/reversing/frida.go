package reversing

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
)

func (e *ReversingEngine) FridaSpawn(process, scriptFile string) (string, error) {
	cmd := exec.Command("frida", "-f", process, "-l", scriptFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("frida spawn: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) FridaAttach(pid int, scriptFile string) (string, error) {
	cmd := exec.Command("frida", "-p", strconv.Itoa(pid), "-l", scriptFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("frida attach: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) FridaListProcesses() (string, error) {
	cmd := exec.Command("frida-ps")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("frida-ps: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) FridaListRunningProcesses(device string) (string, error) {
	cmd := exec.Command("frida-ps", "-U")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("frida-ps usb: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) FridaTraceFunction(binary, funcName string) (string, error) {
	cmd := exec.Command("frida", "-f", binary, "-l", "-",
		fmt.Sprintf(`Interceptor.attach(Module.findExportByName(null, "%s"), { onEnter: function(args) { console.log("[+] Entering %s"); }, onLeave: function(retval) { console.log("[+] Leaving %s"); } });`, funcName, funcName, funcName))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("frida trace: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) FridaHookLibrary(binary, library, funcName string) (string, error) {
	cmd := exec.Command("frida", "-f", binary, "-l", "-",
		fmt.Sprintf(`Interceptor.attach(Module.findExportByName("%s", "%s"), { onEnter: function(args) { console.log("[+] Hooked %s!%s"); }, onLeave: function(retval) { console.log("[+] %s returned"); } });`, library, funcName, library, funcName, funcName))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("frida hook library: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) FridaBypassPin(binary string) (string, error) {
	script := `Java.perform(function() { var ArrayList = Java.use('java.util.ArrayList'); var arrayList = ArrayList.$new(); arrayList.add('Test'); var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager'); var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl'); TrustManagerImpl.trustAnchors.implementation = function() { return arrayList; }; });`
	cmd := exec.Command("frida", "-f", binary, "-l", "-", script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("frida ssl pinning bypass: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) FridaDumpMemory(pid int, outputFile string) (string, error) {
	script := fmt.Sprintf(`var processId = %d; var f = new File("%s", "wb"); Process.enumerateRanges('rwx').forEach(function(range) { f.write(Memory.readByteArray(range.base, range.size)); }); f.flush(); f.close(); console.log("[+] Memory dumped to %s");`, pid, outputFile, outputFile)
	cmd := exec.Command("frida", "-p", strconv.Itoa(pid), "-e", script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("frida dump memory: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) FridaGenerateScriptHook(functionSig, onEnter, onLeave string) (string, error) {
	script := fmt.Sprintf(`Interceptor.attach(ptr("%s"), { onEnter: function(args) { %s }, onLeave: function(retval) { %s } });`, functionSig, onEnter, onLeave)
	return script, nil
}
