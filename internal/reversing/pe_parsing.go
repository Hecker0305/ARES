package reversing

import (
	"bytes"
	"fmt"
	"os/exec"
)

func (e *ReversingEngine) PEDumpHeaders(binaryFile string) (string, error) {
	cmd := exec.Command("dumpbin", "/headers", binaryFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("objdump", "-x", binaryFile)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), fmt.Errorf("pe dump headers: %w", err)
		}
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) PEDumpSections(binaryFile string) (string, error) {
	cmd := exec.Command("dumpbin", "/sections", binaryFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("objdump", "-h", binaryFile)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), fmt.Errorf("pe dump sections: %w", err)
		}
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) PEDumpImports(binaryFile string) (string, error) {
	cmd := exec.Command("dumpbin", "/imports", binaryFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("objdump", "-p", binaryFile)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), fmt.Errorf("pe dump imports: %w", err)
		}
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) PEDumpExports(binaryFile string) (string, error) {
	cmd := exec.Command("dumpbin", "/exports", binaryFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("objdump", "-p", binaryFile)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), fmt.Errorf("pe dump exports: %w", err)
		}
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) PEDumpResources(binaryFile string) (string, error) {
	cmd := exec.Command("dumpbin", "/resources", binaryFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("pe dump resources: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) PEDumpSymbols(binaryFile string) (string, error) {
	cmd := exec.Command("dumpbin", "/symbols", binaryFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("objdump", "-t", binaryFile)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), fmt.Errorf("pe dump symbols: %w", err)
		}
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) PEEntryPoint(binaryFile string) (string, error) {
	cmd := exec.Command("dumpbin", "/headers", binaryFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("readelf", "-h", binaryFile)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), fmt.Errorf("pe entry point: %w", err)
		}
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) PECheckSignature(binaryFile string) (string, error) {
	cmd := exec.Command("sigcheck", "-a", binaryFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("dumpbin", "/verify", binaryFile)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), fmt.Errorf("pe check signature: %w", err)
		}
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) PEListDLLs(binaryFile string) (string, error) {
	cmd := exec.Command("dumpbin", "/dependents", binaryFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("objdump", "-p", binaryFile)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), fmt.Errorf("pe list dlls: %w", err)
		}
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) PEAnalyze(binaryFile string) (string, error) {
	cmd := exec.Command("python3", "-c",
		fmt.Sprintf(`import pefile; pe = pefile.PE("%s"); print(pe.dump_info())`, binaryFile))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("pe analyze: %w", err)
	}
	return stdout.String(), nil
}
