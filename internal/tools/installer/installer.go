package installer

import (
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

var safePkgPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

type Installer struct {
	DryRun bool
}

func New() *Installer {
	return &Installer{}
}

func validatePackageName(pkg, method string) error {
	if !safePkgPattern.MatchString(pkg) {
		return fmt.Errorf("invalid %s package name %q: must match %s", method, pkg, safePkgPattern.String())
	}
	if strings.Contains(pkg, "..") || strings.Contains(pkg, "/") || strings.Contains(pkg, "\\") {
		return fmt.Errorf("invalid %s package name %q: path traversal not allowed", method, pkg)
	}
	return nil
}

func (inst *Installer) EnsureTool(name, aptPackage, goPackage, pipPackage string) error {
	if inst.toolExists(name) {
		return nil
	}
	switch {
	case aptPackage != "" && runtime.GOOS == "linux":
		return inst.aptInstall(aptPackage)
	case goPackage != "":
		return inst.goInstall(goPackage)
	case pipPackage != "":
		return inst.pipInstall(pipPackage)
	}
	return fmt.Errorf("no install method for %s", name)
}

func (inst *Installer) toolExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (inst *Installer) aptInstall(pkg string) error {
	if inst.DryRun {
		return nil
	}
	if err := validatePackageName(pkg, "apt"); err != nil {
		return err
	}
	out, err := exec.Command("apt-get", "install", "-y", pkg).CombinedOutput()
	if err != nil {
		return fmt.Errorf("apt install %s failed: %s: %w", pkg, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (inst *Installer) goInstall(pkg string) error {
	if inst.DryRun {
		return nil
	}
	if err := validatePackageName(pkg, "go"); err != nil {
		return err
	}
	cmd := exec.Command("go", "install", pkg+"@latest")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go install %s failed: %s: %w", pkg, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (inst *Installer) pipInstall(pkg string) error {
	if inst.DryRun {
		return nil
	}
	if err := validatePackageName(pkg, "pip"); err != nil {
		return err
	}
	cmd := exec.Command("pip3", "install", pkg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pip install %s failed: %s: %w", pkg, strings.TrimSpace(string(out)), err)
	}
	return nil
}
