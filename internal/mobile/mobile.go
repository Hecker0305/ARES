package mobile

import (
	"fmt"
	"os"
	"os/exec"
)

// H1 — Frida Dynamic Instrumentation
type FridaEngine struct{}

func NewFridaEngine() *FridaEngine {
	return &FridaEngine{}
}

func (f *FridaEngine) ListDevices() (string, error) {
	cmd := exec.Command("frida-ls-devices")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("frida devices: %w", err)
	}
	return string(output), nil
}

func (f *FridaEngine) Attach(deviceID, processName string) error {
	cmd := exec.Command("frida", "-D", deviceID, "-n", processName, "-l", "-")
	return cmd.Start()
}

func (f *FridaEngine) SSLUnpinScript() string {
	return `
Java.perform(function() {
    var TrustManager = Java.registerClass({
        name: 'com.android.org.conscrypt.TrustManagerImpl',
        methods: {
            checkServerTrusted: function(chain, authType) { return true; }
        }
    });
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
        this.init(km, [TrustManager.$new()], sr);
    };
});
`
}

// H2 — APK/IPA Repackaging
type MobileRepackager struct{}

func NewMobileRepackager() *MobileRepackager {
	return &MobileRepackager{}
}

func (m *MobileRepackager) DecompileAPK(apkPath, outputDir string) error {
	cmd := exec.Command("apktool", "d", apkPath, "-o", outputDir, "-f")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apktool decompile: %w", err)
	}
	return nil
}

func (m *MobileRepackager) RebuildAPK(sourceDir, outputPath string) error {
	cmd := exec.Command("apktool", "b", sourceDir, "-o", outputPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apktool rebuild: %w", err)
	}
	return nil
}

func (m *MobileRepackager) SignAPK(apkPath string) error {
	cmd := exec.Command("apksigner", "sign", "--ks", "test.keystore", "--ks-pass", "pass:android", apkPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apksigner: %w", err)
	}
	return nil
}

func (m *MobileRepackager) PatchNetworkSecurityConfig(sourceDir string) error {
	xmlPath := sourceDir + "/res/xml/network_security_config.xml"
	config := `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>`
	return os.WriteFile(xmlPath, []byte(config), 0644)
}

// H3 — Certificate Pinning Bypass
type PinningBypassEngine struct{}

func NewPinningBypassEngine() *PinningBypassEngine {
	return &PinningBypassEngine{}
}

func (p *PinningBypassEngine) FridaUnpinScript() string {
	return `
setTimeout(function() {
    Java.perform(function() {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

        TrustManagerImpl.checkServerTrusted.implementation = function() {
            console.log('[+] Bypassing SSL pinning');
            return true;
        };
    });
}, 0);
`
}

func (p *PinningBypassEngine) ObjectionPin(deviceID, appName string) error {
	cmd := exec.Command("objection", "-g", appName, "explore", "--disable-ssl-pinning")
	return cmd.Start()
}

func (p *PinningBypassEngine) InstallProxyCA(certPath string) error {
	cmd := exec.Command("adb", "root")
	cmd.Run()
	cmd = exec.Command("adb", "remount")
	cmd.Run()
	cmd = exec.Command("adb", "push", certPath, "/system/etc/security/cacerts/")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install CA: %w", err)
	}
	return nil
}
