#!/bin/bash
set -e

# ============================================================
# Ares Engine — .deb Package Builder
# Run this on Kali Linux or any Debian-based system.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGE_NAME="ares-engine"
PACKAGE_VERSION="$(cd "$PROJECT_DIR" && git describe --tags --always --dirty 2>/dev/null || echo "2.0.0")"
BUILD_DIR="$SCRIPT_DIR/build"
DEB_DIR="$SCRIPT_DIR/ares"

echo "========================================"
echo " Ares Engine .deb Builder"
echo " Version: $PACKAGE_VERSION"
echo "========================================"

# ---- Check dependencies ----
echo "[*] Checking build dependencies..."

for cmd in go node npm make dpkg-deb fakeroot; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "[-] Missing: $cmd"
        echo "    Install with: sudo apt install golang-go nodejs npm make dpkg-dev fakeroot"
        exit 1
    fi
done

GO_VERSION=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
NODE_VERSION=$(node -v | grep -oP 'v\K[0-9]+')
echo "[+] Go $GO_VERSION, Node $NODE_VERSION — OK"

# ---- Clean ----
echo "[*] Cleaning previous builds..."
rm -rf "$BUILD_DIR"
rm -rf "$DEB_DIR/usr"
rm -rf "$DEB_DIR/lib"
rm -rf "$DEB_DIR/etc"
mkdir -p "$DEB_DIR/usr/share/ares-engine"
mkdir -p "$DEB_DIR/usr/share/applications"
mkdir -p "$DEB_DIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$DEB_DIR/usr/bin"
mkdir -p "$DEB_DIR/lib/systemd/system"
mkdir -p "$DEB_DIR/etc/ares-engine"

# ---- Step 1: Build frontend ----
echo "[*] Building frontend..."
cd "$PROJECT_DIR/frontend"
npm ci --omit=dev 2>/dev/null || npm install
npm run build
echo "[+] Frontend built successfully"

# ---- Step 2: Copy frontend dist to embed location ----
echo "[*] Copying frontend dist for Go embed..."
mkdir -p "$PROJECT_DIR/internal/webserver/frontend/dist"
cp -r "$PROJECT_DIR/frontend/dist/"* "$PROJECT_DIR/internal/webserver/frontend/dist/"

# ---- Step 3: Build Go binary (static, stripped) ----
echo "[*] Building Go binary..."
cd "$PROJECT_DIR"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X main.version=$PACKAGE_VERSION" \
    -o "$DEB_DIR/usr/share/ares-engine/ares" ./cmd/ares
echo "[+] Go binary built"

# ---- Step 4: Create symlink in /usr/bin ----
ln -sf /usr/share/ares-engine/ares "$DEB_DIR/usr/bin/ares-engine"

# ---- Step 5: Copy launcher script ----
cp "$SCRIPT_DIR/debian/ares-engine-launcher.sh" "$DEB_DIR/usr/share/ares-engine/"
chmod +x "$DEB_DIR/usr/share/ares-engine/ares-engine-launcher.sh"

# ---- Step 6: Copy systemd service ----
cp "$SCRIPT_DIR/debian/ares-engine.service" "$DEB_DIR/lib/systemd/system/"

# ---- Step 7: Copy desktop entry ----
cp "$SCRIPT_DIR/debian/ares-engine.desktop" "$DEB_DIR/usr/share/applications/"

# ---- Step 8: Copy icon ----
if [ -f "$PROJECT_DIR/assets/logo.png" ]; then
    cp "$PROJECT_DIR/assets/logo.png" "$DEB_DIR/usr/share/icons/hicolor/256x256/apps/ares-engine.png"
    echo "[+] Icon copied"
else
    echo "[!] No logo.png found in assets/, skipping icon"
fi

# ---- Step 9: Copy default config ----
if [ -f "$PROJECT_DIR/.ares.env.example" ]; then
    cp "$PROJECT_DIR/.ares.env.example" "$DEB_DIR/etc/ares-engine/ares.env"
    echo "[+] Default config copied"
fi

# ---- Step 10: Install postinst/prerm ----
mkdir -p "$BUILD_DIR/DEBIAN"
for script in postinst prerm; do
    if [ -f "$SCRIPT_DIR/debian/$script" ]; then
        cp "$SCRIPT_DIR/debian/$script" "$BUILD_DIR/DEBIAN/$script"
        chmod +x "$BUILD_DIR/DEBIAN/$script"
    fi
done

# ---- Step 11: Generate DEBIAN/control ----
echo "[*] Generating control file..."
cat > "$BUILD_DIR/DEBIAN/control" << EOF
Package: $PACKAGE_NAME
Version: $PACKAGE_VERSION
Section: security
Priority: optional
Architecture: amd64
Maintainer: Ares Security <support@ares-security.io>
Depends: ca-certificates, xdg-utils, libc6 (>= 2.31)
Recommends: chromium | firefox | x-www-browser
Description: Ares Engine — AI-Powered Security Scanning Platform
 Ares Engine is an AI-driven penetration testing and vulnerability
 scanning platform. It combines automated reconnaissance, dynamic
 analysis, and LLM-powered agent orchestration to discover and
 validate security weaknesses in web applications and APIs.
 .
 Features:
  * AI-powered scanning with multi-phase methodology
  * 22 specialized scan phases (recon to exploit verification)
  * Automated vulnerability discovery and verification
  * Real-time WebSocket-based live feed
  * Comprehensive reporting and compliance mapping
  * Purple team simulation and validation loops
  * Web-based GUI dashboard
EOF

# ---- Step 12: Build .deb ----
echo "[*] Building .deb package..."
cp -r "$DEB_DIR"/* "$BUILD_DIR/" 2>/dev/null || true

cd "$BUILD_DIR"
find . -type f ! -path './DEBIAN/*' -exec md5sum {} \; > DEBIAN/md5sums 2>/dev/null || true

cd "$SCRIPT_DIR"
fakeroot dpkg-deb --build "$BUILD_DIR" "$SCRIPT_DIR/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64.deb"

# ---- Step 13: Cleanup ----
echo "[*] Cleaning up..."
rm -rf "$BUILD_DIR"
rm -rf "$DEB_DIR/usr"
rm -rf "$DEB_DIR/lib"
rm -rf "$DEB_DIR/etc"
rm -f "$PROJECT_DIR/internal/webserver/frontend/dist/"*

echo ""
echo "========================================"
echo " SUCCESS!"
echo " Package: $SCRIPT_DIR/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64.deb"
echo " Size: $(ls -lh "$SCRIPT_DIR/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64.deb" | awk '{print $5}')"
echo "========================================"
echo ""
echo "Install on Kali Linux:"
echo "  sudo dpkg -i ${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64.deb"
echo "  sudo apt install -f"
echo ""
echo "Run:"
echo "  ares-engine                        # Starts server + opens browser"
echo "  sudo systemctl enable --now ares-engine  # Auto-start on boot"
echo ""
echo "Open:"
echo "  http://127.0.0.1:8080"
echo "========================================"
