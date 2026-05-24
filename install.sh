#!/bin/sh
set -e

# LicScan — Install Script
# Usage: curl -fsSL https://install.codelake.dev/licscan/install.sh | sh
#
# Copyright 2026 codelake Technologies LLC, an Akyros Labs brand
# https://github.com/codelake-dev/licscan

BASE_URL="${LICSCAN_BASE_URL:-https://install.codelake.dev}"
INSTALL_DIR="${LICSCAN_INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="licscan"
VERSION="${LICSCAN_VERSION:-latest}"

main() {
    detect_platform
    download_binary
    install_binary
    verify_installation
}

detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        *)
            echo "Error: unsupported operating system: $OS"
            echo "LicScan supports Linux and macOS. For Windows, download manually from:"
            echo "  ${BASE_URL}/licscan/${VERSION}/licscan-windows-amd64.exe"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *)
            echo "Error: unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    SUFFIX="${OS}-${ARCH}"
    echo "Detected platform: ${SUFFIX}"
}

download_binary() {
    URL="${BASE_URL}/licscan/${VERSION}/${BINARY_NAME}-${SUFFIX}"
    TMPDIR="$(mktemp -d)"
    TMPFILE="${TMPDIR}/${BINARY_NAME}"

    echo "Downloading ${BINARY_NAME} ${VERSION} from ${URL}..."

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$TMPFILE" "$URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$TMPFILE" "$URL"
    else
        echo "Error: curl or wget is required"
        exit 1
    fi

    chmod +x "$TMPFILE"
}

install_binary() {
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMPFILE" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        echo "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "$TMPFILE" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    rm -rf "$TMPDIR"
}

verify_installation() {
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        echo ""
        echo "Successfully installed: $($BINARY_NAME --version)"
        echo "Run 'licscan scan .' to scan the current directory."
    else
        echo ""
        echo "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
        echo "Make sure ${INSTALL_DIR} is in your PATH."
    fi
}

main
