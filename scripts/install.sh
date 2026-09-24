#!/usr/bin/env bash
# Install bugtools globally on Linux/macOS.
#
# Downloads the latest release binary for your platform from GitHub and installs
# it to a directory on your PATH. Usage:
#
#   curl -fsSL https://raw.githubusercontent.com/1phirum/bounty-tools/master/scripts/install.sh | bash
#
# Override the install directory with BUGTOOLS_BIN_DIR (default: ~/.local/bin).
set -euo pipefail

REPO="1phirum/bounty-tools"
BIN_DIR="${BUGTOOLS_BIN_DIR:-$HOME/.local/bin}"

os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)  target_os="unknown-linux-gnu" ;;
  Darwin) target_os="apple-darwin" ;;
  *) echo "unsupported OS: $os (use the Windows installer or build from source)" >&2; exit 1 ;;
esac
case "$arch" in
  x86_64|amd64) target_arch="x86_64" ;;
  arm64|aarch64) target_arch="aarch64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
target="${target_arch}-${target_os}"

# Resolve the latest release tag via the GitHub API.
tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
if [ -z "${tag:-}" ]; then
  echo "could not determine the latest release tag for ${REPO}" >&2
  exit 1
fi

asset="bugtools-${tag}-${target}.tar.gz"
url="https://github.com/${REPO}/releases/download/${tag}/${asset}"
echo "[*] downloading ${asset}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/bugtools.tar.gz"
tar -xzf "$tmp/bugtools.tar.gz" -C "$tmp"

mkdir -p "$BIN_DIR"
install -m 0755 "$tmp/bugtools" "$BIN_DIR/bugtools"
echo "[+] installed bugtools ${tag} to ${BIN_DIR}/bugtools"

case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) echo "[!] ${BIN_DIR} is not on your PATH. Add this to your shell profile:"
     echo "      export PATH=\"${BIN_DIR}:\$PATH\"" ;;
esac
echo "[*] run: bugtools --help"
