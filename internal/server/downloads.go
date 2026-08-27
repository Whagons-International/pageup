package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var allowedDownloads = map[string]bool{
	"pageup-linux-amd64":       true,
	"pageup-linux-arm64":       true,
	"pageup-darwin-amd64":      true,
	"pageup-darwin-arm64":      true,
	"pageup-windows-amd64.exe": true,
	"pageup-windows-arm64.exe": true,
}

func (server *Server) handleDownload(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	name := strings.TrimPrefix(request.URL.Path, "/downloads/")
	if !allowedDownloads[name] || server.config.DownloadsDir == "" {
		http.NotFound(writer, request)
		return
	}
	path := filepath.Join(server.config.DownloadsDir, name)
	if _, err := os.Stat(path); err != nil {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, name))
	writer.Header().Set("Cache-Control", "public, max-age=3600")
	http.ServeFile(writer, request, path)
}

func (server *Server) handleInstallShell(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	baseURL := server.publicURL(request)
	script := `#!/bin/sh
set -eu

base_url='` + shellSingleQuote(baseURL) + `'
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)

case "$os" in
  linux|darwin) ;;
  *) echo "pageup: unsupported operating system: $os" >&2; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "pageup: unsupported architecture: $arch" >&2; exit 1 ;;
esac

if [ -w /usr/local/bin ]; then
  destination=/usr/local/bin/pageup
else
  destination="$HOME/.local/bin/pageup"
  mkdir -p "$HOME/.local/bin"
fi

temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT INT TERM
curl -fsSL "$base_url/downloads/pageup-$os-$arch" -o "$temporary"
chmod 0755 "$temporary"
mv "$temporary" "$destination"
trap - EXIT INT TERM

echo "Installed pageup to $destination"
case ":$PATH:" in
  *":$(dirname "$destination"):"*) ;;
  *) echo "Add $(dirname "$destination") to PATH." ;;
esac
echo "Run: pageup auth login --endpoint $base_url --name \"this computer\""
`
	writer.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Write([]byte(script))
}

func shellSingleQuote(value string) string {
	return strings.ReplaceAll(value, "'", `'"'"'`)
}

func (server *Server) handleInstallPowerShell(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	baseURL := strings.ReplaceAll(server.publicURL(request), "'", "''")
	script := `$ErrorActionPreference = 'Stop'
$BaseUrl = '` + baseURL + `'
$Arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'amd64' }
$InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\pageup'
$Destination = Join-Path $InstallDir 'pageup.exe'
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Invoke-WebRequest -UseBasicParsing "$BaseUrl/downloads/pageup-windows-$Arch.exe" -OutFile $Destination
$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($UserPath -split ';') -notcontains $InstallDir) {
  [Environment]::SetEnvironmentVariable('Path', ($UserPath.TrimEnd(';') + ';' + $InstallDir), 'User')
}
Write-Host "Installed pageup to $Destination"
Write-Host "Open a new terminal, then run: pageup auth login --endpoint $BaseUrl --name 'this computer'"
`
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Write([]byte(script))
}
