<#
.SYNOPSIS
  Generate a self-signed TLS certificate + key for a radminpro LAN host and
  print the SHA-256 fingerprint used by the client for certificate pinning.

.DESCRIPTION
  Produces an ECDSA P-256 certificate (works with the server's ECDHE-ECDSA
  cipher suites). For a managed-PKI deployment, issue the cert from your CA
  instead and distribute the CA bundle to clients (radmin_client --ca).

.EXAMPLE
  .\gen-cert.ps1 -Cn radmin-host01 -HostIp 192.168.1.50
#>
param(
  [string]$Cn = "radminpro-host",
  [string]$HostIp = "127.0.0.1",
  [int]$Days = 825,
  [string]$OutDir = "."
)

$ErrorActionPreference = "Stop"

$openssl = (Get-Command openssl -ErrorAction SilentlyContinue)
if (-not $openssl) {
  Write-Error "openssl not found in PATH. Install OpenSSL (vcpkg installs one under installed\x64-windows\tools\openssl) or add Git's usr\bin to PATH."
  exit 1
}

$key = Join-Path $OutDir "server.key"
$crt = Join-Path $OutDir "server.crt"

Write-Host "Generating ECDSA P-256 self-signed certificate..."
& openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes `
  -keyout $key -out $crt -days $Days -subj "/CN=$Cn" `
  -addext "subjectAltName=DNS:$Cn,IP:$HostIp"

if ($LASTEXITCODE -ne 0) { Write-Error "openssl failed"; exit 1 }

# Restrict the private key so only the current user / admins can read it.
icacls $key /inheritance:r /grant:r "$($env:USERNAME):(R)" "Administrators:(R)" "SYSTEM:(R)" | Out-Null

$fp = (& openssl x509 -in $crt -noout -fingerprint -sha256)
Write-Host ""
Write-Host "Certificate : $crt"
Write-Host "Private key : $key   (permissions restricted)"
Write-Host $fp
Write-Host ""
Write-Host "Pin this on the client (colons are optional):"
$hex = ($fp -split "=")[1]
Write-Host "  radmin_client view <host> --user <u> --pin $hex"
