# Install bugtools globally on Windows (PowerShell).
#
# Downloads the latest release .exe from GitHub and installs it to
# %LOCALAPPDATA%\Programs\bugtools, adding that folder to your user PATH.
#
#   Run in PowerShell:
#     irm https://raw.githubusercontent.com/1phirum/bounty-tools/master/scripts/install.ps1 | iex
#
# Override the install directory with $env:BUGTOOLS_BIN_DIR.
$ErrorActionPreference = 'Stop'

$repo   = '1phirum/bounty-tools'
$target = 'x86_64-pc-windows-msvc'
$binDir = if ($env:BUGTOOLS_BIN_DIR) { $env:BUGTOOLS_BIN_DIR } else { "$env:LOCALAPPDATA\Programs\bugtools" }

# Resolve the latest release tag.
$release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'bugtools-install' }
$tag = $release.tag_name
if (-not $tag) { throw "could not determine the latest release tag for $repo" }

$asset = "bugtools-$tag-$target.zip"
$url   = "https://github.com/$repo/releases/download/$tag/$asset"
Write-Host "[*] downloading $asset"

$tmp = Join-Path $env:TEMP ("bugtools-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  $zip = Join-Path $tmp 'bugtools.zip'
  Invoke-WebRequest -Uri $url -OutFile $zip -Headers @{ 'User-Agent' = 'bugtools-install' }
  Expand-Archive -Path $zip -DestinationPath $tmp -Force

  New-Item -ItemType Directory -Force -Path $binDir | Out-Null
  Copy-Item -Force (Join-Path $tmp 'bugtools.exe') (Join-Path $binDir 'bugtools.exe')
  Write-Host "[+] installed bugtools $tag to $binDir\bugtools.exe"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# Add the install dir to the user PATH if it isn't already there.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $binDir) {
  [Environment]::SetEnvironmentVariable('Path', "$userPath;$binDir", 'User')
  Write-Host "[+] added $binDir to your user PATH (open a new terminal to pick it up)"
}
Write-Host "[*] run: bugtools --help"
