param()

$dirs = @(
    'workspace\projects',
    'workspace\exports',
    'workspace\logs',
    'workspace\cache',
    'modules\subdomain',
    'modules\dns',
    'modules\http-probe',
    'modules\crawler',
    'modules\javascript',
    'modules\parameters',
    'modules\technology',
    'modules\sql-injection',
    'engines\dns-go',
    'engines\crawler-go',
    'engines\http-go'
)

foreach ($d in $dirs) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    New-Item -ItemType File -Force -Path (Join-Path $d '.gitkeep') | Out-Null
}
Write-Host "Architecture directories created successfully"
