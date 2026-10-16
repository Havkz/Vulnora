$ErrorActionPreference = 'Stop'
$runtimePath = Join-Path $env:USERPROFILE '.vulnora\sandbox\runtime.json'
if (-not (Test-Path -LiteralPath $runtimePath)) { & (Join-Path $PSScriptRoot 'setup-windows-arsenal.ps1') }
$runtime = Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json
$ollamaProcess = $null
$needsModel = ($args.Count -eq 0 -or $args[0] -in 'interactive', 'test', 'models', '--verify-providers')
$providerEnvironment = @()
# WSL has a separate login store. Invoke the user's authenticated Windows executable instead.
$codex = Get-Command codex.exe, codex.cmd -ErrorAction SilentlyContinue | Select-Object -First 1
if ($codex) {
    $codexPath = $codex.Source
    if ($codexPath -like '*.cmd') {
        $package = Join-Path (Split-Path $codexPath -Parent) 'node_modules\@openai\codex'
        $codexPath = if (Test-Path -LiteralPath $package) {
            Get-ChildItem -LiteralPath $package -Filter codex.exe -Recurse | Select-Object -First 1 -ExpandProperty FullName
        } else { $null }
    }
    if ($codexPath -and $codexPath -match '^([A-Za-z]):\\') {
        $hostCommand = '/mnt/' + $Matches[1].ToLowerInvariant() + '/' + $codexPath.Substring(3).Replace('\', '/')
        $providerEnvironment += "VULNORA_CODEX_HOST_COMMAND=$hostCommand"
        $codexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE '.codex' }
        $publicConfig = Join-Path $codexHome 'config.toml'
        if (Test-Path -LiteralPath $publicConfig) {
            foreach ($line in [IO.File]::ReadLines($publicConfig)) {
                if ($line -match '^\s*\[') { break }
                if ($line -match '^\s*model\s*=\s*["'']([^"'']+)["'']\s*(?:#.*)?$') {
                    $providerEnvironment += "VULNORA_CODEX_MODEL=$($Matches[1])"
                    break
                }
            }
        }
    }
}
try {
    if ($needsModel) {
        try { $null = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2 }
        catch {
            $ollamaExe = Get-Command ollama.exe -ErrorAction SilentlyContinue
            if ($ollamaExe) {
                $previousHost = $env:OLLAMA_HOST
                try {
                    $env:OLLAMA_HOST = '127.0.0.1:11434'
                    $ollamaProcess = Start-Process $ollamaExe.Source -ArgumentList 'serve' -WindowStyle Hidden -PassThru
                } finally { $env:OLLAMA_HOST = $previousHost }
                $ready = $false
                for ($attempt = 0; $attempt -lt 20; $attempt++) {
                    Start-Sleep -Milliseconds 500
                    try {
                        $null = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2
                        $ready = $true
                        break
                    } catch { }
                }
                if (-not $ready) { Write-Warning 'Ollama unavailable. Vulnora will report provider readiness and supported fallback.' }
            } else { Write-Warning 'Ollama is not installed. Vulnora will report provider readiness and supported fallback.' }
        }
    }
    & wsl.exe -d $runtime.distro --user $runtime.user --exec env @providerEnvironment bash "$($runtime.appDirectory)/scripts/start-linux-vulnora.sh" @args
    if ($LASTEXITCODE -notin 0, 130) { throw "Vulnora exited with code $LASTEXITCODE." }
} finally {
    if ($ollamaProcess -and -not $ollamaProcess.HasExited) { Stop-Process -Id $ollamaProcess.Id }
}
