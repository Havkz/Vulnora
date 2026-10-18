$ErrorActionPreference = 'Stop'
$runtimePath = Join-Path $env:USERPROFILE '.vulnora\sandbox\runtime.json'
if (-not (Test-Path -LiteralPath $runtimePath)) { & (Join-Path $PSScriptRoot 'setup-windows-arsenal.ps1') }
$runtime = Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json
$providerEnvironment = @()
$hostPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if ($hostPowerShell -match '^([A-Za-z]):\\') {
    $providerEnvironment += 'VULNORA_OLLAMA_HOST_POWERSHELL=/mnt/' + $Matches[1].ToLowerInvariant() + '/' + $hostPowerShell.Substring(3).Replace('\', '/')
    $providerEnvironment += 'VULNORA_OLLAMA_HOST_HELPER=' + (Join-Path $PSScriptRoot 'serve-windows-ollama.ps1')
}
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
        $modelCache = Join-Path $codexHome 'models_cache.json'
        if ((Test-Path -LiteralPath $modelCache) -and $modelCache -match '^([A-Za-z]):\\') {
            $providerEnvironment += 'VULNORA_CODEX_MODELS_CACHE=/mnt/' + $Matches[1].ToLowerInvariant() + '/' + $modelCache.Substring(3).Replace('\', '/')
        }
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
& wsl.exe -d $runtime.distro --user $runtime.user --exec env @providerEnvironment bash "$($runtime.appDirectory)/scripts/start-linux-vulnora.sh" @args
if ($LASTEXITCODE -notin 0, 130) { throw "Vulnora exited with code $LASTEXITCODE." }
