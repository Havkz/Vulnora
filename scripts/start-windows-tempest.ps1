$ErrorActionPreference = 'Stop'
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
& (Join-Path $PSScriptRoot 'setup-windows-arsenal.ps1')
$ollamaProcess = $null
$model = 'huihui_ai/qwen3-coder-abliterated:30b'
$needsModel = ($args.Count -eq 0 -or $args[0] -in 'interactive', 'test')
$providerCheck = Join-Path $env:USERPROFILE '.t3mp3st\sandbox\providers-verified'
try {
    if ($needsModel) {
        try { $null = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2 }
        catch {
            $ollamaExe = (Get-Command ollama.exe -ErrorAction Stop).Source
            $env:OLLAMA_HOST = '127.0.0.1:11434'
            $ollamaProcess = Start-Process $ollamaExe -ArgumentList 'serve' -WindowStyle Hidden -PassThru
            $ready = $false
            for ($attempt = 0; $attempt -lt 20; $attempt++) {
                Start-Sleep -Milliseconds 500
                try {
                    $null = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2
                    $ready = $true
                    break
                } catch { }
            }
            if (-not $ready) { throw 'Ollama konnte nicht gestartet werden.' }
        }
    }
    if ($needsModel -and -not (Test-Path $providerCheck)) {
        & wsl.exe -d Tempest-Arsenal --user tempest --exec bash /home/tempest/app/scripts/start-linux-tempest.sh --verify-providers
        if ($LASTEXITCODE -ne 0) { throw 'Codex/Ollama-Verbindungstest fehlgeschlagen. Linux-CLI wurde nicht gestartet.' }
        [IO.File]::WriteAllText($providerCheck, (Get-Date -Format o))
    }
    & wsl.exe -d Tempest-Arsenal --user tempest --exec bash /home/tempest/app/scripts/start-linux-tempest.sh @args
    if ($LASTEXITCODE -ne 0) { throw "Tempest wurde mit Fehlercode $LASTEXITCODE beendet." }
} finally {
    if ($needsModel) {
        try {
            $body = @{ model = $model; stream = $false; keep_alive = 0 } | ConvertTo-Json -Compress
            $null = Invoke-RestMethod 'http://127.0.0.1:11434/api/generate' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 30
        } catch { Write-Warning 'Ollama-Modell konnte nicht entladen werden.' }
    }
    if ($ollamaProcess -and -not $ollamaProcess.HasExited) { Stop-Process -Id $ollamaProcess.Id }
}
