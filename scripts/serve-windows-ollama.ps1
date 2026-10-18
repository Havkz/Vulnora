$ErrorActionPreference = 'Stop'
$owned = $null
try {
    try {
        $null = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 1
        return
    } catch { }
    $ollama = Get-Command ollama.exe -ErrorAction Stop
    $previousHost = $env:OLLAMA_HOST
    try {
        $env:OLLAMA_HOST = '127.0.0.1:11434'
        $owned = Start-Process -FilePath $ollama.Source -ArgumentList 'serve' -WindowStyle Hidden -PassThru
    } finally { $env:OLLAMA_HOST = $previousHost }
    # Keep ownership until Vulnora closes this pipe; model loading is separate.
    $null = [Console]::In.ReadLine()
} finally {
    if ($owned -and -not $owned.HasExited) { Stop-Process -Id $owned.Id }
}
