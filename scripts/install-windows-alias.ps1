$ErrorActionPreference = 'Stop'
$root = Join-Path $env:USERPROFILE '.vulnora'
$runtimePath = Join-Path $root 'sandbox\runtime.json'
if (-not (Test-Path -LiteralPath $runtimePath)) { throw 'Install and validate the Vulnora runtime before replacing aliases.' }
$launcher = Join-Path $PSScriptRoot 'start-windows-vulnora.ps1'
$backup = Join-Path $root ('backups\aliases-' + (Get-Date -Format 'yyyyMMdd-HHmmss-ffff'))
$null = New-Item -ItemType Directory -Path $backup -Force
$wrapper = Join-Path $root 'start-vulnora.ps1'
if (Test-Path -LiteralPath $wrapper) { Copy-Item -LiteralPath $wrapper -Destination (Join-Path $backup 'start-vulnora.ps1') }
[IO.File]::WriteAllText($wrapper, "& '" + $launcher.Replace("'", "''") + "' @args`r`n", [Text.UTF8Encoding]::new($true))
$documents = [Environment]::GetFolderPath('MyDocuments')
foreach ($shell in @('PowerShell', 'WindowsPowerShell')) {
    $profilePath = Join-Path $documents "$shell\Microsoft.PowerShell_profile.ps1"
    $content = if (Test-Path -LiteralPath $profilePath) { [IO.File]::ReadAllText($profilePath) } else { '' }
    if (Test-Path -LiteralPath $profilePath) { Copy-Item -LiteralPath $profilePath -Destination (Join-Path $backup "$shell-profile.ps1") }
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($content, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Profile has syntax errors; preserved without changes: $profilePath" }
    $functions = @($ast.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -in 'tempest', 'vulnora'
    } | Sort-Object { $_.Extent.StartOffset } -Descending)
    foreach ($function in $functions) {
        $content = $content.Remove($function.Extent.StartOffset, $function.Extent.EndOffset - $function.Extent.StartOffset)
    }
    $content += "`r`nfunction vulnora {`r`n    & '" + $wrapper.Replace("'", "''") + "' @args`r`n}`r`n"
    $null = New-Item -ItemType Directory -Path (Split-Path $profilePath -Parent) -Force
    [IO.File]::WriteAllText($profilePath, $content, [Text.UTF8Encoding]::new($true))
}
$commandPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\vulnora.cmd'
if (Test-Path -LiteralPath $commandPath) { Copy-Item -LiteralPath $commandPath -Destination (Join-Path $backup 'vulnora.cmd') }
[IO.File]::WriteAllText($commandPath, "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"%USERPROFILE%\.vulnora\start-vulnora.ps1`" %*`r`n")
$legacyCommand = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\tempest.cmd'
if (Test-Path -LiteralPath $legacyCommand) {
    Copy-Item -LiteralPath $legacyCommand -Destination (Join-Path $backup 'tempest.cmd')
    Remove-Item -LiteralPath $legacyCommand
}
Write-Host "Vulnora command installed. Profile backups: $backup"
