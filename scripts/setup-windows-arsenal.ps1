$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$sandboxRoot = Join-Path $env:USERPROFILE '.t3mp3st\sandbox'
$imagePath = Join-Path $sandboxRoot 'kali-linux-2026.2-wsl-rootfs-amd64.wsl'
$readyPath = Join-Path $sandboxRoot 'ready'
if (Test-Path $readyPath) { return }
if (-not (Test-Path $imagePath)) { throw 'Verified Kali rootfs missing. Stage the image before running setup.' }
$checksumPath = Join-Path $sandboxRoot 'SHA256SUMS'
$expected = ((Get-Content $checksumPath | Where-Object { $_ -match [regex]::Escape((Split-Path $imagePath -Leaf)) }) -split '\s+')[0]
if ((Get-FileHash -LiteralPath $imagePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected.ToLowerInvariant()) {
    throw 'Kali rootfs checksum mismatch.'
}
function ConvertTo-LinuxPath([string] $path) {
    $absolute = [IO.Path]::GetFullPath($path)
    if ($absolute -notmatch '^([A-Za-z]):\\') { throw 'A local drive path is required.' }
    return '/mnt/' + $Matches[1].ToLowerInvariant() + '/' + $absolute.Substring(3).Replace('\', '/')
}
function Invoke-TempestWsl([string[]] $arguments) {
    & wsl.exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "Tempest Linux setup failed (exit $LASTEXITCODE). See the WSL/network/package error above. The environment is not marked ready." }
}
$distributions = (& wsl.exe --list --quiet) -replace "`0", '' | ForEach-Object { $_.Trim() }
if ($distributions -notcontains 'Tempest-Arsenal') {
    Invoke-TempestWsl -arguments @('--import', 'Tempest-Arsenal', (Join-Path $sandboxRoot 'linux'), $imagePath, '--version', '2')
}
$archive = Join-Path $sandboxRoot 'project.tar'
& git.exe -C $repo archive --format=tar --output=$archive HEAD
if ($LASTEXITCODE -ne 0) { throw 'Unable to archive the committed Tempest project.' }
Invoke-TempestWsl -arguments @('-d', 'Tempest-Arsenal', '--user', 'root', '--exec', 'bash',
    (ConvertTo-LinuxPath (Join-Path $PSScriptRoot 'initialize-tempest-linux.sh')),
    (ConvertTo-LinuxPath $archive), (ConvertTo-LinuxPath (Join-Path $env:USERPROFILE '.t3mp3st')),
    (ConvertTo-LinuxPath (Join-Path $env:USERPROFILE '.codex')))
Invoke-TempestWsl -arguments @('-d', 'Tempest-Arsenal', '--user', 'tempest', '--exec', 'bash', '/home/tempest/app/scripts/install-linux-arsenal.sh')
Invoke-TempestWsl -arguments @('-d', 'Tempest-Arsenal', '--user', 'root', '--exec', 'rm', '-f', '/etc/sudoers.d/tempest')
Invoke-TempestWsl -arguments @('-d', 'Tempest-Arsenal', '--user', 'tempest', '--exec', '/home/tempest/.local/bin/codex', 'login', 'status')
Invoke-TempestWsl -arguments @('-d', 'Tempest-Arsenal', '--user', 'tempest', '--exec', 'test', '-f', '/home/tempest/.tempest-arsenal-ready')
[IO.File]::WriteAllText($readyPath, (Get-Date -Format o))
Write-Host 'Tempest website/API arsenal installed and checked.'
