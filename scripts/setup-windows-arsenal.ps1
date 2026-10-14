$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$sandboxRoot = Join-Path $env:USERPROFILE '.vulnora\sandbox'
$runtimePath = Join-Path $sandboxRoot 'runtime.json'
$null = New-Item -ItemType Directory -Path $sandboxRoot -Force
function ConvertTo-LinuxPath([string] $path) {
    $absolute = [IO.Path]::GetFullPath($path)
    if ($absolute -notmatch '^([A-Za-z]):\\') { throw 'A local drive path is required.' }
    return '/mnt/' + $Matches[1].ToLowerInvariant() + '/' + $absolute.Substring(3).Replace('\', '/')
}
function Invoke-VulnoraWsl([string[]] $arguments) {
    & wsl.exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "Vulnora Linux setup failed (exit $LASTEXITCODE). See the WSL/network/package error above. The environment is not marked ready." }
}
$distributions = (& wsl.exe --list --quiet) -replace "`0", '' | ForEach-Object { $_.Trim() }
$distro = if ($distributions -contains 'Vulnora-Arsenal') { 'Vulnora-Arsenal' }
    elseif ($distributions -contains 'Tempest-Arsenal') { 'Tempest-Arsenal' } else { 'Vulnora-Arsenal' }
$linuxUser = if ($distro -eq 'Tempest-Arsenal') { 'tempest' } else { 'vulnora' }
$revision = (& git.exe -C $repo rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[a-f0-9]{40}$') { throw 'Unable to resolve the committed Vulnora revision.' }
$appDirectory = "/home/$linuxUser/.vulnora/releases/$revision"
if (Test-Path -LiteralPath $runtimePath) {
    $runtime = Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json
    if ($runtime.revision -eq $revision -and $runtime.distro -eq $distro -and $runtime.user -eq $linuxUser -and $runtime.appDirectory -eq $appDirectory) {
        & wsl.exe -d $distro --user $linuxUser --exec test -f "$appDirectory/dist/cli.js"
        if ($LASTEXITCODE -eq 0) { return }
    }
}
if ($distributions -notcontains $distro) {
    $imagePath = Join-Path $sandboxRoot 'kali-linux-2026.2-wsl-rootfs-amd64.wsl'
    if (-not (Test-Path -LiteralPath $imagePath)) { throw 'Verified Kali rootfs missing. Stage the image before running setup.' }
    $checksumPath = Join-Path $sandboxRoot 'SHA256SUMS'
    $expected = ((Get-Content -LiteralPath $checksumPath | Where-Object { $_ -match [regex]::Escape((Split-Path $imagePath -Leaf)) }) -split '\s+')[0]
    if ((Get-FileHash -LiteralPath $imagePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected.ToLowerInvariant()) { throw 'Kali rootfs checksum mismatch.' }
    Invoke-VulnoraWsl -arguments @('--import', 'Vulnora-Arsenal', (Join-Path $sandboxRoot 'linux'), $imagePath, '--version', '2')
}
$archive = Join-Path $sandboxRoot "project-$revision.tar"
& git.exe -C $repo archive --format=tar --output=$archive HEAD
if ($LASTEXITCODE -ne 0) { throw 'Unable to archive the committed Vulnora project.' }
& wsl.exe -d $distro --user $linuxUser --exec true
if ($LASTEXITCODE -ne 0) {
    Invoke-VulnoraWsl -arguments @('-d', $distro, '--user', 'root', '--exec', 'bash',
        (ConvertTo-LinuxPath (Join-Path $PSScriptRoot 'initialize-vulnora-linux.sh')),
        (ConvertTo-LinuxPath $archive), (ConvertTo-LinuxPath (Join-Path $env:USERPROFILE '.vulnora')))
    Invoke-VulnoraWsl -arguments @('-d', $distro, '--user', $linuxUser, '--exec', 'bash', "/home/$linuxUser/app/scripts/install-linux-arsenal.sh")
    Invoke-VulnoraWsl -arguments @('-d', $distro, '--user', 'root', '--exec', 'rm', '-f', '/etc/sudoers.d/vulnora')
}
Invoke-VulnoraWsl -arguments @('-d', $distro, '--user', $linuxUser, '--exec', 'bash',
    (ConvertTo-LinuxPath (Join-Path $PSScriptRoot 'deploy-vulnora-linux.sh')), (ConvertTo-LinuxPath $archive),
    $revision, (ConvertTo-LinuxPath (Join-Path $env:USERPROFILE '.vulnora')))
$runtime = @{ distro = $distro; user = $linuxUser; appDirectory = $appDirectory; revision = $revision }
if (Test-Path -LiteralPath $runtimePath) {
    $backupDirectory = Join-Path $env:USERPROFILE '.vulnora\backups'
    $null = New-Item -ItemType Directory -Path $backupDirectory -Force
    Copy-Item -LiteralPath $runtimePath -Destination (Join-Path $backupDirectory ('runtime-' + (Get-Date -Format 'yyyyMMdd-HHmmss-ffff') + '.json'))
}
$temporary = "$runtimePath.tmp"
[IO.File]::WriteAllText($temporary, ($runtime | ConvertTo-Json))
Move-Item -LiteralPath $temporary -Destination $runtimePath -Force
Write-Host 'Vulnora website/API release installed and checked.'
