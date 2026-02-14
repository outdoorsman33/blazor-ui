$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$pidFile = Join-Path $projectRoot ".demo-pids.json"
$stoppedPids = @()

if (Test-Path $pidFile) {
    try {
        $pidInfo = Get-Content -Raw $pidFile | ConvertFrom-Json
        foreach ($name in @("ApiPid", "WebPid", "TunnelPid")) {
            $pidValue = [int]($pidInfo.$name)
            if ($pidValue -gt 0) {
                Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue
                $stoppedPids += $pidValue
            }
        }
    }
    catch {
        # Fall through to process scan.
    }

    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
}

$candidateProcesses = Get-CimInstance Win32_Process |
    Where-Object { $_.CommandLine -and $_.Name -in @("dotnet.exe", "cloudflared.exe", "ssh.exe") }

$matches = foreach ($process in $candidateProcesses) {
    $commandLine = $process.CommandLine.ToLowerInvariant()

    $isApi = $commandLine.Contains("src\wrestlingplatform.api")
    $isWeb = $commandLine.Contains("src\wrestlingplatform.web")
    $isCloudflaredTunnel = $process.Name -ieq "cloudflared.exe" -and $commandLine.Contains(" tunnel ") -and $commandLine.Contains("--url")
    $isLocalhostRunTunnel = $process.Name -ieq "ssh.exe" -and $commandLine.Contains("localhost.run")

    if ($isApi -or $isWeb -or $isCloudflaredTunnel -or $isLocalhostRunTunnel) {
        $process
    }
}

foreach ($process in $matches) {
    Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    if ($stoppedPids -notcontains $process.ProcessId) {
        $stoppedPids += $process.ProcessId
    }
}

Write-Host "Stopped $($stoppedPids.Count) demo process(es)."
