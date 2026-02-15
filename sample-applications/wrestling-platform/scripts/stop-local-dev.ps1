$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$pidFile = Join-Path $projectRoot ".local-dev-pids.json"
$stoppedPids = @()

if (Test-Path $pidFile) {
    try {
        $pidInfo = Get-Content -Raw $pidFile | ConvertFrom-Json
        foreach ($name in @("ApiPid", "WebPid")) {
            $pidValue = [int]($pidInfo.$name)
            if ($pidValue -gt 0) {
                Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue
                $stoppedPids += $pidValue
            }
        }
    }
    catch {
        # Continue with process scan.
    }

    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
}

$candidateProcesses = Get-CimInstance Win32_Process |
    Where-Object {
        $_.CommandLine -and (
            $_.Name -ieq "dotnet.exe" -or
            $_.Name -ieq "WrestlingPlatform.Api.exe" -or
            $_.Name -ieq "WrestlingPlatform.Web.exe")
    }

foreach ($process in $candidateProcesses) {
    if ($process.Name -ieq "WrestlingPlatform.Api.exe" -or $process.Name -ieq "WrestlingPlatform.Web.exe") {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        if ($stoppedPids -notcontains $process.ProcessId) {
            $stoppedPids += $process.ProcessId
        }

        continue
    }

    $commandLine = $process.CommandLine.ToLowerInvariant()
    if ($commandLine.Contains("src\\wrestlingplatform.api") -or $commandLine.Contains("src\\wrestlingplatform.web")) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        if ($stoppedPids -notcontains $process.ProcessId) {
            $stoppedPids += $process.ProcessId
        }
    }
}

Get-Process testhost -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process vstest.console -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "Stopped $($stoppedPids.Count) local process(es)."
