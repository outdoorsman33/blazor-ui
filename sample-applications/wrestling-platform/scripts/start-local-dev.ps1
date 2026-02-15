param(
    [string]$ApiUrl = "http://127.0.0.1:5099",
    [string]$WebUrl = "http://127.0.0.1:5105",
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$pidFile = Join-Path $projectRoot ".local-dev-pids.json"

function Get-LocalProcesses {
    $candidateProcesses = Get-CimInstance Win32_Process |
        Where-Object {
            $_.CommandLine -and (
                $_.Name -ieq "dotnet.exe" -or
                $_.Name -ieq "WrestlingPlatform.Api.exe" -or
                $_.Name -ieq "WrestlingPlatform.Web.exe")
        }

    $matches = foreach ($process in $candidateProcesses) {
        if ($process.Name -ieq "WrestlingPlatform.Api.exe" -or $process.Name -ieq "WrestlingPlatform.Web.exe") {
            $process
            continue
        }

        $commandLine = $process.CommandLine.ToLowerInvariant()
        if ($commandLine.Contains("src\\wrestlingplatform.api") -or $commandLine.Contains("src\\wrestlingplatform.web")) {
            $process
        }
    }

    return $matches
}

function Stop-ExistingLocalProcesses {
    if (Test-Path $pidFile) {
        try {
            $pidInfo = Get-Content -Raw $pidFile | ConvertFrom-Json
            foreach ($name in @("ApiPid", "WebPid")) {
                $pidValue = [int]($pidInfo.$name)
                if ($pidValue -gt 0) {
                    Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            # Ignore malformed pid file and continue with process scan.
        }

        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }

    foreach ($process in (Get-LocalProcesses)) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }

    Get-Process testhost -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process vstest.console -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Wait-ForListeningPort {
    param(
        [int]$Port,
        [int]$TimeoutSeconds = 45
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $listening = netstat -ano | Select-String ":$Port\s+.*LISTENING"
        if ($listening) {
            return
        }

        Start-Sleep -Milliseconds 500
    }

    throw "Timed out waiting for port $Port to enter LISTENING state."
}

function Wait-ForHealth {
    param(
        [string]$Url,
        [int]$TimeoutSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10
            if ($response.StatusCode -eq 200) {
                return
            }
        }
        catch {
            # Keep waiting while service starts up.
        }

        Start-Sleep -Seconds 1
    }

    throw "Timed out waiting for health check endpoint: $Url"
}

Stop-ExistingLocalProcesses

$apiLog = Join-Path $projectRoot "api-local.log"
$apiErrLog = Join-Path $projectRoot "api-local.err.log"
$webLog = Join-Path $projectRoot "web-local.log"
$webErrLog = Join-Path $projectRoot "web-local.err.log"

Remove-Item $apiLog,$apiErrLog,$webLog,$webErrLog -Force -ErrorAction SilentlyContinue

if (-not $NoBuild) {
    dotnet build "$projectRoot\\WrestlingPlatform.slnx" | Out-Host
}

$apiArguments = @("run", "--project", "src/WrestlingPlatform.Api", "--urls", $ApiUrl, "--no-build")
$webArguments = @("run", "--project", "src/WrestlingPlatform.Web", "--urls", $WebUrl, "--no-build")

$apiProcess = Start-Process dotnet -ArgumentList $apiArguments -WorkingDirectory $projectRoot -RedirectStandardOutput $apiLog -RedirectStandardError $apiErrLog -WindowStyle Hidden -PassThru
$webProcess = Start-Process dotnet -ArgumentList $webArguments -WorkingDirectory $projectRoot -RedirectStandardOutput $webLog -RedirectStandardError $webErrLog -WindowStyle Hidden -PassThru

$apiPort = [int]([uri]$ApiUrl).Port
$webPort = [int]([uri]$WebUrl).Port

Wait-ForListeningPort -Port $apiPort
Wait-ForListeningPort -Port $webPort
Wait-ForHealth -Url "$ApiUrl/healthz"
Wait-ForHealth -Url "$WebUrl/healthz"

@{
    ApiPid = $apiProcess.Id
    WebPid = $webProcess.Id
    CreatedUtc = [DateTime]::UtcNow.ToString("o")
} | ConvertTo-Json | Set-Content $pidFile

Write-Host "Local API URL: $ApiUrl"
Write-Host "Local Web URL: $WebUrl"
Write-Host "Logs:"
Write-Host "  $apiLog"
Write-Host "  $apiErrLog"
Write-Host "  $webLog"
Write-Host "  $webErrLog"
Write-Host "PID file: $pidFile"
