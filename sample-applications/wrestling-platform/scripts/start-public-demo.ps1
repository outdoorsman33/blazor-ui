param(
    [string]$ApiUrl = "http://127.0.0.1:5099",
    [string]$WebUrl = "http://127.0.0.1:5105"
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$pidFile = Join-Path $projectRoot ".demo-pids.json"

function Get-DemoProcesses {
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

    return $matches
}

function Stop-ExistingDemoProcesses {
    if (Test-Path $pidFile) {
        try {
            $pidInfo = Get-Content -Raw $pidFile | ConvertFrom-Json
            foreach ($name in @("ApiPid", "WebPid", "TunnelPid")) {
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

    $processes = Get-DemoProcesses
    foreach ($process in $processes) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }
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

function Wait-ForCloudflareUrl {
    param(
        [string[]]$LogPaths,
        [int]$TunnelPid,
        [int]$TimeoutSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        $tunnelProcess = Get-Process -Id $TunnelPid -ErrorAction SilentlyContinue
        if (-not $tunnelProcess) {
            $tailBlocks = foreach ($path in $LogPaths) {
                if (Test-Path $path) {
                    "[$path]`n" + ((Get-Content -Tail 25 $path) -join [Environment]::NewLine)
                }
            }

            $tailText = if ($tailBlocks.Count -gt 0) { $tailBlocks -join [Environment]::NewLine + [Environment]::NewLine + "---" + [Environment]::NewLine } else { "<no tunnel logs found>" }
            throw "Tunnel process exited early. Last tunnel log lines:`n$tailText"
        }

        foreach ($path in $LogPaths) {
            if (-not (Test-Path $path)) {
                continue
            }

            $match = Select-String -Path $path -Pattern "https://[-a-z0-9]+\.trycloudflare\.com" | Select-Object -First 1
            if ($match) {
                return $match.Matches[0].Value
            }
        }

        Start-Sleep -Milliseconds 500
    }

    throw "Timed out waiting for quick tunnel URL. Check tunnel logs for errors."
}

Stop-ExistingDemoProcesses

$apiLog = Join-Path $projectRoot "api-demo.log"
$apiErrLog = Join-Path $projectRoot "api-demo.err.log"
$webLog = Join-Path $projectRoot "web-demo.log"
$webErrLog = Join-Path $projectRoot "web-demo.err.log"
$tunnelLog = Join-Path $projectRoot "cloudflared-demo.log"
$tunnelErrLog = Join-Path $projectRoot "cloudflared-demo.err.log"

Remove-Item $apiLog,$apiErrLog,$webLog,$webErrLog,$tunnelLog,$tunnelErrLog -Force -ErrorAction SilentlyContinue

$apiProcess = Start-Process dotnet -ArgumentList @("run", "--project", "src/WrestlingPlatform.Api", "--urls", $ApiUrl) -WorkingDirectory $projectRoot -RedirectStandardOutput $apiLog -RedirectStandardError $apiErrLog -WindowStyle Hidden -PassThru
$webProcess = Start-Process dotnet -ArgumentList @("run", "--project", "src/WrestlingPlatform.Web", "--urls", $WebUrl) -WorkingDirectory $projectRoot -RedirectStandardOutput $webLog -RedirectStandardError $webErrLog -WindowStyle Hidden -PassThru

$apiPort = [int]([uri]$ApiUrl).Port
$webPort = [int]([uri]$WebUrl).Port

Wait-ForListeningPort -Port $apiPort
Wait-ForListeningPort -Port $webPort

if (-not (Test-Path "tools\\cloudflared.exe")) {
    New-Item -ItemType Directory -Force "tools" | Out-Null
    Invoke-WebRequest -Uri "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe" -OutFile "tools\\cloudflared.exe"
}

$tunnelExe = Join-Path $projectRoot "tools\\cloudflared.exe"
$tunnelProcess = Start-Process $tunnelExe -ArgumentList @("tunnel", "--url", $WebUrl, "--no-autoupdate") -WorkingDirectory $projectRoot -RedirectStandardOutput $tunnelLog -RedirectStandardError $tunnelErrLog -WindowStyle Hidden -PassThru

@{
    ApiPid = $apiProcess.Id
    WebPid = $webProcess.Id
    TunnelPid = $tunnelProcess.Id
    CreatedUtc = [DateTime]::UtcNow.ToString("o")
} | ConvertTo-Json | Set-Content $pidFile

$tunnelUrl = Wait-ForCloudflareUrl -LogPaths @($tunnelLog, $tunnelErrLog) -TunnelPid $tunnelProcess.Id

Write-Host "Public URL: $tunnelUrl"
Write-Host "API URL: $ApiUrl"
Write-Host "Web URL: $WebUrl"
Write-Host "Logs:"
Write-Host "  $apiLog"
Write-Host "  $apiErrLog"
Write-Host "  $webLog"
Write-Host "  $webErrLog"
Write-Host "  $tunnelLog"
Write-Host "  $tunnelErrLog"
Write-Host "PID file: $pidFile"
