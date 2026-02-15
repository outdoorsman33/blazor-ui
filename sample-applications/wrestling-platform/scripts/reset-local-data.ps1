$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

& "$PSScriptRoot\stop-local-dev.ps1"

$dbPatterns = @(
    "src\WrestlingPlatform.Api\wrestling-platform*.db",
    "src\WrestlingPlatform.Api\wrestling-platform*.db-shm",
    "src\WrestlingPlatform.Api\wrestling-platform*.db-wal",
    "wrestling-platform*.db",
    "wrestling-platform*.db-shm",
    "wrestling-platform*.db-wal"
)

$deleted = 0
foreach ($pattern in $dbPatterns) {
    Get-ChildItem -Path $projectRoot -Filter (Split-Path $pattern -Leaf) -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like "*wrestling-platform*.db*" } |
        ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            $deleted++
        }
}

Write-Host "Deleted $deleted SQLite database file(s)."
Write-Host "Run .\scripts\start-local-dev.ps1 to reseed fresh demo data."
