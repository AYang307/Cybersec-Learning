<#
.SYNOPSIS
    CCDC Module 1 — Local TCP Socket Inspector
.DESCRIPTION
    Queries active TCP connections and listening sockets on Windows,
    filtering for CCDC mock ports or showing listening states.
.EXAMPLE
    .\inspect_sockets.ps1 -Port 8080
    .\inspect_sockets.ps1 -State Listen
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [int]$Port,

    [Parameter(Mandatory=$false)]
    [ValidateSet('Listen', 'Established', 'SynSent', 'TimeWait', 'All')]
    [string]$State = 'All'
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " CCDC Local Socket Inspector (PowerShell NetTCPIP)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$params = @{}
if ($State -ne 'All') {
    $params['State'] = $State
}
if ($Port) {
    $params['LocalPort'] = $Port
}

$connections = Get-NetTCPConnection @params -ErrorAction SilentlyContinue

if (-not $connections) {
    Write-Host "[!] No active TCP connections matched the filter (Port: $Port, State: $State)" -ForegroundColor Yellow
    exit 0
}

$results = foreach ($conn in $connections) {
    $processName = "Unknown"
    if ($conn.OwningProcess -gt 0) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($proc) {
            $processName = $proc.ProcessName
        }
    }

    [PSCustomObject]@{
        LocalAddress  = $conn.LocalAddress
        LocalPort     = $conn.LocalPort
        RemoteAddress = $conn.RemoteAddress
        RemotePort    = $conn.RemotePort
        State         = $conn.State
        PID           = $conn.OwningProcess
        ProcessName   = $processName
    }
}

$results | Format-Table -AutoSize
