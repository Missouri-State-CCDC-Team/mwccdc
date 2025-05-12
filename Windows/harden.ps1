# ==============================================================================
# Script Name : harden.ps1
# Description : Invokes all the applicable base hardening scripts in this
#               directory.
# Author      : Tyler Olson
# Organization: Missouri State University
# Version     : 1.0
# ==============================================================================

$LogFile = "C:\Logs\MasterHardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$LogDir = Split-Path $LogFile -Parent
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$TimeStamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    
    # Also output to console with color
    switch ($Level) {
        "INFO" { Write-Host $LogMessage -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $LogMessage -ForegroundColor Red }
    }
}

function Invoke-Script {
    param (
        [string]$ScriptPath,
        [string]$Description,
        [hashtable]$Parameters = @{}
    )

    # Here probably should test to see if script exits

    # Write the log of start of execution

    Write-Log "Executing: $Description" "INFO"

    try {
        # Create parameter string
        $paramString = ""
        foreach ($key in $Parameters.Keys) {
            $value = $Parameters[$key]
            # If value contains spaces, wrap in quotes
            if ($value -match "\s") {
                $paramString += " -$key `"$value`""
            } else {
                $paramString += " -$key $value"
            }
        }

        # Execute the script with parameters
        if ($paramString) {
            $command = "& '$ScriptPath'$paramString"
            Write-Log "Command: $command" "INFO"
            Invoke-Expression $command
        } else {
            Write-Log "Command: & '$ScriptPath'" "INFO"
            & $ScriptPath
        }
        
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            Write-Log "$Description completed with exit code $LASTEXITCODE" "WARNING"
            return $false
        } else {
            Write-Log "$Description completed successfully" "SUCCESS"
            return $true
        }
    }
    catch {
        Write-Log "Error executing $Description`: $_" "ERROR"
        return $false
    }
}

Write-Log "Starting to run the hardening scripts" "INFO"

# 1. RESET THOSE CREDS BABY
$success = Invoke-SecurityScript -ScriptPath $GoldenTicketScript -Description "Golden Ticket Attack Mitigation"
if (-not $success) {
    Write-Log "Golden Ticket mitigation failed or had warnings" "WARNING"
}

# 2. Disable all remote management
$success = Invoke-SecurityScript -ScriptPath $DisableRemotingScript -Description "Disabling Remote Management"
if (-not $success) {
    Write-Log "Remote management disabling failed or had warnings" "WARNING"
}

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "                    Hardening Server Summary                      " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "Invoked several scripts all doing different things"
Write-Host "Sorry I'm not writing it all here."
Write-Host "NEXT TASKS:"
Write-Host " 1. CHANGE ADMINISTRATOR PASSWORD ASAP"
Write-Host "==================================================================" -ForegroundColor Cyan