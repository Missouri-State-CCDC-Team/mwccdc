# ==============================================================================
# Script Name : .\tools.ps1
# Description : Various utility functions for system administration.
# Author      : Tyler Olson
# Version     : 1.0
# ==============================================================================
# Usage       : .\tools.ps1 
# ==============================================================================

$sysinternals_downloadUrl = https://download.sysinternals.com/files/SysinternalsSuite.zip
$sysinternalsPath = "C:\Tools\Sysinternals"

# Log file setup
$LogDir = "C:\Logs"
$LogFile = "$LogDir\tools$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$TimeStamp] [$Level] $Message"
    $LogMessage | Out-File -FilePath $LogFile -Append
    
    # Also output to console with color coding
    switch ($Level) {
        "INFO" { Write-Host $LogMessage -ForegroundColor Gray }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $LogMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
    }
}

# Ensure winget is avalible on the host
try {
    Get-Command winget -ErrorAction Stop | Out-Null
    Write-Log "Winget is already installed." "SUCCESS"
}
catch {
    Write-Log "Winget not found. User should attempt to fix" "INFO"
}


# Programs to install 
$programs = @(
    "Mozilla.Firefox",
    "Git.Git"
)

# Attempt to install each program
foreach ($program in $programs) {
    try {
        Write-Log "Installing $program via winget" "INFO"
        winget install --id=$program --silent --accept-source-agreements --accept-package-agreements
        Write-Log "$program installed successfully." "SUCCESS"
    }
    catch {
        Write-Log "Failed to install $program" "ERROR"
    }
}


# Install the sysinternals suite to C:\Tools\Sysinternals
wget $sysinternals_downloadUrl -OutFile "$env:TEMP\SysinternalsSuite.zip"
Expand-Archive -Path "$env:TEMP\SysinternalsSuite.zip" -DestinationPath "C:\Tools\Sysinternals" -Force
Write-Log "Sysinternals Suite downloaded and extracted to C:\Tools\Sysinternals" "SUCCESS"

# Ensure the sysintenals tools is in the shell file for easy access
$profilePath = $PROFILE.CurrentUserAllHosts
if (-not (Test-Path $profilePath)) {
    New-Item -Path $profilePath -ItemType File -Force | Out-Null
}

# Add Sysinternals envrionment variable in the system variables
[System.Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\Tools\Sysinternals", [System.EnvironmentVariableTarget]::Machine)
Write-Log "Sysinternals path added to system PATH environment variable." "SUCCESS"
