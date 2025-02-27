# ==============================================================================
# Script Name : WSL Install for 2019
# Description : This script installs WSL and an ubuntu image to run on the system.
#               It will also grab the ansibleserver.sh script to set up the server properly
# Author      : Tyler Olson
# Organization: Missouri State University
# Version     : 1.0
# ==============================================================================
# Usage       : ./ccdc_hardening.sh
# Notes       :
#   - This script must be run with root or sudo privileges.
#   - Review all configurations to ensure they align with competition policies.
# ==============================================================================
# Changelog:
#   v1.0 - Creation! All basics are in here.
# ==============================================================================

Write-Host

# 1. Install WSL feature
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart

# 2. Install WSL2 Kernel Update (required for Windows Server 2019)
$kernelUrl = "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi"
$kernelPath = "$env:TEMP\wsl_update.msi"
Invoke-WebRequest -Uri $kernelUrl -OutFile $kernelPath
Start-Process msiexec.exe -Wait -ArgumentList "/i $kernelPath /quiet /norestart"
wsl --set-default-version 2


# If a reboot is needed, create a scheduled task to resume after reboot
if ($needsReboot) {
    $taskName = "ContinueWSLSetup"
    $scriptPath = "$env:TEMP\resume_wsl_install.ps1"

    # Write the remainder of the script to a new file
    @'
# Resume WSL installation
$githubScriptUrl = "https://raw.githubusercontent.com/Missouri-State-CCDC-Team/mwccdc/refs/heads/main/ansible/ansibleserver.sh"
$wslCommand = @"
#!/bin/bash
apt-get update && apt-get upgrade -y
curl -sSL $githubScriptUrl | bash -s --
"@

$tempScript = "$env:TEMP\wsl_init.sh"
$wslCommand | Out-File -FilePath $tempScript -Encoding ASCII
wsl -d Ubuntu -u root bash -c "bash $tempScript"
Remove-Item $tempScript

# Remove the scheduled task
schtasks /delete /tn "ContinueWSLSetup" /f
Remove-Item -Path "$scriptPath" -Force
'@ | Out-File -FilePath $scriptPath -Encoding ASCII

    # Create a scheduled task to run this script at startup
    schtasks /create /tn $taskName /tr "powershell.exe -ExecutionPolicy Bypass -File $scriptPath" /sc onstart /ru SYSTEM

    # Reboot the system
    Restart-Computer -Force
}