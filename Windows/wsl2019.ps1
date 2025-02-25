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

# 3. Install Ubuntu (silent install)
$ubuntuUrl = "https://aka.ms/wsl-ubuntu-2004"
$ubuntuPath = "$env:TEMP\Ubuntu.appx"
Invoke-WebRequest -Uri $ubuntuUrl -OutFile $ubuntuPath
Add-AppxPackage -Path $ubuntuPath

# 4. Wait for WSL initialization and run commands in Ubuntu
$githubScriptUrl = "https://raw.githubusercontent.com/Missouri-State-CCDC-Team/mwccdc/refs/heads/main/ansible/ansibleserver.sh"
$wslCommand = @"
#!/bin/bash
# Update packages first
apt-get update && apt-get upgrade -y

# Download and execute external script
curl -sSL $githubScriptUrl | bash -s --
"@

# Save commands to temporary script
$tempScript = "$env:TEMP\wsl_init.sh"
$wslCommand | Out-File -FilePath $tempScript -Encoding ASCII

# Execute the script in Ubuntu
wsl -d Ubuntu -u root bash -c "bash $tempScript"

# Cleanup
Remove-Item $tempScript