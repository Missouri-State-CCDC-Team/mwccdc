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

Write-Host "Starting to provision this server!"

# Ensure WSL is enabled
Write-Output "Checking WSL installation..."
$wslFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux

if ($wslFeature.State -ne "Enabled") {
    Write-Output "Enabling WSL..."
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
}

#2. Install the distrobution
Write-Host "Invoking web requests"
invoke-webrequest https://wslstorestorage.blob.core.windows.net/wslblob/Ubuntu2404-240425.AppxBundle
Rename-Item .\Ubuntu2404-240425.AppxBundle.appx .\Ubuntu2404.zip
Expand-Archive .\Ubuntu2404.zip .\Ubuntu2404


Write-Host "Installing the app package..."
Add-AppxPackage .\Ubuntu2404\Ubuntu_2404.0.5.0_x64.appx

# Define GitHub script URL and download it
$githubScriptURL = "https://raw.githubusercontent.com/Missouri-State-CCDC-Team/mwccdc/refs/heads/main/ansible/ansibleserver.sh"
$wslCommand = "curl -fsSL $githubScriptURL -o ~/setup.sh && chmod +x ~/setup.sh && bash ~/setup.sh"

Write-Output "Running GitHub script inside Ubuntu..."
wsl bash -c "$wslCommand"