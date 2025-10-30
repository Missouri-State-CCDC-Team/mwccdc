<#
.SYNOPSIS
    Deploys the Splunk Universal Forwarder on a Windows Server
#>

param (
    # Optional: Specify the IP address of the Splunk Indexer (receiver).
    [string]$INDEXER_IP = "172.20.242.20",

    # Optional: Specify the hostname to be used by Splunk.
    # Defaults to the machine's current hostname.
    [string]$SplunkHostname = $env:COMPUTERNAME
)

# PowerShell script to install and configure Splunk Universal Forwarder on Windows machines
# This script was modified off of the original version provided by Samuel Brucker to add additional features. 
# Changes by: Tyler Olson 2025 
# Credit to: Samuel Brucker 2024 - 2026

# Define variables
$SPLUNK_VERSION = "10.0.1"
$SPLUNK_BUILD = "c486717c322b"
$SPLUNK_MSI = "splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-windows-x64.msi"
$SPLUNK_DOWNLOAD_URL = "https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/windows/${SPLUNK_MSI}"
$INSTALL_DIR = "C:\Program Files\SplunkUniversalForwarder"
$RECEIVER_PORT = "9997"

# Download Splunk Universal Forwarder MSI
Write-Host "Downloading Splunk Universal Forwarder MSI..."
#take away the progress bar, but drastically speeds up downloads on older powershell versions. On server 2019, I'm not joking that it's at least 20x or 30x faster
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri $SPLUNK_DOWNLOAD_URL -OutFile $SPLUNK_MSI

# Install Splunk Universal Forwarder
Write-Host "Installing Splunk Universal Forwarder..."
# The $INDEXER_IP variable will be pulled from the parameters
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $SPLUNK_MSI AGREETOLICENSE=Yes RECEIVING_INDEXER=${INDEXER_IP}:${RECEIVER_PORT} /quiet" -Wait

# Configure inputs.conf for monitoring
$inputsConfPath = "$INSTALL_DIR\etc\system\local\inputs.conf"
Write-Host "Configuring inputs.conf for monitoring..."

@"
[monitor://C:\tmp\test.log]
disabled = 0
index = main
sourcetype = test
"@ | Out-File -FilePath $inputsConfPath -Encoding ASCII

# Configure server.conf to use the specified hostname
$serverConfPath = "$INSTALL_DIR\etc\system\local\server.conf"
Write-Host "Setting custom hostname for the logs to '$SplunkHostname'..."
# The $SplunkHostname variable will be pulled from the parameters
@"
[general]
serverName = $SplunkHostname
hostnameOption = shortname
"@ | Out-File -FilePath $serverConfPath -Encoding ASCII

# Start Splunk Universal Forwarder service
Write-Host "Starting Splunk Universal Forwarder service..."
Start-Process -FilePath "$INSTALL_DIR\bin\splunk.exe" -ArgumentList "start" -Wait

# Set Splunk Universal Forwarder to start on boot
Write-Host "Setting Splunk Universal Forwarder to start on boot..."
Start-Process -FilePath "$INSTALL_DIR\bin\splunk.exe" -ArgumentList "enable boot-start" -Wait

Write-Host "Splunk Universal Forwarder installation and configuration complete!"
