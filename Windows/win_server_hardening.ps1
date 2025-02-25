# Ensure the script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Run this script as an administrator."
    exit
}

#Function Reset-UserPassword {
#    param (
#        [string]$UserName,
#        [string]$NewPassword
#    )
#    Write-Host "Resetting password for user $UserName..."
#    net user $UserName $NewPassword
#}

function Export-CommandHistory {
    $historyFile = (Get-PSReadlineOption).HistorySavePath
    if (Test-Path $historyFile) {
        $outputPath = "$env:USERPROFILE\Documents\CommandHistory.txt"
        Get-Content $historyFile | Out-File -FilePath $outputPath -Encoding UTF8
        Write-Host "Command history exported to $outputPath"
    } else {
        Write-Host "No command history file found."
    }
}

function Set-RestrictedExecutionPolicy {
    Set-ExecutionPolicy -ExecutionPolicy Restricted -Force
    Write-Host "Execution policy set to Restricted."
}

function Disable-Remoting {
    Disable-PSRemoting -Force -SkipNetworkProfileCheck
    Write-Host "WinRM Disabled"
    # Disable RDP
    try {
        # Set registry value to deny Remote Desktop connections
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Force

        # Optionally disable the Remote Desktop Service (TermService)
        Set-Service -Name TermService -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name TermService -Force -ErrorAction SilentlyContinue
        Write-Host "Remote Desktop has been disabled." -ForegroundColor Green
    }
    catch {
        Write-Host "error in disabling remote assistance: $_" -ForegroundColor Red
    }
    # Disable remote registry
    try {
        Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
        Write-Host "Remote Registry service has been disabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Error disabling Remote Registry: $_" -ForegroundColor Red
    }
}

function Stop-UnnecessaryServices {
    $services = @("bthserv", "MapsBroker", "Spooler", "SSDPSRV")
    foreach ($service in $services) {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            Stop-Service -Name $service -Force
            Write-Host "Stopped service: $service"
        } else {
            Write-Host "Service not found: $service"
        }
    }
}

function Run-SystemFileCheck {
    Write-Host "Starting system file check..."
    sfc /scannow
    Write-Host "System file check completed."
}

function Check-LastLogon {
    $adminLastLogon = (net user administrator | Select-String -Pattern "^Last logon").Line
    Write-Host "Administrator's last logon: $adminLastLogon"
}

Function Disable-SMBv1 {
    Write-Host "Disabling SMBv1..."
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
}

# Configure firewall rules
Function Configure-Firewall {
    Write-Host "Configuring firewall rules..."

    # Clear all current rules
   # netsh advfirewall firewall delete rule name=all

    # Allow inbound rules for specific ports
    $allowInboundPorts = @(80, 443, 67, 22, 53, 8000)
    foreach ($port in $allowInboundPorts) {
        netsh advfirewall firewall add rule name="Allow-Inbound-Port-$port" dir=in action=allow protocol=TCP localport=$port
    }

    # Block all other inbound traffic
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

    # Allow outbound rules for specific ports
    $allowOutboundPorts = @(80, 443, 67, 22, 53, 8000)
    foreach ($port in $allowOutboundPorts) {
        netsh advfirewall firewall add rule name="Allow-Outbound-Port-$port" dir=out action=allow protocol=TCP localport=$port
    }
    
    # Block all other outbound traffic
    netsh advfirewall set allprofiles firewallpolicy allowinbound,blockoutbound
}

#Function Disable-UnnecessaryAccounts {
#    Write-Host "Disabling unnecessary user accounts..."
#    Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -notmatch "Administrator|DefaultAccount|Guest" } | ForEach-Object {
#        Disable-LocalUser -Name $_.Name
 #       Write-Host "Disabled account: $_.Name"
#    }
#}

Function Configure-NTP {
    Write-Host "Configuring NTP..."
    w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:YES /update
    Restart-Service w32time
    w32tm /resync
}

function Check-HostsFile {
    $hostsFilePath = "$env:WinDir\System32\drivers\etc\hosts"
    if (Test-Path $hostsFilePath) {
        Write-Host "Opening hosts file for review..."
        notepad.exe $hostsFilePath
    } else {
        Write-Host "Hosts file not found."
    }
}

function Get-ADUserLastLogon {
    if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
        Get-ADUser -Filter * -Properties LastLogonDate | 
            Select-Object Name, LastLogonDate | 
            Format-Table -AutoSize
    } else {
        Write-Host "Active Directory module not installed or available."
    }
}

Function Install-WLANService {
    Write-Host "Installing Wireless LAN Service..."
    Add-WindowsFeature -Name Wireless-Networking
    Start-Service -Name "WlanSvc"
}

#Function Download-Splunk {
#    Write-Host "Downloading Splunk Universal Forwarder..."
 #   $url = "https://download.splunk.com/products/universalforwarder/releases/9.2.0.1/windows/splunkforwarder-9.2.0.1-d8ae995bf219-x64-release.msi"
 #   $output = "C:\SplunkForwarder.msi"
 #   Invoke-WebRequest -Uri $url -OutFile $output
#    Write-Host "Splunk downloaded to $output"
#}

# Main script execution
Write-Host "Starting server configuration script..."


#Reset-UserPassword -UserName "Administrator" -NewPassword "NewSecurePassword123!"

#Disable-SMBv1

Configure-Firewall

#Disable-UnnecessaryAccounts

Configure-NTP

#Set-RestrictedExecutionPolicy

#Run-SystemFileCheck

#Install-WLANService

#Download-Splunk

Stop-UnnecessaryServices

Disable-Remoting

Check-HostsFile

Check-LastLogon

Get-ADUserLastLogon

Export-CommandHistory


Write-Host "Script execution completed."
