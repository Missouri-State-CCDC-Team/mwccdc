#!/bin/bash 
# ==============================================================================
# Script Name : splunkharden.sh
# Description : If we have the time to use ansible for our network. Through ssh this will set up and ansible user with a supplied public key file for ansible.
# Author      : Tyler Olson
# Organization: Missouri State University
# Version     : 1.0
# ==============================================================================
# Usage       : splunkharden.sh
# Notes       :
#   - 
# ==============================================================================
# Changelog:
#   v0.9 - Not done yet.
# ==============================================================================

# Defined variables:
defaultUsers= ("root", "sysadmin")
sudo_password= "changemenow"
new_password="password"
splunk_version="9.1.1"
backupip="172.20.20.20"
backup-account="root"
 
# I love the colors
RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[0;33m'
BLUE=$'\e[0;34m'
NC=$'\e[0m'  #No Color - resets the color back to default


if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root or with sudo privileges"
    exit 1
fi

log() {
    echo -e "${RED}$1${NC}"
}

password_changes() {
    for user in $defaultUsers; do
        echo "Changing password for $user"
        passwd $user
}

#-------------

backup() {
    # define the variables needed for this function
    local SPLUNK_HOME=/"opt/splunk"
    local BACKUP_DIR="/backup/splunk"

    tar -czvf "$BACKUP_FILE" \
        --exclude="$SPLUNK_HOME/var/run/splunk/dispatch" \
        --exclude="$SPLUNK_HOME/var/run/splunk/kvstore" \
        "$SPLUNK_HOME/etc" \
        "$SPLUNK_HOME/var/lib/splunk" \
        "$SPLUNK_HOME/var/log/splunk"


}


updateinstall() {
    echo "Now attempting to upgrade packages..."
    # Install some applications to assist with anti cookie theft (I'M KEEPING THEM ALLLL)
    yum update
    yum install fail2ban rkhunter curl
    systemctl enable fail2ban
}

#-------------
# Change sshd configuration
updateSSH() {
    # Needed SSH Config Files
    local SSHD_CONFIG_DIR="/etc/ssh/"
    local SSHD_CONFIG="/etc/ssh/sshd_config"

    # Ensure sshd_config.d directory exists
    mkdir -p "$SSHD_CONFIG_DIR"
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup"
    #Set permissions
    chmod 444 "$SSHD_CONFIG"

    sed -i \
      -e "s/^[# ]*Port.*/Port $port/" \
      -e 's/^[# ]*PasswordAuthentication.*/PasswordAuthentication no/' \
      -e 's/^[# ]*PermitRootLogin.*/PermitRootLogin no/' \
      -e 's/^[# ]*PubkeyAuthentication.*/PubkeyAuthentication yes/' \
      -e 's/^[# ]*X11[Ff]orwarding .*/X11Forwarding no/' \
      -e 's/^[# ]*MaxAuthTries .*/MaxAuthTries 3/' \
      -e 's/^[# ]*ClientAliveMaxCount .*//ClientAliveMaxCount 2/' \
      "$SSHD_CONFIG"

    systemctl restart ssh
    echo  "Configuring SSH daemon..."

    # Test configuration to see if there was errors
    if ! sshd -t ; then
        echo "Error: Invalid SSHD configuration"
        echo "Rolling back changes..."
        if [ -f "${SSHD_CONFIG}.backup" ]; then
            mv "${SSHD_CONFIG}.backup" "$SSHD_CONFIG"
        fi
        rm -f "$SSHD_CUSTOM_CONFIG"
        exit 1
}


firewallConfig() {
    # Firewall Rules
    sudo firewall-cmd --new-zone=ccdczone
    sudo firewall-cmd --set-default-zone=ccdczone
    sudo firewall-cmd --permanent --zone=ccdczone --add-port=8000/tcp
    sudo firewall-cmd --permanent --zone=ccdczone --add-port=8089/tcp
    sudo firewall-cmd --permanent --zone=ccdczone --add-port=8191/tcp
    sudo firewall-cmd --permanent --zone=ccdczone --add-port=8191/tcp
    sudo firewall-cmd --permanent --zone=ccdczone --add-port=2222/tcp
    # Chronyd (NTP)
    sudo firewall-cmd --permanent --add-port=323/

    # Explicitly deny traffic
    sudo firewall-cmd --permanent --zone=ccdczone --set-target=DROP

    sudo firewall-cmd --reload

    echo "------------"
    echo "firewall rules:"
    firewall-cmd --list-all
    echo "-------------"
}

login_wall() {
    # Logging in wall
    LINE='wall "$(id -un) logged in from $(echo $SSH_CLIENT | awk '"'"'{print $1}'"'"')"'

    echo "$LINE" | sudo tee /etc/profile.d/login_wall.sh > /dev/null
    sudo chmod +x /etc/profile.d/login_wall.sh

    for dir in /home/*; do
        if [ -d "$dir" ]; then
            USER_BASHRC="$dir/.bashrc"
            if ! grep -qF "$LINE" "$USER_BASHRC"; then
                echo "$LINE" | sudo tee -a "$USER_BASHRC" > /dev/null
            fi
        fi
    done

    if ! grep -qF "$LINE" /root/.bashrc; then
        echo "$LINE" | sudo tee -a /root/.bashrc > /dev/null
    fi
}

scriptCopy() {
    # Clones some important scripts for splunk :)
    curl https://raw.githubusercontent.com/Missouri-State-CCDC-Team/mwccdc/refs/heads/main/Linux/lockAndExpireUser.sh >> lockAndExpireUser.sh
    curl https://github.com/Missouri-State-CCDC-Team/mwccdc/blob/main/Linux/fileMonitoringEtc.sh >> fileMonitor.sh
}


main() {
    backup || 
}