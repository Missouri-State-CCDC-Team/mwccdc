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
root_user="root"
sudo_user= "sysadmin"
sudo_password= "changemenow"
new_password="password"
splunk_version="9.1.1"
backupip="172.20.20.20"
backup-account="root"
$SSHD_CONFIG="/etc/ssh/sshd_config"
 

if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root or with sudo privileges"
    exit 1
fi


#-------------

## Taking backup of splunk services (3 local locations 1 remote)
mkdir /root/backiit
mkdir ~/backup

# SSH Backup
cp -R /etc/ssh /root/backit
cp -R /etc/ssh ~/backup

yum install fail2ban
systemctl enable fail2ban


#-------------
# Change sshd configuration

# Replace (or uncomment and update) the configuration directives:
sed -i 's/^#\?Port .*/Port 2222/' "$SSHD_CONFIG"
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' "$SSHD_CONFIG"
sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' "$SSHD_CONFIG"
sed -i 's/^#\?X11[Ff]orwarding .*/X11Forwarding no/' "$SSHD_CONFIG"
sed -i 's/^#\?MaxAuthTries .*/MaxAuthTries 3/' "$SSHD_CONFIG"
sed -i 's/^#\?ClientAliveMaxCount .*/ClientAliveMaxCount 2/' "$SSHD_CONFIG"
sed -i 's/^#\?AllowUsers.*/AllowUsers/' "$SSHD_CONFIG"
# If the AllowUsers directive isn’t present at all, you might add it:

systemctl restart ssh

# Change mongod configuration to not bind to 0.0.0.0


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
