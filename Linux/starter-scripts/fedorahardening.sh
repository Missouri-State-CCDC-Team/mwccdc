
#!/bin/bash 
# ==============================================================================
# Script Name : fedoraharden.sh
# Description : Configure everything from A to B
# Author      : Tyler Olson
# Organization: Missouri State University
# Version     : 0.9
# ==============================================================================
# Usage       : fedoraharden.sh
# Notes       :
#   - Make sure to update the variables as needed to configure the system correctly.
# ==============================================================================
# Changelog:
#   v0.9 - Working on the many different functions
# ==============================================================================

# Check if added as root
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root or with sudo privileges"
    exit 1
fi

# Definitions:
username='root'
newUsername='example'
services=("postfix" "dovecot")

RED=$'\e[0;31m'; GREEN=$'\e[0;32m'; YELLOW=$'\e[0;33m'; BLUE=$'\e[0;34m'; NC=$'\e[0m'       # Sets the colors in use throughout the cude


# Functions:
notify() { echo -e "${RED}$1${NC}"; }

software() {
    sudo yum update
    yum install -y tmux tripwire
}

passchange() {
    echo "changing root password"
    passwd
    echo "changing password of provided username"
    passwd $username
}


backup() {
    mkdir -p /root/backit /etc/backup/ /root/backit/binaries

    for service in "${services[@]}"; do
        if [ -d "/etc/$service" ]; then
            cp -r "/etc/$service" "/root/backit/"
            echo "Backed up /etc/$service"
        elif [ -f "/etc/$service.conf" ]; then
            cp "/etc/$service.conf" "/root/backit/"
            echo "Backed up /etc/$service.conf"
        else
            echo "Warning: No config found for $service"
        fi
    done

    rsync -av /usr/bin/ /root/backit/binaries/ --exclude "*.tmp"       # backup binaries

    echo "Completed the backup"
}

malphp() {
    echo "cleaning up php files"
    find / -type f -name "index.php" ! -path "/var/www/*" 2>/dev/null | while read -r file; do
        # Backup the file to /root/ with a timestamp
        backup_file="/root/$(basename "$file")_$(date +%F_%T)"
        cp "$file" "$backup_file"
        rm -f "$file"            # Remove the original file

        # Log the action
        echo "Removed malicious PHP file: $file (Backed up at $backup_file)" | tee -a "$LOGFILE"
    done
    echo "cleaned up any php"
}

findcron() {
    echo "Scanning for crontab entries..."

    # Locations to check
    locations=("/etc/crontab" "/etc/cron.d/*" "/var/spool/cron/crontabs/*" "/var/spool/cron/*" "/etc/cron.hourly/*" "/etc/cron.daily/*" "/etc/cron.weekly/*" "/etc/cron.monthly/*" "/etc/anacrontab")

    # Loop through each location
    for loc in "${locations[@]}"; do
        if [ -f "$loc" ] || [ -d "$loc" ]; then
            content=$(cat "$loc" 2>/dev/null)
            if [ -n "$content" ]; then
                echo -e "\n--- Found crontab at: $loc ---"
                echo "$content"
            fi
        fi
    done

    for user in $(cut -d: -f1 /etc/passwd); do
        cronfile="/var/spool/cron/crontabs/$user"
        if [ -f "$cronfile" ]; then
            content=$(cat "$cronfile" 2>/dev/null)
            if [ -n "$content" ]; then
                echo -e "\n--- User crontab for $user at: $cronfile ---"
                echo "$content"
            fi
        fi
    done

    echo "crontab scan complete."
}

firewall_config() {
    # Firewall Rules
    sudo firewall-cmd --new-zone=ccdczone                                           # Creating a new zone
    sudo firewall-cmd --set-default-zone=ccdczone                                   
    sudo firewall-cmd --permanent --zone=ccdczone --add-port=587/tcp,25/tcp         # Ports for SMTP
    sudo firewall-cmd --permanent --zone=ccdczone --add-port=110/tcp,995/tcp        # Ports for Pop3
    sudo firewall-cmd --permanent --zone=ccdczone --add-port=5312/tcp               # Adding ports for SSH
    sudo firewall-cmd --permanent --add-port=323                                    # Chronyd (NTP)
    sudo firewall-cmd --permanent --zone=ccdczone --set-target=DROP                 # Explicitly deny traffic
    sudo firewall-cmd --reload || notify "failed to reload firewalld" >&2           # Reloading the firewall

    # Listing all the current rules for debugging.
    echo "------------"
    echo "firewall rules:"
    firewall-cmd --list-all
    echo "-------------"
}

check_services() {
    local service=$1
    local port=$2

    if nc -z localhost $port; then
        echo "$service is running on port $port."
    else
        notify "failed to find the service running, attempting to start it"
        sudo systemctl start $service || notify "service failed to start, check its logs and restore it" >&2
    fi
}


### NEED TO ADD PUBLIC KEY ADDITION TO THIS FILE. 

ssh_config() {
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
    fi
}

main() {
    software
    passchange
    backup
    malphp
    findcron
    firewall_config
    check_services
    ssh_config

    echo "completed all basic hardening"
    echo 'Please now run "AdvHardening" for your distro'
    echo "and don't forget to change the password"
}

main