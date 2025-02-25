
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
newRootPassword='password'
RED=$'\e[0;31m'; GREEN=$'\e[0;32m'; YELLOW=$'\e[0;33m'; BLUE=$'\e[0;34m'; NC=$'\e[0m'       # Sets the colors in use throughout the cude


# Functions:
notify() { echo -e "${RED}$1${NC}"; }

software() {
    sudo yum update
    yum install -y tmux tripwire
}

tripwire() {
    # Commands adapted from redhat's implementation 
    echo -e "${GREEN}About to create keys for tripwire, be ready to enter supplied site and local password"
    echo "This local key is intdnded to be unique to each server. Please note down what you put in."
    twadmin --generate-keys --local-keyfile /etc/tripwire/$(hostname)-local.key || notify "failed to set local key"
    echo "This site key is accross the network."
    twadmin --generate-keys --site-keyfile /etc/tripwire/site.key || notify "failed to generate site key"

    # Create the config file for the tripwire configuration
    twadmin --create-cfgfile --site-keyfile /etc/tripwire/site.key /etc/tripwire/twcfg.txt
}

# ==============================================================================
# Set up a login wall that will notify everyone if someone logs in through SSH
# ==============================================================================

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


# ==============================================================================
# Set up a login wall that will notify everyone if someone logs in through SSH
# ==============================================================================

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

main() {
    login_wall


}