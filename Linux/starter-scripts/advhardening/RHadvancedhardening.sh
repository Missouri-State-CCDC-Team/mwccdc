#!/bin/bash 
# ==============================================================================
# Script Name : RHAdvancedHardening.sh
# Description : Runs advanced software and hardening on redhat based systems.
# Author      : Tyler Olson
# Organization: Missouri State University
# Version     : 0.9
# ==============================================================================
# Usage       : RHAdvancedHardening.sh
# Notes       :
#   - Make sure to update the variables as needed to configure the system correctly.
# ==============================================================================
# Changelog:
#   v0.9 - Working on the many different functions
# ==============================================================================


forwarderScript="https://tinyurl.com/test"


# Check if root
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root or with sudo privileges"
    exit 1
fi

tripwire() {
    yum install -y tripwire
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

fowarder_script() {
    wget $forwarderScript -o splunkforward.sh
    chmod +x ./splunkforward.sh
    
    echo "forwarder script installed please configure it and run."
}

main() {
    tripwire
    login_wall
    forwarderScript
    
    echo "don't forget to update packages."
}