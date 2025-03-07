#!/bin/bash 
# ==============================================================================
# Script Name : DEBAdvancedHardening.sh
# Description : Runs advanced software and hardening on debian based systems.
# Author      : Tyler Olson
# Organization: Missouri State University
# Version     : 0.9
# ==============================================================================
# Usage       : RHAdvancedHardening.sh
# Notes       :
#   - Make sure to update the variables as needed to configure the system correctly.
# ==============================================================================
# Changelog:
#   v1 - Fancy file man :)
# ==============================================================================

RED=$'\e[0;31m'; GREEN=$'\e[0;32m'; YELLOW=$'\e[0;33m'; BLUE=$'\e[0;34m'; NC=$'\e[0m'       # Sets the colors in use throughout the code
forwarderScript="https://tinyurl.com/msuforwarder"


# Check if root
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root or with sudo privileges"
    exit 1
fi

software() {
    apt install -y tripwire rkhunter lynis
}

tripwire() {
    # Commands adapted from Red Hats's implementation 
    echo -e "${GREEN}About to create keys for tripwire, be ready to enter supplied site and local password${NC}"
    echo -e "${YELLOW}This local key is intended to be unique to each server. Please note down what you put in.${NC}"
    twadmin --generate-keys --local-keyfile /etc/tripwire/$(hostname)-local.key || notify "failed to set local key"
    echo -e "${YELLOW}This site key is accross the network.${NC}"
    twadmin --generate-keys --site-keyfile /etc/tripwire/site.key || notify "failed to generate site key"

    # Create the config file for the tripwire configuration
    echo -e "${YELLOW} Creating the configuration file and signing it"
    twadmin --create-cfgfile --site-keyfile /etc/tripwire/site.key /etc/tripwire/twcfg.txt

    # Create a policy file
    echo -e "${YELLOW} Creating the policy file and signing it"
    sudo twadmin --create-polfile --site-keyfile /etc/tripwire/site.key /etc/tripwire/twpol.txt
    sudo tripwire --init

    echo -e "${GREEN} Created all the files needed for tripwire to function. \n Please ensure you have written down these passwords${NC}"
    echo -e "${YELLOW} use tripwire --check --interactive to complete FS Checks${NC}"

}

enable_auditd_logging() {
    echo -e "${YELLOW}Enabling auditd logging for executed commands...${NC}"
    echo "-a always,exit -F arch=b64 -S execve -k execution" >> /etc/audit/rules.d/audit.rules
    augenrules --load
    systemctl restart auditd
}


login_wall() {
    echo -e "${YELLOW} Currently adding a profile wall to the users in the system for login notifications${NC}"
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
    forwarder_script
    enable_auditd_logging
    
    echo "${RED}don't forget to update packages.${NC}"
}