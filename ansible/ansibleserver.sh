#!/bin/bash
# This script is to set up everything including the collections for roles that are used in my playbooks. 

# Steps for ubuntu on 2019 docker:
# 1. Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
# 2. Invoke-WebRequest -Uri https://aka.ms/wslubuntu2004 -OutFile Ubuntu.appx -UseBasicParsing
# Here for rest: https://learn.microsoft.com/en-us/windows/wsl/install-on-server

# Color Variables
RED='\033[0;31m'; GREEN='\033[0;32m'; RESET='\033[0m' # Reset color

log() {
    echo -e "${RED}$1${RESET}"
}

pre-setup() {
    # Update the server and install the required packages
    sudo apt update
    sudo apt install ansible python3-paramiko git -y

    # make the directory for ansible 
    mkdir ~/ansible && cd ~/ansible || log "failed to change directory"

    # Take the hosts file in the given files and send it to /etc/hosts
    cat hosts | sudo tee -a /etc/hosts || log "Failed to put the hosts file in"
}

galaxy-setup() {
    ansible-galaxy collection install devsec.hardening
    ansible-galaxy role install robertdebock.fail2ban
    ansible-galaxy role install geerlingguy.ntp
    ansible-galaxy role install geerlingguy.security
}
# https://robertdebock.nl/how-to-use-these-roles.html and https://github.com/robertdebock/ansible-role-fail2ban foir using fail2ban


github() {
    mkdir ~/ansible/github && cd ~/ansible/github || log "Failed to Change Directory"
    # Audit for CIS configurations
    git clone https://github.com/ansible-lockdown/Windows-2019-CIS-Audit
    git clone https://github.com/ansible-lockdown/RHEL7-CIS-Audit
    git clone https://github.com/ansible-lockdown/UBUNTU18-CIS-Audit 

    # Remediate to CIS Benchmarks 
    git clone https://github.com/ansible-lockdown/Windows-2019-CIS
    git clone https://github.com/rdiers/CentOS7-CIS 
    git clone https://github.com/ansible-lockdown/RHEL7-CIS
    git clone https://github.com/ansible-lockdown/UBUNTU18-CIS 

    #reset to home
    cd ~
}


git_sparse_clone() (
  rurl="$1" localdir="$2" && shift 2

  mkdir -p "$localdir"
  cd "$localdir"

  git init
  git remote add -f origin "$rurl"

  git config core.sparseCheckout true

  # Loops over remaining args
  for i; do
    echo "$i" >> .git/info/sparse-checkout
  done

  git pull origin master
)


main() {
    pre-setup || log "Pre-set up failed"
    galaxy-setup || log "Galaxy failed"
    github || log "Github failed"
    git_sparse_clone "https://github.com/Missouri-State-CCDC-Team/mwccdc" "./ansible/" "/ansible"
}

main