#!/bin/bash
# This script is to set up everything including the collections for roles that are used in my playbooks. 


sudo apt update
sudo apt install ansible python3- git

mkdir ~/ansible
cd ~/ansible

ansible-galaxy collection install devsec.hardening


mkdir ~/ansible/github
cd ~/ansible/github
git clone https://github.com/ansible-lockdown/Windows-2019-CIS
git clone https://github.com/rdiers/CentOS7-CIS 
