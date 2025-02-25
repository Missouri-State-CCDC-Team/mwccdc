#!/bin/bash

# This will take the fedora system and configure the firewalls, backups, and take the entire system to a more secure spot.

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