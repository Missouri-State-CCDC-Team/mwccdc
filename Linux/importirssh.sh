#!/bin/bash
# This will create an IR account with a pre-hashed password (CHANGE on next login) and prepare for ansible playbooks to be put onto the machine.

if [ "$EUID" -ne 0 ]; then 
    echo "This script needs to be run as sudo"
    exit 1
fi

USERNAME="CCDCIR"
PASSWORD='$6$BcYgtsE4/DaFDYRG$smzaU3PCbYSZlVu7dseVcOoyTUmqh71/dG04JLTw7DYvszm5aNiqGyXJemlOVCJ8WiDlqi7GY/2/wTyqhtCrI0'
PUBLIC_KEY="./pubkey"
SUDOERS_FILE="/etc/sudoers.d/$USERNAME"
read -p "enter the ssh port number: " port

if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    echo "Error: Invalid port number"
    exit 1
fi



create_user() {
    # This will create the IR user with the provided password
    useradd -m -s /bin/bash "$USERNAME"
    usermod -p "$PASSWORD" "$USERNAME"
    echo "Created a user with a hashed password"

    # Check for success
    if ! id "$USERNAME" &>/dev/null; then
        echo "User $USERNAME does not exist."
        exit 1
    fi  
}

add_to_sudo() {
    usermod -aG sudo $USERNAME
    echo "$USERNAME ALL=(ALL) ALL" >> /etc/sudoers.d/$USERNAME
    chmod 440 "$SUDOERS_FILE"

    if ! [ -f "$SUDOERS_FILE" ]; then
        echo "Error: Failed to create sudoers file"
        exit 1
    fi
}

add_ssh_key() {
    local ssh_dir="/home/$USERNAME/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"

    mkdir -p "$ssh_dir"
    chown -R "$USERNAME:$USERNAME" "/home/$USERNAME"
    chmod 700 "$ssh_dir"

    if [[ -n "$PUBLIC_KEY" ]]; then
        cat "$PUBKEY_FILE" > "$auth_keys"
        chmod 600 "$auth_keys"
        chown "$USERNAME:$USERNAME" "$auth_keys"
        echo "Added SSH public key"
    else
        echo "Warning: No SSH public key provided"
    fi
}

fix_sshd_config() {
log "Configuring SSH daemon..."
    
    # Ensure sshd_config.d directory exists
    mkdir -p "$SSHD_CONFIG_DIR"
    
    # Check and add Include directive if needed
    if ! grep -q "^Include /etc/ssh/sshd_config.d/\*.conf" "$SSHD_CONFIG"; then
        echo "Adding Include directive to main sshd_config..."
        # Backup original config
        cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup"
        # Add Include directive at the beginning of the file
        echo -e "\n#Include a custom config overiding other settings\nInclude /etc/ssh/sshd_config.d/*.conf" >> "$SSHD_CONFIG"
    fi
    
    # Create custom config file with hardened settings
    cat > "$SSHD_CUSTOM_CONFIG" << EOL
# MWCCDC Custom SSH
Port $port
# Authentication
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
MaxAuthTries 3
AuthenticationMethods publickey

# Access restrictions
AllowUsers $USERNAME
PermitEmptyPasswords no
LoginGraceTime 20
MaxSessions 2


# Logging and monitoring
LogLevel VERBOSE
PrintMotd no
PrintLastLog yes

# Environment and features
X11Forwarding no
AllowTcpForwarding no
PermitTunnel no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
Banner none
EOL

    chmod 444 "$SSHD_CONFIG"
    chmod 444 "$SSHD_CUSTOM_CONFIG"
    
    # Test configuration
    if ! sshd -t ; then
        echo "Error: Invalid SSHD configuration"
        echo "Rolling back changes..."
        if [ -f "${SSHD_CONFIG}.backup" ]; then
            mv "${SSHD_CONFIG}.backup" "$SSHD_CONFIG"
        fi
        rm -f "$SSHD_CUSTOM_CONFIG"
        exit 1
    fi
    
    echo "SSH daemon configuration updated and verified"
}

main() {
    create_user || exit 1
    add_to_sudo || exit 1
    add_ssh_key || exit 1
    fix_sshd_config || exit 1
}

main
