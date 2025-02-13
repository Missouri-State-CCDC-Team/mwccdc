# This will create an IR account with a pre-hashed password (CHANGE on next login) and prepare for ansible playbooks to be put onto the machine.

if [ "$EUID" -ne 0 ]; then 
    echo "This script needs to be run as sudo"
    exit 1
fi

USERNAME="CCDCIR"
PASSWORD='$6$BcYgtsE4/DaFDYRG$smzaU3PCbYSZlVu7dseVcOoyTUmqh71/dG04JLTw7DYvszm5aNiqGyXJemlOVCJ8WiDlqi7GY/2/wTyqhtCrI0'
PUBLIC_KEY=""
SUDOERS_FILE="/etc/sudoers.d/$USERNAME"

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
        echo "$PUBLIC_KEY" > "$auth_keys"
        chmod 600 "$auth_keys"
        chown "$USERNAME:$USERNAME" "$auth_keys"
        echo "Added SSH public key"
    else
        echo "Warning: No SSH public key provided"
    fi
}

fix_sshd_config() {
    sed -i 's/^#\?\(PasswordAuthentication\s\+\).*$/\1no/' /etc/ssh/sshd_config
    sed -i 's/^#\?\(PubkeyAuthentication\s\+\).*$/\1yes/' /etc/ssh/sshd_config
    echo "Restart sshd to ensure that it worked"
}

main() {
    create_user
    add_to_sudo
    add_ssh_key
    fix_sshd_config
}

main
