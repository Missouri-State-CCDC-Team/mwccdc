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
    echo "$USERNAME ALL=(ALL) ALL:ALL" >> /etc/sudoers.d/$USERNAME
    chmod 440 "$SUDOERS_FILE"
}

add_ssh_key() {
    sudo -u "$USERNAME" mkdir -p "/home/$USERNAME/.ssh"
    sudo -u "$USERNAME" chmod 700 "/home/$USERNAME/.ssh"

    echo "$PUBLIC_KEY" | sudo -u "USERNAME" tee -a "home/$USERNAME/.ssh/authorized_keys"

    sudo -u "$USERNAME" chmod 600 "/home/$USERNAME/.ssh/authorized_keys"

    echo "User $USERNAME ssh key added to their home directory"
}

fix_sshd_config() {
    sed -i 's/^#\?\(PasswordAuthentication\s\+\).*$/\1no/' /etc/ssh/sshd_config
    sed -i 's/^#\?\(PubkeyAuthentication\s\+\).*$/\1yes/' /etc/ssh/sshd_config
    echo "Restart sshd to ensure that it worked"
}

create_user()
add_to_sudo()
add_ssh_key()
fix_sshd_config()