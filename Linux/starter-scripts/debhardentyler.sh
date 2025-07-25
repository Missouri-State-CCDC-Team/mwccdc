#!/bin/bash 
# ==============================================================================
# Script Name : debianharden-dns.sh
# Description : Configure hardening for Debian DNS/NTP Server (BIND9)
# Based on    : Tyler Olson's original script
# ==============================================================================
# Usage       : debianharden-dns.sh
# Notes       :
#   - Make sure to update the variables as needed to configure the system correctly.
# ==============================================================================
# Changelog:
#   v1.0 - Adapted for Debian DNS/NTP server with BIND9
# ==============================================================================

# Check if added as root
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root or with sudo privileges"
    exit 1
fi

username='root'
newUsername='example'
services=("bind9" "ntp")
port=55460  # SSH port

RED=$'\e[0;31m'; GREEN=$'\e[0;32m'; YELLOW=$'\e[0;33m'; BLUE=$'\e[0;34m'; NC=$'\e[0m'  # Sets the colors in use throughout the code

# Functions:
notify() { echo -e "${RED}$1${NC}"; }

software() {
    echo -e "${YELLOW} Installing software required for this system${NC}"
    apt update
    apt upgrade -y
    apt install -y bind9 bind9utils bind9-doc ntp ntpdate tmux aide ufw dnsutils net-tools
    echo -e "${GREEN} Software function completed.${NC}"
}

passchange() {
    echo -e "${YELLOW}changing root password${NC}"
    passwd
    echo -e "${YELLOW}changing password of provided username${NC}"
    passwd $username
}

backup() {
    mkdir -p /root/backit /etc/backup/ /root/backit/binaries

    for service in "${services[@]}"; do
        if [ -d "/etc/$service" ]; then
            cp -r "/etc/$service" "/root/backit/"
            echo -e "${GREEN}Backed up /etc/$service${NC}"
        elif [ -f "/etc/$service.conf" ]; then
            cp "/etc/$service.conf" "/root/backit/"
            echo -e "${GREEN}Backed up /etc/$service.conf${NC}"
        else
            echo -e "${RED}Warning: No config found for $service${NC}"
        fi
    done

    rsync -av /usr/bin/ /root/backit/binaries/ --exclude "*.tmp"  # backup binaries
    tar -czvf /root/backit/in_hardening_backup.tar.gz \
    /root \
    /etc/bind \
    /etc/ntp.conf \
    /etc/cron* \
    /etc/passwd \
    /etc/group \
    /etc/shadow \
    /etc/sudoers* \
    /etc/hosts \
    /etc/hostname \
    /etc/aliases \
    /etc/systemd \
    /etc/apt \
    /etc/resolv.conf \
    /var/cache/bind \
    /var/lib/bind \
    /etc/default/ntp

    echo -e "${YELLOW}Completed the backup${NC}"
}

find_malicious() {
    echo -e "${YELLOW}scanning for PHP malicious files${NC}\n\n"
    # Check for PHP files outside web directories (DNS servers shouldn't have PHP)
    find / -type f -name "*.php" 2>/dev/null | while read -r file; do
        # Backup the file to /root/ with a timestamp
        backup_file="/root/$(basename "$file")_$(date +%F_%T)"
        cp "$file" "$backup_file"
        rm -f "$file"            # Remove the original file

        # Log the action
        echo -e "${YELLOW}Removed potentially malicious file: $file (Backed up at $backup_file)${NC}"
    done
    
    # Check for unusual scripts in system directories
    find /etc /bin /sbin /usr/bin /usr/sbin -type f -name "*.sh" -o -name "*.pl" -o -name "*.py" | grep -v "/etc/profile.d/" | while read -r file; do
        echo -e "${YELLOW}Suspicious script found: $file${NC}"
        ls -la "$file"
    done
    
    echo "${YELLOW}Completed malicious file scan${NC}"
}

findcron() {
    echo -e "${YELLOW}Scanning for crontab entries...${NC}"

    # Locations to check
    locations=("/etc/crontab" "/etc/cron.d/*" "/var/spool/cron/crontabs/*" "/etc/cron.hourly/*" "/etc/cron.daily/*" "/etc/cron.weekly/*" "/etc/cron.monthly/*" "/etc/anacrontab")

    # Loop through each location
    for loc in "${locations[@]}"; do
        if [ -f "$loc" ] || [ -d "$loc" ]; then
            content=$(cat "$loc" 2>/dev/null)
            if [ -n "$content" ]; then
                echo -e "\n${RED}--- Found crontab at: $loc ---${NC}"
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
                echo -e "${GREEN}\n --- Crontab finished printing ---${NC}"
            fi
        fi
    done

    echo -e "${GREEN}crontab scan complete.${NC}"
}

firewall_config() {
    echo -e "${YELLOW}--- Starting to configure firewall rules for DNS/NTP server ---${NC}"
    
    # Ensure UFW is installed and enabled
    apt install -y ufw
    ufw --force enable
    
    # Reset to defaults
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow necessary services
    ufw allow $port/tcp                 # Custom SSH port
    ufw allow 53/tcp                    # DNS TCP
    ufw allow 53/udp                    # DNS UDP
    ufw allow 123/udp                   # NTP
    
    # Optional: Allow zone transfers only from specific IPs
    # Replace with your secondary DNS server IPs
    # ufw allow from 192.168.1.2 to any port 53
    
    # Optional: Allow DNS queries only from your network
    # Replace with your network
    # ufw allow from 192.168.0.0/24 to any port 53
    
    # Logging
    ufw logging on
    
    # Reload firewall
    ufw reload || notify "failed to reload ufw" >&2
    
    # List rules
    echo -e "${YELLOW}------------${NC}"
    echo -e "${BLUE}firewall rules:${NC}"
    ufw status verbose
    echo -e "${YELLOW}------------${NC}"
}

check_services() {
    echo -e "${YELLOW}Checking critical services...${NC}"
    
    # Check BIND9
    if systemctl is-active --quiet bind9; then
        echo -e "${GREEN}BIND9 DNS server is running.${NC}"
        dig @localhost -p 53 localhost
    else
        notify "BIND9 is not running, attempting to start it"
        systemctl start bind9 || notify "service bind9 failed to start, check logs" >&2
    fi
    
    # Check NTP
    if systemctl is-active --quiet ntp; then
        echo -e "${GREEN}NTP service is running.${NC}"
        ntpq -p
    else
        notify "NTP service is not running, attempting to start it"
        systemctl start ntp || notify "service ntp failed to start, check logs" >&2
    fi
    
    # Check SSH
    if nc -z localhost $port 2>/dev/null; then
        echo -e "${GREEN}SSH is running on port $port.${NC}"
    else
        notify "SSH is not running on port $port, checking standard port"
        if nc -z localhost 22 2>/dev/null; then
            echo -e "${YELLOW}SSH is running on standard port 22, not on custom port $port.${NC}"
        else
            notify "SSH is not running, attempting to start it"
            systemctl start ssh || notify "service ssh failed to start, check logs" >&2
        fi
    fi
}

ssh_config() {
    # Needed SSH Config Files
    local SSHD_CONFIG_DIR="/etc/ssh/"
    local SSHD_CONFIG="/etc/ssh/sshd_config"

    # Ensure sshd_config.d directory exists
    mkdir -p "$SSHD_CONFIG_DIR"
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup"
    # Set permissions
    chmod 444 "$SSHD_CONFIG"

    sed -i \
      -e "s/^[# ]*Port.*/Port $port/" \
      -e 's/^[# ]*PasswordAuthentication.*/PasswordAuthentication no/' \
      -e 's/^[# ]*PermitRootLogin.*/PermitRootLogin no/' \
      -e 's/^[# ]*PubkeyAuthentication.*/PubkeyAuthentication yes/' \
      -e 's/^[# ]*X11Forwarding .*/X11Forwarding no/' \
      -e 's/^[# ]*MaxAuthTries .*/MaxAuthTries 3/' \
      -e 's/^[# ]*ClientAliveMaxCount .*/ClientAliveMaxCount 2/' \
      "$SSHD_CONFIG"

    systemctl restart ssh
    echo "Configuring SSH daemon..."

    # Test configuration to see if there was errors
    if ! sshd -t ; then
        echo "Error: Invalid SSHD configuration"
        echo "Rolling back changes..."
        if [ -f "${SSHD_CONFIG}.backup" ]; then
            mv "${SSHD_CONFIG}.backup" "$SSHD_CONFIG"
        fi
        exit 1
    fi
}

fail2ban_setup() {
    echo -e "${YELLOW}Setting up fail2ban...${NC}"
    apt install -y fail2ban
    
    # Configure fail2ban
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    
    # Edit configuration to protect SSH with custom port
    cat > /etc/fail2ban/jail.d/ssh-custom.conf << EOF
[sshd]
enabled = true
port = $port
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
    
    # Restart fail2ban
    systemctl restart fail2ban
    systemctl enable fail2ban
    
    echo -e "${GREEN}fail2ban installed and configured.${NC}"
}

ntp_secure() {
    echo -e "${YELLOW}Securing NTP Server...${NC}"
    
    # Backup original config
    cp /etc/ntp.conf /etc/ntp.conf.backup
    
    # Create secure NTP configuration
    cat > /etc/ntp.conf << EOF
# /etc/ntp.conf, configuration for ntpd; see ntp.conf(5) for help

# Use Debian pool servers
server 0.debian.pool.ntp.org iburst
server 1.debian.pool.ntp.org iburst
server 2.debian.pool.ntp.org iburst
server 3.debian.pool.ntp.org iburst

# Restrict access to local networks only
# Replace with your network if needed
restrict -4 default kod notrap nomodify nopeer noquery limited
restrict -6 default kod notrap nomodify nopeer noquery limited

# Local users can query the time server
restrict 127.0.0.1
restrict ::1

# Allow specific subnets to query the timeserver
# Uncomment and modify as needed
# restrict 192.168.0.0 mask 255.255.255.0 nomodify notrap

# Location of drift file
driftfile /var/lib/ntp/ntp.drift

# Enable logging - change if needed
logfile /var/log/ntp.log
EOF

    # Check the configuration and restart
    if ntpd -n -c /etc/ntp.conf > /dev/null 2>&1; then
        echo -e "${GREEN}NTP configuration is valid.${NC}"
        systemctl restart ntp
    else
        echo -e "${RED}NTP configuration error. Restoring backup.${NC}"
        cp /etc/ntp.conf.backup /etc/ntp.conf
        systemctl restart ntp
    fi
}

main() {
    software
    passchange
    backup
    find_malicious
    findcron
    firewall_config
    ssh_config
    fail2ban_setup
    ntp_secure
    check_services
    
    echo -e "\n----\n${GREEN}Completed all basic hardening for Debian DNS/NTP server${NC}"
    echo -e "${YELLOW}Don't forget to review BIND9 and NTP configurations for your specific needs${NC}"
    echo -e "${YELLOW}Also ensure your DNS zones are properly configured in /etc/bind/${NC}"
}

main