# Wazuh Agent Role

This Ansible role installs and configures Wazuh agents for comprehensive security monitoring, intrusion detection, and compliance management. The role supports multiple operating systems and provides CCDC-optimized security monitoring configurations.

!!!!!
ROLE IS IN AN UNTESTED STATE IT WILL REQUIRE ADDITIONAL LINTING AND EDITING BEFORE FULLY FUNCTIONAL. 
CURRENTLY IN AN EXPERIMENTAL STATE THIS DOCS WAS WRITTEN BY CLAUDE

## Requirements

- Ansible 2.9+
- Target systems: RHEL/CentOS 7+, Ubuntu 16.04+, Debian 9+, Windows Server 2016+
- Network connectivity to Wazuh manager
- Sufficient disk space for logs and agent data (~1GB recommended)

## Role Variables

### Required Variables
```yaml
wazuh_server_ip: "192.168.1.100"  # IP address of Wazuh manager/server
```

### Core Configuration Variables
```yaml
# Wazuh version and connectivity
wazuh_agent_version: "4.5.2"
wazuh_agent_repo_version: "4.x"
wazuh_manager_port: 1514
wazuh_registration_port: 1515
wazuh_registration_password: ""  # Optional: set for password-based registration

# Agent behavior
wazuh_agent_register: true
wazuh_agent_service_enabled: true
wazuh_agent_verify_host_cert: false
wazuh_agent_verify_manager_cert: false
```

### Security Monitoring Configuration
```yaml
# File integrity monitoring frequency (seconds)
wazuh_agent_syscheck_frequency: 43200  # 12 hours (competition optimized)

# Security modules
wazuh_agent_rootcheck_enabled: true          # Rootkit detection
wazuh_agent_wodle_openscap_enabled: true     # SCAP compliance scanning
wazuh_agent_wodle_cis_cat_enabled: true      # CIS benchmark assessment
wazuh_agent_command_monitoring_enabled: true # Command execution monitoring
wazuh_agent_file_monitoring_enabled: true    # File integrity monitoring
wazuh_agent_syscollector_enabled: true       # System information collection

# Alert configuration
wazuh_agent_log_alert_level: 3  # Alert level (0-15, 3 = medium+)
```

### Monitoring Paths Configuration
```yaml
# Linux directories to monitor
wazuh_agent_monitored_directories:
  - { path: "/etc", check_all: "yes" }
  - { path: "/usr/bin", check_all: "yes" }
  - { path: "/var/log", check_all: "yes" }
  - { path: "/home", check_all: "no", check_sum: "yes" }

# Windows directories to monitor (Windows systems only)
wazuh_agent_windows_monitored_directories:
  - { path: "C:\\Windows\\System32", check_all: "yes" }
  - { path: "C:\\Program Files", check_all: "yes" }

# Custom log files to monitor
wazuh_agent_custom_logs:
  - "/var/log/custom-app/*.log"
  - "/opt/application/logs/error.log"

# Monitored network ports
wazuh_agent_monitored_ports:
  - protocol: "tcp"
    port_range: "22,80,443,3389"
  - protocol: "udp" 
    port_range: "53,123"
```

## Dependencies

None. This role manages its own dependencies and repository configuration.

## Example Playbook

### Basic CCDC Setup
```yaml
---
- hosts: all
  become: true
  roles:
    - wazuh_agent
  vars:
    wazuh_server_ip: "172.20.241.20"
    wazuh_agent_syscheck_frequency: 3600  # 1 hour for competition
```

### Advanced Security Monitoring
```yaml
---
- hosts: web_servers
  become: true
  roles:
    - wazuh_agent
  vars:
    wazuh_server_ip: "10.0.0.100"
    wazuh_registration_password: "{{ vault_wazuh_password }}"
    wazuh_agent_syscheck_frequency: 1800  # 30 minutes for critical servers
    wazuh_agent_monitored_directories:
      - { path: "/var/www", check_all: "yes" }
      - { path: "/etc/apache2", check_all: "yes" }
      - { path: "/var/log/apache2", check_all: "no" }
    wazuh_agent_custom_logs:
      - "/var/log/apache2/*.log"
      - "/var/www/application/logs/*.log"
```

### Windows Domain Controller Monitoring
```yaml
---
- hosts: windows_domain_controllers
  roles:
    - wazuh_agent
  vars:
    wazuh_server_ip: "10.0.0.100"
    wazuh_agent_windows_monitored_directories:
      - { path: "C:\\Windows\\SYSVOL", check_all: "yes" }
      - { path: "C:\\Windows\\System32\\config", check_all: "yes" }
    wazuh_agent_custom_logs:
      - "Application"
      - "Security" 
      - "System"
      - "Directory Service"
```

## Supported Operating Systems

### Currently Supported
- Ubuntu 16.04+
- Debian 9+
- RHEL/CentOS 7+
- Fedora 30+
- Windows Server 2016+
- Windows 10+

### OS-Specific Features
- **Linux**: Full file integrity monitoring, rootkit detection, SCAP scanning
- **Windows**: Event log monitoring, registry monitoring, Windows-specific compliance
- **All**: Network monitoring, command execution tracking, system inventory

## CCDC Competition Optimizations

### High-Frequency Monitoring
```yaml
# Competition-optimized settings
wazuh_agent_syscheck_frequency: 1800      # 30 minutes
wazuh_agent_log_alert_level: 2            # Lower threshold for alerts
wazuh_agent_rootcheck_frequency: 3600     # 1 hour rootkit checks
```

### Critical Path Monitoring
```yaml
# Focus on attack vectors common in CCDC
wazuh_agent_monitored_directories:
  - { path: "/etc/passwd", check_all: "yes" }
  - { path: "/etc/shadow", check_all: "yes" }
  - { path: "/etc/sudoers", check_all: "yes" }
  - { path: "/home", check_all: "no", check_sum: "yes" }
  - { path: "/var/www", check_all: "yes" }
  - { path: "/tmp", check_all: "no" }
  - { path: "/var/tmp", check_all: "no" }
```

### Service-Specific Monitoring
```yaml
# Web server monitoring
web_server_monitoring:
  - { path: "/etc/apache2", check_all: "yes" }
  - { path: "/etc/nginx", check_all: "yes" }
  - { path: "/var/log/apache2", check_all: "no" }

# Database monitoring
database_monitoring:
  - { path: "/etc/mysql", check_all: "yes" }
  - { path: "/var/lib/mysql", check_all: "no" }
  - { path: "/var/log/mysql", check_all: "no" }
```


## Integration with CCDC Infrastructure

### Incident Response Integration
```yaml
# Configure for rapid incident response
wazuh_agent_command_monitoring_enabled: true
wazuh_agent_monitored_commands:
  - "su"
  - "sudo" 
  - "ssh"
  - "nc"
  - "wget"
  - "curl"
```

## Role Structure

```
wazuh_agent/
├── README.md
├── defaults/main.yml         # Default variables
├── vars/
│   ├── Debian.yml           # Debian-specific variables
│   ├── RedHat.yml           # RHEL-specific variables
│   └── Windows.yml          # Windows-specific variables
├── tasks/
│   ├── main.yml             # Main task orchestration
│   ├── install-linux.yml    # Linux installation
│   ├── install-windows.yml  # Windows installation
│   ├── configure.yml        # Configuration tasks
│   └── register.yml         # Agent registration
├── templates/
│   ├── ossec.conf.j2        # Main configuration template
│   └── local_internal_options.conf.j2
├── handlers/main.yml        # Service restart handlers
└── files/                   # Static configuration files
```

## License

MIT License - See repository root for details.

## Author Information

This role was created for the Missouri State CCDC team. It incorporates security best practices and competition-specific optimizations developed through multiple CCDC seasons.