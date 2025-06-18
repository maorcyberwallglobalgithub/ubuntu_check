#!/bin/bash



# ================================

# Ubuntu 22.04 Final Security Audit Script (3 Output Files)

# ================================



# Define output directory and files

OUTPUT_DIR="$HOME/SEND_TO_MAOR4"

mkdir -p "$OUTPUT_DIR"



AUDIT_FILE="$OUTPUT_DIR/SECURITY_AUDIT_UBUNTU22.txt"

PACKAGES_FILE="$OUTPUT_DIR/installed_software_versions.txt"

UPDATES_FILE="$OUTPUT_DIR/security_updates.txt"



echo "===============================" > "$AUDIT_FILE"

echo "  Ubuntu 22.04 Security Audit Report  " >> "$AUDIT_FILE"

echo "===============================" >> "$AUDIT_FILE"

echo "Date: $(date)" >> "$AUDIT_FILE"

echo "Hostname: $(hostname)" >> "$AUDIT_FILE"

echo -e "\n-------------------------------\n" >> "$AUDIT_FILE"



run_safely() {

    bash -c "$1" >> "$AUDIT_FILE" 2>/dev/null || echo "Error running: $1" >> "$AUDIT_FILE"

}



# OS Version

echo "=== Operating System Version ===" >> "$AUDIT_FILE"

run_safely "lsb_release -a"

run_safely "uname -r"

echo -e "\n-------------------------------\n" >> "$AUDIT_FILE"



# Security Updates - to separate file

echo "=== Security Updates (to separate file) ===" >> "$AUDIT_FILE"

apt list --upgradable 2>/dev/null > "$UPDATES_FILE"



# SSH Security Settings

echo "=== SSH Security Settings ===" >> "$AUDIT_FILE"

run_safely "grep -Ei '^PermitRootLogin|^PasswordAuthentication|^Protocol|^ClientAliveInterval|^ClientAliveCountMax' /etc/ssh/sshd_config"

echo -e "\n-------------------------------\n" >> "$AUDIT_FILE"



# Idle Timeout Settings

echo "=== Idle Timeout Settings ===" >> "$AUDIT_FILE"

[ -f /etc/profile ] && grep -E 'TMOUT=[0-9]+' /etc/profile >> "$AUDIT_FILE"

[ -f /etc/bash.bashrc ] && grep -E 'TMOUT=[0-9]+' /etc/bash.bashrc >> "$AUDIT_FILE"

run_safely "grep '^ClientAliveInterval' /etc/ssh/sshd_config"

run_safely "grep '^ClientAliveCountMax' /etc/ssh/sshd_config"

echo -e "\n-------------------------------\n" >> "$AUDIT_FILE"



# Account Lockout Policies

echo "=== Account Lockout Policies ===" >> "$AUDIT_FILE"

run_safely "grep -E 'deny|fail_interval|unlock_time|even_deny_root|root_unlock_time' /etc/security/faillock.conf"

echo -e "\n-------------------------------\n" >> "$AUDIT_FILE"



# Password Policies

echo "=== Password Policy ===" >> "$AUDIT_FILE"

run_safely "grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs"

run_safely "grep -E 'minlen|minclass|dcredit|ucredit|lcredit|ocredit|maxrepeat|difok' /etc/security/pwquality.conf"

run_safely "grep -E '^password.*pam_pwquality' /etc/pam.d/common-password"

echo -e "\n-------------------------------\n" >> "$AUDIT_FILE"



# Users with UID 0

echo "=== Users with UID 0 ===" >> "$AUDIT_FILE"

awk -F: '($3 == 0) { print $1 }' /etc/passwd >> "$AUDIT_FILE"

echo -e "\n-------------------------------\n" >> "$AUDIT_FILE"



# Sudoers Configuration

echo "=== Sudoers Configuration ===" >> "$AUDIT_FILE"

run_safely "sudo cat /etc/sudoers"

run_safely "ls -l /etc/sudoers.d/"

echo -e "\n-------------------------------\n" >> "$AUDIT_FILE"



# User and Group Configuration

echo "=== User and Group Configuration ===" >> "$AUDIT_FILE"

run_safely "getent passwd"

run_safely "getent group"

run_safely "lastlog"

run_safely "awk -F: '($2=="" || $2=="!*" || $2=="!!") {print $1 " has no password!"}' /etc/shadow"

run_safely "awk -F: '{ if ($7 == "/bin/bash") print $1 " has a shell access"; }' /etc/passwd"

echo -e "\n-------------------------------\n" >> "$AUDIT_FILE"



# Running Services and Ports

echo "=== Running Services and Ports ===" >> "$AUDIT_FILE"

run_safely "ss -tulnp"

run_safely "systemctl list-units --type=service --state=running"

run_safely "systemctl list-unit-files | grep enabled"

echo -e "\n-------------------------------\n" >> "$AUDIT_FILE"



# AppArmor Status

echo "=== AppArmor Status ===" >> "$AUDIT_FILE"

run_safely "sudo aa-status"

run_safely "sudo apparmor_status"

echo -e "\n-------------------------------\n" >> "$AUDIT_FILE"



# Installed Software Versions - separate file

dpkg-query -W -f='Software: ${Package}\nVersion: ${Version}\n---\n' > "$PACKAGES_FILE"



echo "Audit completed."

echo "Main report: $AUDIT_FILE"

echo "Installed packages: $PACKAGES_FILE"

echo "Security updates: $UPDATES_FILE"

