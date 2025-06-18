#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/SSH_Access_Control_Audit.txt"
mkdir -p "$OUTPUT_DIR"
echo -e "# SSH Access Control Audit - CIS Section 5.1\n" > "$OUTPUT_FILE"

print_section() {
  echo -e "\n# ======================================" >> "$OUTPUT_FILE"
  echo -e "# CIS Section: $1" >> "$OUTPUT_FILE"
  echo -e "# ======================================" >> "$OUTPUT_FILE"
  echo -e "\nCurrent State:\n$2" >> "$OUTPUT_FILE"
  echo -e "\nExpected Value / Best Practice:\n$3" >> "$OUTPUT_FILE"
  echo -e "\nRationale:\n$4" >> "$OUTPUT_FILE"
  echo -e "\nRecommendation:\n$5" >> "$OUTPUT_FILE"
  echo -e "\nAudit Result: $6" >> "$OUTPUT_FILE"
}

run_check() {
  local label="$1"
  local command="$2"
  local expected="$3"
  local rationale="$4"
  local recommendation="$5"

  result=$(eval "$command" 2>&1)
  [[ -z "$result" ]] && result="(No output from command)"

  if [[ "$result" =~ $expected ]]; then
    print_section "$label" "$result" "$expected" "$rationale" "$recommendation" "PASS"
  else
    print_section "$label" "$result" "$expected" "$rationale" "$recommendation" "FAIL"
  fi
}

# 5.1.1
perm_check=$(stat -c "%a %U %G" /etc/ssh/sshd_config 2>/dev/null)
expected_perm="600 root root"
rationale_perm="sshd configuration must not be modifiable or readable by unauthorized users."
recommend_perm="Run: chmod 600 /etc/ssh/sshd_config && chown root:root /etc/ssh/sshd_config"
[[ "$perm_check" == "$expected_perm" ]] && result_perm="PASS" || result_perm="FAIL"
print_section "5.1.1 Ensure permissions on /etc/ssh/sshd_config" "$perm_check" "$expected_perm" "$rationale_perm" "$recommend_perm" "$result_perm"

# 5.1.2 - 5.1.22
run_check "5.1.2 Ensure permissions on SSH private host key files" "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat -c '%n %a %U %G' {} \;" "600 root root" "Private host keys must be protected from unauthorized access." "Run: chmod 600 and chown root:root on all private SSH host key files."

run_check "5.1.3 Ensure permissions on SSH public host key files" "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat -c '%n %a %U %G' {} \;" "644 root root" "Public keys must be readable but not writable." "Run: chmod 644 and chown root:root on all public SSH host key files."

run_check "5.1.4 Ensure SSH access is limited" "grep -E '^AllowUsers|^AllowGroups|^DenyUsers|^DenyGroups' /etc/ssh/sshd_config" "." "Limit SSH access to only specific users/groups." "Use AllowUsers, AllowGroups, DenyUsers, or DenyGroups in sshd_config."

run_check "5.1.5 Ensure sshd Banner is configured" "sshd -T | grep -Ei '^banner\\s+/.*'" "/etc/issue.net" "Banner warns unauthorized users and supports legal compliance." "Set 'Banner /etc/issue.net' in /etc/ssh/sshd_config."

run_check "5.1.6 Ensure sshd Ciphers are configured" "sshd -T | grep -i ciphers" "aes(128|256)-(gcm|ctr)@openssh.com" "Using weak ciphers may allow data exposure via downgrade attacks." "Edit /etc/ssh/sshd_config to set strong Ciphers only."

run_check "5.1.7 Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured" "sshd -T | grep -Ei 'clientaliveinterval|clientalivecountmax'" "clientaliveinterval.*[1-9]|clientalivecountmax.*[1-9]" "Ensure idle SSH sessions timeout appropriately." "Set ClientAliveInterval 15 and ClientAliveCountMax 3."

run_check "5.1.8 Ensure sshd DisableForwarding is enabled" "sshd -T | grep -i disableforwarding" "yes" "Disabling forwarding reduces risk of misuse or tunneling attacks." "Set DisableForwarding yes in sshd_config."

run_check "5.1.9 Ensure sshd IgnoreRhosts is enabled" "sshd -T | grep -i ignorerhosts" "yes" "Rhosts-based authentication is insecure." "Set IgnoreRhosts yes in sshd_config."

run_check "5.1.10 Ensure sshd HostbasedAuthentication is disabled" "sshd -T | grep -i hostbasedauthentication" "no" "Host-based authentication is insecure and can be spoofed." "Set HostbasedAuthentication no in sshd_config."

run_check "5.1.11 Ensure sshd PermitEmptyPasswords is disabled" "sshd -T | grep -i permitemptypasswords" "no" "Empty passwords allow unauthorized access." "Set PermitEmptyPasswords no in sshd_config."

run_check "5.1.12 Ensure sshd PermitRootLogin is disabled" "sshd -T | grep -i permitrootlogin" "no" "Disabling direct root login enhances system security." "Set PermitRootLogin no in sshd_config."

run_check "5.1.13 Ensure sshd PermitUserEnvironment is disabled" "sshd -T | grep -i permituserenvironment" "no" "User environment options may allow privilege escalation." "Set PermitUserEnvironment no in sshd_config."

run_check "5.1.14 Ensure only approved MAC algorithms are used" "sshd -T | grep -i macs" "hmac-(sha2-512|sha2-256)-etm@openssh.com" "Weak MACs may allow tampering with SSH traffic." "Use strong MACs in sshd_config."

run_check "5.1.15 Ensure sshd LoginGraceTime is set to one minute or less" "sshd -T | grep -i logingracetime" "(30|60)" "Short grace time limits unauthorized access attempts." "Set LoginGraceTime 60 in sshd_config."

run_check "5.1.16 Ensure sshd LogLevel is appropriate" "sshd -T | grep -i loglevel" "VERBOSE|INFO" "Proper log level ensures sufficient auditing." "Set LogLevel INFO or VERBOSE in sshd_config."

run_check "5.1.17 Ensure sshd MaxAuthTries is set to 4 or less" "sshd -T | grep -i maxauthtries" "[1-4]" "Limits brute-force password guessing." "Set MaxAuthTries 4 in sshd_config."

run_check "5.1.18 Ensure sshd MaxStartups is configured" "sshd -T | grep -i maxstartups" "." "Limits concurrent unauthenticated SSH connections." "Set MaxStartups to reasonable values like 10:30:60."

run_check "5.1.19 Ensure sshd MaxSessions is limited" "sshd -T | grep -i maxsessions" "[1-9]" "Limits abuse of multiplexed SSH sessions." "Set MaxSessions to a reasonable number like 10."

run_check "5.1.20 Ensure sshd AllowTcpForwarding is disabled" "sshd -T | grep -i allowtcpforwarding" "no" "Disabling TCP forwarding reduces misuse risk." "Set AllowTcpForwarding no in sshd_config."

run_check "5.1.21 Ensure sshd X11Forwarding is disabled" "sshd -T | grep -i x11forwarding" "no" "X11 forwarding can be abused to capture keystrokes." "Set X11Forwarding no in sshd_config."

run_check "5.1.22 Ensure sshd UsePAM is enabled" "sshd -T | grep -i usepam" "yes" "PAM supports local authentication policies and controls." "Set UsePAM yes in sshd_config."

echo -e "\n\nAudit complete. Report saved to: $OUTPUT_FILE"

#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/Privilege_Escalation_Audit.txt"
mkdir -p "$OUTPUT_DIR"
echo -e "# Privilege Escalation Audit - CIS Section 5.2\n" > "$OUTPUT_FILE"

print_section() {
  echo -e "\n# ======================================" >> "$OUTPUT_FILE"
  echo -e "# CIS Section: $1" >> "$OUTPUT_FILE"
  echo -e "# ======================================" >> "$OUTPUT_FILE"
  echo -e "\nCurrent State:\n$2" >> "$OUTPUT_FILE"
  echo -e "\nExpected Value / Best Practice:\n$3" >> "$OUTPUT_FILE"
  echo -e "\nRationale:\n$4" >> "$OUTPUT_FILE"
  echo -e "\nRecommendation:\n$5" >> "$OUTPUT_FILE"
  echo -e "\nAudit Result: $6" >> "$OUTPUT_FILE"
}

run_check() {
  local label="$1"
  local command="$2"
  local expected="$3"
  local rationale="$4"
  local recommendation="$5"

  result=$(eval "$command" 2>&1)
  [[ -z "$result" ]] && result="(No output from command)"

  if [[ "$result" =~ $expected ]]; then
    print_section "$label" "$result" "$expected" "$rationale" "$recommendation" "PASS"
  else
    print_section "$label" "$result" "$expected" "$rationale" "$recommendation" "FAIL"
  fi
}

# 5.2.1 Ensure sudo is installed
run_check "5.2.1 Ensure sudo is installed" \
  "dpkg-query -s sudo &>/dev/null && echo 'sudo is installed' || dpkg-query -s sudo-ldap &>/dev/null && echo 'sudo-ldap is installed' || echo 'Neither sudo nor sudo-ldap is installed'" \
  "sudo is installed|sudo-ldap is installed" \
  "sudo enables granular control of privileged commands and auditing." \
  "Install sudo using: apt install sudo"

# 5.2.2 Ensure sudo commands use pty
run_check "5.2.2 Ensure sudo commands use pty" \
  "grep -rPi '^\s*Defaults\s+([^#\n\r]+,)?use_pty' /etc/sudoers*" \
  "Defaults use_pty" \
  "Using pty prevents background process abuse with sudo." \
  "Edit sudoers with visudo and add: Defaults use_pty"

# 5.2.3 Ensure sudo log file exists
run_check "5.2.3 Ensure sudo log file exists" \
  "grep -rPsi 'Defaults\s+logfile\s*=\s*\"?/var/log/sudo.log\"?' /etc/sudoers*" \
  "/var/log/sudo.log" \
  "Logging sudo commands supports better auditing and forensics." \
  "Add Defaults logfile=\"/var/log/sudo.log\" to sudoers with visudo"

# 5.2.4 Ensure users must provide password for privilege escalation
run_check "5.2.4 Ensure users must provide password for privilege escalation" \
  "grep -r '^[^#].*NOPASSWD' /etc/sudoers*" \
  "^$" \
  "Preventing passwordless sudo reduces unauthorized escalation risk." \
  "Remove NOPASSWD tags from all sudoers files using visudo"

# 5.2.5 Ensure re-authentication for privilege escalation is not disabled globally
run_check "5.2.5 Ensure re-authentication is not disabled" \
  "grep -r '^[^#].*!authenticate' /etc/sudoers*" \
  "^$" \
  "Ensure re-authentication is required for sudo privilege elevation." \
  "Remove any !authenticate directives from sudoers files"

# 5.2.6 Ensure sudo authentication timeout is configured correctly
run_check "5.2.6 Ensure sudo authentication timeout is <= 15" \
  "grep -roP 'timestamp_timeout=\\K[0-9]*' /etc/sudoers*" \
  "^([0-9]|1[0-5])$" \
  "Limit sudo credential caching to max 15 minutes." \
  "Set timestamp_timeout=15 in sudoers using visudo"

# 5.2.7 Ensure access to the su command is restricted
run_check "5.2.7 Ensure access to su is restricted" \
  "grep -Pi '^\s*auth\s+(required|requisite)\s+pam_wheel.so\s+.*(use_uid).*group=' /etc/pam.d/su" \
  "pam_wheel.so.*use_uid.*group=" \
  "Restricting su to specific group improves control and auditing." \
  "Edit /etc/pam.d/su to include: auth required pam_wheel.so use_uid group=sugroup"

echo -e "\n\nAudit complete. Report saved to: $OUTPUT_FILE"

#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/PAM_Modules_Audit.txt"
mkdir -p "$OUTPUT_DIR"
echo -e "# PAM Modules Audit - CIS Section 5.3\n" > "$OUTPUT_FILE"

print_section() {
  echo -e "\n# ======================================" >> "$OUTPUT_FILE"
  echo -e "# CIS Section: $1" >> "$OUTPUT_FILE"
  echo -e "# ======================================" >> "$OUTPUT_FILE"
  echo -e "\nCurrent State:\n$2" >> "$OUTPUT_FILE"
  echo -e "\nExpected Value / Best Practice:\n$3" >> "$OUTPUT_FILE"
  echo -e "\nRationale:\n$4" >> "$OUTPUT_FILE"
  echo -e "\nRecommendation:\n$5" >> "$OUTPUT_FILE"
  echo -e "\nAudit Result: $6" >> "$OUTPUT_FILE"
}

run_version_check() {
  local label="$1"
  local pkg="$2"
  local min_version="$3"
  local rationale="$4"
  local recommendation="$5"

  status=$(dpkg-query -s "$pkg" 2>/dev/null | grep -P '^(Status|Version)\b')
  version=$(echo "$status" | grep Version | awk '{print $2}')
  current=$(echo "$status")

  if dpkg --compare-versions "$version" ge "$min_version"; then
    print_section "$label" "$current" "$pkg >= $min_version" "$rationale" "$recommendation" "PASS"
  else
    print_section "$label" "$current" "$pkg >= $min_version" "$rationale" "$recommendation" "FAIL"
  fi
}

# 5.3.1.1 Ensure latest version of libpam-runtime is installed
run_version_check \
  "5.3.1.1 Ensure latest version of libpam-runtime is installed" \
  "libpam-runtime" \
  "1.5.2-6" \
  "Updated versions of PAM include necessary security and functionality improvements." \
  "Run: apt upgrade libpam-runtime"

# 5.3.1.2 Ensure libpam-modules is installed
run_version_check \
  "5.3.1.2 Ensure libpam-modules is installed" \
  "libpam-modules" \
  "1.5.2-6" \
  "libpam-modules provides essential functionality for PAM authentication." \
  "Run: apt upgrade libpam-modules"

# 5.3.1.3 Ensure libpam-pwquality is installed
run_version_check \
  "5.3.1.3 Ensure libpam-pwquality is installed" \
  "libpam-pwquality" \
  "1.4.4-1" \
  "libpam-pwquality enforces strong password policies to resist brute force attacks." \
  "Run: apt install libpam-pwquality"

echo -e "\n\nAudit complete. Report saved to: $OUTPUT_FILE"

#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/PAM_Profiles_Audit.txt"
mkdir -p "$OUTPUT_DIR"
echo -e "# PAM Profiles Audit - CIS Section 5.3.2\n" > "$OUTPUT_FILE"

print_section() {
  echo -e "\n# ======================================" >> "$OUTPUT_FILE"
  echo -e "# CIS Section: $1" >> "$OUTPUT_FILE"
  echo -e "# ======================================" >> "$OUTPUT_FILE"
  echo -e "\nCurrent State:\n$2" >> "$OUTPUT_FILE"
  echo -e "\nExpected Value / Best Practice:\n$3" >> "$OUTPUT_FILE"
  echo -e "\nRationale:\n$4" >> "$OUTPUT_FILE"
  echo -e "\nRecommendation:\n$5" >> "$OUTPUT_FILE"
  echo -e "\nAudit Result: $6" >> "$OUTPUT_FILE"
}

run_check() {
  local label="$1"
  local command="$2"
  local expected="$3"
  local rationale="$4"
  local recommendation="$5"

  result=$(eval "$command")
  if [[ "$result" =~ $expected ]]; then
    print_section "$label" "$result" "$expected" "$rationale" "$recommendation" "PASS"
  else
    print_section "$label" "$result" "$expected" "$rationale" "$recommendation" "FAIL"
  fi
}

# 5.3.2.1 Ensure pam_unix module is enabled
run_check \
  "5.3.2.1 Ensure pam_unix module is enabled" \
  "grep -P -- '\\bpam_unix\\.so\\b' /etc/pam.d/common-{account,session,auth,password}" \
  "pam_unix\\.so" \
  "Ensure system uses standard Unix authentication mechanisms." \
  "Run: pam-auth-update --enable unix"

# 5.3.2.2 Ensure pam_faillock module is enabled
run_check \
  "5.3.2.2 Ensure pam_faillock module is enabled" \
  "grep -P -- '\\bpam_faillock\\.so\\b' /etc/pam.d/common-{auth,account}" \
  "pam_faillock\\.so" \
  "Mitigates brute-force password attacks by locking accounts after repeated failures." \
  "Create faillock profiles and run pam-auth-update --enable faillock && --enable faillock_notify"

# 5.3.2.3 Ensure pam_pwquality module is enabled
run_check \
  "5.3.2.3 Ensure pam_pwquality module is enabled" \
  "grep -P -- '\\bpam_pwquality\\.so\\b' /etc/pam.d/common-password" \
  "pam_pwquality\\.so" \
  "Enforces strong password complexity rules." \
  "If not present, create pwquality profile and run: pam-auth-update --enable pwquality"

# 5.3.2.4 Ensure pam_pwhistory module is enabled
run_check \
  "5.3.2.4 Ensure pam_pwhistory module is enabled" \
  "grep -P -- '\\bpam_pwhistory\\.so\\b' /etc/pam.d/common-password" \
  "pam_pwhistory\\.so" \
  "Prevents users from reusing previous passwords." \
  "If not present, create pwhistory profile and run: pam-auth-update --enable pwhistory"

echo -e "\n\nAudit complete. Report saved to: $OUTPUT_FILE"

#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/pam_faillock_audit.txt"
mkdir -p "$OUTPUT_DIR"
echo -e "# PAM faillock Audit - CIS Section 5.3.3\n" > "$OUTPUT_FILE"

print_section() {
  echo -e "\n# ======================================" >> "$OUTPUT_FILE"
  echo -e "# CIS Section: $1" >> "$OUTPUT_FILE"
  echo -e "# ======================================" >> "$OUTPUT_FILE"
  echo -e "\nCurrent State:\n$2" >> "$OUTPUT_FILE"
  echo -e "\nExpected Value / Best Practice:\n$3" >> "$OUTPUT_FILE"
  echo -e "\nRationale:\n$4" >> "$OUTPUT_FILE"
  echo -e "\nRecommendation:\n$5" >> "$OUTPUT_FILE"
  echo -e "\nAudit Result: $6" >> "$OUTPUT_FILE"
}

run_check() {
  local label="$1"
  local command="$2"
  local expected="$3"
  local rationale="$4"
  local recommendation="$5"

  result=$(eval "$command" 2>/dev/null)
  if [[ -z "$result" ]]; then
    result="No matching configuration found or command returned no output"
  fi

  if [[ "$result" =~ $expected ]]; then
    print_section "$label" "$result" "$expected" "$rationale" "$recommendation" "PASS"
  else
    print_section "$label" "$result" "$expected" "$rationale" "$recommendation" "FAIL"
  fi
}

# 5.3.3.1.1 - Ensure password failed attempts lockout is configured
run_check \
  "5.3.3.1.1 Ensure password failed attempts lockout is configured" \
  "grep -Pi -- '^\\h*deny\\h*=\\h*[0-9]+' /etc/security/faillock.conf" \
  "deny\\h*=\\h*[1-5]" \
  "Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks." \
  "Edit /etc/security/faillock.conf and set: deny = 5"

# 5.3.3.1.2 - Ensure password unlock time is configured
run_check \
  "5.3.3.1.2 Ensure password unlock time is configured" \
  "grep -Pi -- '^\\h*unlock_time\\h*=\\h*[0-9]+' /etc/security/faillock.conf" \
  "unlock_time\\h*=\\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})" \
  "Unlocking user after lockout should be delayed enough to mitigate DoS attacks." \
  "Edit /etc/security/faillock.conf and set: unlock_time = 900"

# 5.3.3.1.3 - Ensure password failed attempts lockout includes root account
run_check \
  "5.3.3.1.3 Ensure password failed attempts lockout includes root account" \
  "grep -Pi -- '^(\\h*even_deny_root|\\h*root_unlock_time\\h*=\\h*[0-9]+)' /etc/security/faillock.conf" \
  "even_deny_root|root_unlock_time\\h*=\\h*([6-9][0-9]|[1-9][0-9]{2,})" \
  "Root account should also be protected from brute-force login attempts." \
  "Edit /etc/security/faillock.conf and set even_deny_root and root_unlock_time = 60 or more"

echo -e "\nAudit complete. Report saved to: $OUTPUT_FILE"

#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/configure_pwquality.txt"
mkdir -p "$OUTPUT_DIR"
echo -e "# =============================\n# CIS Section 5.3.3.2 - PAM Password Quality\n# =============================" > "$OUTPUT_FILE"

# Function to write audit block
audit_pwquality_setting() {
    local setting="$1"
    local description="$2"
    local good_pattern="$3"
    local bad_pattern="$4"
    local file_glob="$5"

    echo -e "\n---" >> "$OUTPUT_FILE"
    echo "Setting: $setting" >> "$OUTPUT_FILE"
    echo -e "Description:\n$description\n" >> "$OUTPUT_FILE"

    local current_state=$(grep -Psi -- "^\h*$setting\h*=\h*.*" $file_glob 2>/dev/null)
    if [[ -z "$current_state" ]]; then
        current_state="No setting found for $setting."
    fi
    echo -e "Current State:\n$current_state\n" >> "$OUTPUT_FILE"

    if grep -Psiq -- "$good_pattern" $file_glob 2>/dev/null && ! grep -Psiq -- "$bad_pattern" /etc/pam.d/common-password 2>/dev/null; then
        echo "Audit Result: **PASS**" >> "$OUTPUT_FILE"
    else
        echo "Audit Result: **FAIL**" >> "$OUTPUT_FILE"
    fi
}

CONF_GLOB="/etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"

# difok
audit_pwquality_setting \
    "difok" \
    "Number of characters in the new password that must not be present in the old password. Recommended value: >=2." \
    "^\h*difok\h*=\h*([2-9]|[1-9][0-9]+)\b" \
    "^\h*password\h+.*pam_pwquality\\.so.*difok\h*=\h*[01]\b" \
    "$CONF_GLOB"

# minlen
audit_pwquality_setting \
    "minlen" \
    "Minimum password length. Recommended: 14 or more." \
    "^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b" \
    "^\h*password\h+.*pam_pwquality\\.so.*minlen\h*=\h*(\d|1[0-3])\b" \
    "$CONF_GLOB"

# maxrepeat
audit_pwquality_setting \
    "maxrepeat" \
    "Maximum number of allowed same consecutive characters in a new password. Recommended: <=3 and !=0." \
    "^\h*maxrepeat\h*=\h*[1-3]\b" \
    "^\h*password\h+.*pam_pwquality\\.so.*maxrepeat\h*=\h*(0|[4-9]|[1-9][0-9]+)\b" \
    "$CONF_GLOB"

# maxsequence
audit_pwquality_setting \
    "maxsequence" \
    "Maximum length of monotonic character sequences in the password. Recommended: <=3 and !=0." \
    "^\h*maxsequence\h*=\h*[1-3]\b" \
    "^\h*password\h+.*pam_pwquality\\.so.*maxsequence\h*=\h*(0|[4-9]|[1-9][0-9]+)\b" \
    "$CONF_GLOB"

# dictcheck
audit_pwquality_setting \
    "dictcheck" \
    "Check for dictionary words in the password. Should not be disabled (dictcheck=0)." \
    "^\h*dictcheck\h*=\h*[^0]\b" \
    "^\h*password\h+.*pam_pwquality\\.so.*dictcheck\h*=\h*0\b" \
    "$CONF_GLOB"

# enforcing
audit_pwquality_setting \
    "enforcing" \
    "Whether password quality checks are enforced (1) or only warnings shown (0). Should be 1." \
    "^\h*enforcing\h*=\h*1\b" \
    "^\h*password\h+.*pam_pwquality\\.so.*enforcing\h*=\h*0\b" \
    "$CONF_GLOB"

# enforce_for_root
audit_pwquality_setting \
    "enforce_for_root" \
    "Ensure password quality checks are enforced for root user." \
    "^\h*enforce_for_root\b" \
    "" \
    "$CONF_GLOB"

#!/usr/bin/env bash


#!/usr/bin/env bash

# =============================
# Section 5.3.3.3 - Configure pam_pwhistory module
# =============================

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/configure_pam_pwhistory_module.txt"

mkdir -p "$OUTPUT_DIR"

write_section() {
    echo -e "\n---\nCIS Section: $1\n---\n" >> "$OUTPUT_FILE"
}

write_rationale() {
    echo -e "Rationale:\n$1\n" >> "$OUTPUT_FILE"
}

write_recommendation() {
    echo -e "Recommendation:\n$1\n" >> "$OUTPUT_FILE"
}

write_best_practice() {
    echo -e "Best Practice:\n$1\n" >> "$OUTPUT_FILE"
}

write_result() {
    echo -e "Audit Result: $1\n" >> "$OUTPUT_FILE"
}

write_current_state() {
    echo -e "Current State:\n$1\n" >> "$OUTPUT_FILE"
}

# 5.3.3.3.1 Ensure password history remember is configured
write_section "5.3.3.3.1 – Ensure password history remember is configured"

write_rationale "Requiring users not to reuse their passwords makes it less likely that an attacker will be able to guess the password or use a compromised password."

write_best_practice "Ensure pam_pwhistory.so includes remember=24 or more in /etc/pam.d/common-password."

REMEMBER_LINE=$(grep -Psi '^\h*password\h+[^#

]+\h+pam_pwhistory\.so\h+([^#

]+\h+)?remember=\d+' /etc/pam.d/common-password)

if [[ $REMEMBER_LINE == *"remember="* ]]; then
    write_current_state "$REMEMBER_LINE"
    if echo "$REMEMBER_LINE" | grep -q "remember=[2-9][4-9]\|remember=[3-9][0-9]"; then
        write_result "**PASS**"
    else
        write_result "**FAIL**"
    fi
else
    write_current_state "pam_pwhistory.so not configured with remember option."
    write_result "**FAIL**"
fi

write_recommendation "Edit the pam_pwhistory.so line in /usr/share/pam-configs/pwhistory to include remember=24 or more, and run pam-auth-update --enable pwhistory."

# 5.3.3.3.2 Ensure password history is enforced for the root user
write_section "5.3.3.3.2 – Ensure password history is enforced for the root user"

write_rationale "Requiring password history enforcement for the root user reduces risk of repeated use of compromised passwords."

write_best_practice "Ensure pam_pwhistory.so includes enforce_for_root."

ENFORCE_LINE=$(grep -Psi '^\h*password\h+[^#

]+\h+pam_pwhistory\.so\h+([^#

]+\h+)?enforce_for_root' /etc/pam.d/common-password)

if [[ $ENFORCE_LINE == *"enforce_for_root"* ]]; then
    write_current_state "$ENFORCE_LINE"
    write_result "**PASS**"
else
    write_current_state "pam_pwhistory.so not configured with enforce_for_root."
    write_result "**FAIL**"
fi

write_recommendation "Edit the pam_pwhistory.so line to include enforce_for_root and run pam-auth-update --enable pwhistory."

# 5.3.3.3.3 Ensure pam_pwhistory includes use_authtok
write_section "5.3.3.3.3 – Ensure pam_pwhistory includes use_authtok"

write_rationale "use_authtok allows consistent handling of new passwords across PAM modules."

write_best_practice "Ensure pam_pwhistory.so includes use_authtok."

AUTHTOK_LINE=$(grep -Psi '^\h*password\h+[^#

]+\h+pam_pwhistory\.so\h+([^#

]+\h+)?use_authtok' /etc/pam.d/common-password)

if [[ $AUTHTOK_LINE == *"use_authtok"* ]]; then
    write_current_state "$AUTHTOK_LINE"
    write_result "**PASS**"
else
    write_current_state "pam_pwhistory.so not configured with use_authtok."
    write_result "**FAIL**"
fi

write_recommendation "Edit the pam_pwhistory.so line to include use_authtok and run pam-auth-update --enable pwhistory."

#!/usr/bin/env bash

# =============================
# Section 5.3.3.4 - Configure pam_unix module
# =============================

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/configure_pam_unix_module.txt"

echo "# =============================" > "$OUTPUT_FILE"
echo "# CIS Section 5.3.3.4 - Configure pam_unix module" >> "$OUTPUT_FILE"
echo "# =============================" >> "$OUTPUT_FILE"

check_pam_unix_nullok() {
    echo -e "\n---\nCIS Section: 5.3.3.4.1 – Ensure pam_unix does not include nullok\n---\n" >> "$OUTPUT_FILE"
    echo "Rationale: Using a strong password is essential to protecting data." >> "$OUTPUT_FILE"
    echo "Best Practice: Do not include 'nullok' in pam_unix.so lines." >> "$OUTPUT_FILE"
    echo "Recommendation: Remove 'nullok' argument from pam_unix.so if present." >> "$OUTPUT_FILE"

    result=$(grep -PH -- '^[^#\n\r]+pam_unix\.so.*nullok' /etc/pam.d/common-{password,auth,account,session,session-noninteractive})
    if [ -z "$result" ]; then
        echo -e "\nCurrent State: No 'nullok' found in pam_unix.so configuration." >> "$OUTPUT_FILE"
        echo "Audit Result: **PASS**" >> "$OUTPUT_FILE"
    else
        echo -e "\nCurrent State:\n$result" >> "$OUTPUT_FILE"
        echo "Audit Result: **FAIL**" >> "$OUTPUT_FILE"
    fi
}

check_pam_unix_remember() {
    echo -e "\n---\nCIS Section: 5.3.3.4.2 – Ensure pam_unix does not include remember\n---\n" >> "$OUTPUT_FILE"
    echo "Rationale: The pam_pwhistory module should be used instead of pam_unix remember option." >> "$OUTPUT_FILE"
    echo "Best Practice: Use pam_pwhistory for password history enforcement." >> "$OUTPUT_FILE"
    echo "Recommendation: Remove 'remember=n' argument from pam_unix.so if present." >> "$OUTPUT_FILE"

    result=$(grep -PH -- '^[^#\n\r]+pam_unix\.so.*remember=\d+' /etc/pam.d/common-{password,auth,account,session,session-noninteractive})
    if [ -z "$result" ]; then
        echo -e "\nCurrent State: No 'remember=n' found in pam_unix.so configuration." >> "$OUTPUT_FILE"
        echo "Audit Result: **PASS**" >> "$OUTPUT_FILE"
    else
        echo -e "\nCurrent State:\n$result" >> "$OUTPUT_FILE"
        echo "Audit Result: **FAIL**" >> "$OUTPUT_FILE"
    fi
}

check_pam_unix_hashing() {
    echo -e "\n---\nCIS Section: 5.3.3.4.3 – Ensure pam_unix includes a strong password hashing algorithm\n---\n" >> "$OUTPUT_FILE"
    echo "Rationale: Strong hashes protect passwords more effectively." >> "$OUTPUT_FILE"
    echo "Best Practice: Use 'yescrypt' or 'sha512' hashing algorithms." >> "$OUTPUT_FILE"
    echo "Recommendation: Ensure pam_unix.so includes 'yescrypt' or 'sha512' in password section." >> "$OUTPUT_FILE"

    result=$(grep -PH -- '^[^#\n\r]+pam_unix\.so.*(sha512|yescrypt)' /etc/pam.d/common-password)
    if [ -n "$result" ]; then
        echo -e "\nCurrent State:\n$result" >> "$OUTPUT_FILE"
        echo "Audit Result: **PASS**" >> "$OUTPUT_FILE"
    else
        echo -e "\nCurrent State: No strong password hashing algorithm found (sha512 or yescrypt not present)." >> "$OUTPUT_FILE"
        echo "Audit Result: **FAIL**" >> "$OUTPUT_FILE"
    fi
}

check_pam_unix_use_authtok() {
    echo -e "\n---\nCIS Section: 5.3.3.4.4 – Ensure pam_unix includes use_authtok\n---\n" >> "$OUTPUT_FILE"
    echo "Rationale: Allows consistency when stacking password modules." >> "$OUTPUT_FILE"
    echo "Best Practice: use_authtok should be present in pam_unix.so in password section." >> "$OUTPUT_FILE"
    echo "Recommendation: Add 'use_authtok' to pam_unix.so line in /etc/pam.d/common-password." >> "$OUTPUT_FILE"

    result=$(grep -PH -- '^[^#\n\r]+pam_unix\.so.*use_authtok' /etc/pam.d/common-password)
    if [ -n "$result" ]; then
        echo -e "\nCurrent State:\n$result" >> "$OUTPUT_FILE"
        echo "Audit Result: **PASS**" >> "$OUTPUT_FILE"
    else
        echo -e "\nCurrent State: use_authtok not found in pam_unix.so password section." >> "$OUTPUT_FILE"
        echo "Audit Result: **FAIL**" >> "$OUTPUT_FILE"
    fi
}

check_pam_unix_nullok
check_pam_unix_remember
check_pam_unix_hashing
check_pam_unix_use_authtok

#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/configure_user_accounts_and_env.txt"

write_section() {
    echo -e "\n---\nCIS Section: $1\n---\n" >> "$OUTPUT_FILE"
}

write_result() {
    echo -e "Current State:\n$1\n\nAudit Result: $2\n" >> "$OUTPUT_FILE"
}

write_best_practice() {
    echo -e "Best Practice:\n$1\n" >> "$OUTPUT_FILE"
}

write_rationale() {
    echo -e "Rationale:\n$1\n" >> "$OUTPUT_FILE"
}

write_recommendation() {
    echo -e "Recommendation:\n$1\n" >> "$OUTPUT_FILE"
}

# 5.4.1.1 Ensure password expiration is configured
write_section "5.4.1.1 – Ensure password expiration is configured"
MAX_DAYS=$(grep -Pi -- '^\s*PASS_MAX_DAYS\s+\d+' /etc/login.defs | awk '{print $2}')
USER_MAX_DAYS=$(awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1)print "User: " $1 ", PASS_MAX_DAYS: " $5}' /etc/shadow)
if [[ "$MAX_DAYS" -le 365 && -z "$USER_MAX_DAYS" ]]; then
    write_result "PASS_MAX_DAYS is $MAX_DAYS" "PASS"
else
    write_result "PASS_MAX_DAYS is $MAX_DAYS; Issues found: $USER_MAX_DAYS" "FAIL"
fi
write_rationale "Limiting password lifetime reduces the window of opportunity for attackers."
write_best_practice "Set PASS_MAX_DAYS to 365 or less"
write_recommendation "Edit /etc/login.defs and set PASS_MAX_DAYS 365"

# 5.4.1.2 Ensure minimum password age is configured
write_section "5.4.1.2 – Ensure minimum password age is configured"
MIN_DAYS=$(grep -Pi -- '^\s*PASS_MIN_DAYS\s+\d+' /etc/login.defs | awk '{print $2}')
USER_MIN_DAYS=$(awk -F: '($2~/^\$.+\$/) {if($4 < 1)print "User: " $1 ", PASS_MIN_DAYS: " $4}' /etc/shadow)
if [[ "$MIN_DAYS" -ge 1 && -z "$USER_MIN_DAYS" ]]; then
    write_result "PASS_MIN_DAYS is $MIN_DAYS" "PASS"
else
    write_result "PASS_MIN_DAYS is $MIN_DAYS; Issues found: $USER_MIN_DAYS" "FAIL"
fi
write_rationale "Prevents rapid password change to circumvent reuse policies."
write_best_practice "Set PASS_MIN_DAYS to 1 or more"
write_recommendation "Edit /etc/login.defs and set PASS_MIN_DAYS 1"

# 5.4.1.3 Ensure password expiration warning days is configured
write_section "5.4.1.3 – Ensure password expiration warning days is configured"
WARN_DAYS=$(grep -Pi -- '^\s*PASS_WARN_AGE\s+\d+' /etc/login.defs | awk '{print $2}')
USER_WARN_DAYS=$(awk -F: '($2~/^\$.+\$/) {if($6 < 7)print "User: " $1 ", PASS_WARN_AGE: " $6}' /etc/shadow)
if [[ "$WARN_DAYS" -ge 7 && -z "$USER_WARN_DAYS" ]]; then
    write_result "PASS_WARN_AGE is $WARN_DAYS" "PASS"
else
    write_result "PASS_WARN_AGE is $WARN_DAYS; Issues found: $USER_WARN_DAYS" "FAIL"
fi
write_rationale "Gives users time to update passwords securely before expiration."
write_best_practice "Set PASS_WARN_AGE to 7 or more"
write_recommendation "Edit /etc/login.defs and set PASS_WARN_AGE 7"

# 5.4.1.4 Ensure strong password hashing algorithm is configured
write_section "5.4.1.4 – Ensure strong password hashing algorithm is configured"
HASH_METHOD=$(grep -Pi -- '^\s*ENCRYPT_METHOD\s+(SHA512|YESCRYPT)' /etc/login.defs | awk '{print $2}')
if [[ "$HASH_METHOD" == "SHA512" || "$HASH_METHOD" == "YESCRYPT" ]]; then
    write_result "ENCRYPT_METHOD is $HASH_METHOD" "PASS"
else
    write_result "ENCRYPT_METHOD is $HASH_METHOD" "FAIL"
fi
write_rationale "Stronger hash algorithms protect passwords against brute-force attacks."
write_best_practice "Use SHA512 or YESCRYPT"
write_recommendation "Edit /etc/login.defs and set ENCRYPT_METHOD YESCRYPT"

# 5.4.1.5 Ensure inactive password lock is configured
write_section "5.4.1.5 – Ensure inactive password lock is configured"
INACTIVE_DEFAULT=$(useradd -D | grep INACTIVE | cut -d= -f2)
USER_INACTIVE=$(awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)print "User: " $1 ", INACTIVE: " $7}' /etc/shadow)
if [[ "$INACTIVE_DEFAULT" -le 45 && -z "$USER_INACTIVE" ]]; then
    write_result "Default INACTIVE is $INACTIVE_DEFAULT" "PASS"
else
    write_result "Default INACTIVE is $INACTIVE_DEFAULT; Issues found: $USER_INACTIVE" "FAIL"
fi
write_rationale "Inactive accounts are vulnerable to unnoticed compromises."
write_best_practice "Set default INACTIVE to 45 or less"
write_recommendation "Run: useradd -D -f 45"

# 5.4.1.6 Ensure all users last password change date is in the past
write_section "5.4.1.6 – Ensure all users last password change date is in the past"
OUTDATED_USERS=""
while IFS= read -r user; do
    last_change=$(date -d "$(chage --list "$user" | grep '^Last password change' | cut -d: -f2 | grep -v 'never$')" +%s 2>/dev/null)
    now=$(date +%s)
    if [[ "$last_change" -gt "$now" ]]; then
        OUTDATED_USERS+="User: "$user" last password change is in the future
"
    fi
done < <(awk -F: '$2~/^\$.+\$/{print $1}' /etc/shadow)
if [[ -z "$OUTDATED_USERS" ]]; then
    write_result "All last password change dates are valid." "PASS"
else
    write_result "$OUTDATED_USERS" "FAIL"
fi
write_rationale "Future-dated password changes can bypass password expiration policies."
write_best_practice "Ensure all password change dates are in the past"
write_recommendation "Use 'chage' to correct future-dated changes"

# =============================
# CIS Section 5.4.2 - Root and System Accounts - Audit
# =============================

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/cis_5.4.2_root_system_accounts_audit.txt"

mkdir -p "$OUTPUT_DIR"
echo "# CIS Section 5.4.2 - Root and System Accounts - Audit" > "$OUTPUT_FILE"

# ========== 5.4.2.1 Ensure root is the only UID 0 account ==========
echo -e "\n---\nCIS Section: 5.4.2.1 – Ensure root is the only UID 0 account\n---" >> "$OUTPUT_FILE"
echo -e "Rationale:\nOnly the root user should have UID 0 to minimize attack surface." >> "$OUTPUT_FILE"
echo -e "Audit:" >> "$OUTPUT_FILE"
UID0_USERS=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
echo -e "Current State:\n$UID0_USERS" >> "$OUTPUT_FILE"
if [[ "$UID0_USERS" == "root" ]]; then
  echo -e "Audit Result: PASS" >> "$OUTPUT_FILE"
else
  echo -e "Audit Result: FAIL" >> "$OUTPUT_FILE"
fi

# ========== 5.4.2.2 Ensure root is the only GID 0 account ==========
echo -e "\n---\nCIS Section: 5.4.2.2 – Ensure root is the only GID 0 account\n---" >> "$OUTPUT_FILE"
echo -e "Rationale:\nOnly root should have GID 0." >> "$OUTPUT_FILE"
GID0_USERS=$(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4==0) {print $1":"$4}' /etc/passwd)
echo -e "Current State:\n$GID0_USERS" >> "$OUTPUT_FILE"
if [[ "$GID0_USERS" == "root:0" ]]; then
  echo -e "Audit Result: PASS" >> "$OUTPUT_FILE"
else
  echo -e "Audit Result: FAIL" >> "$OUTPUT_FILE"
fi

# ========== 5.4.2.3 Ensure group root is the only GID 0 group ==========
echo -e "\n---\nCIS Section: 5.4.2.3 – Ensure group root is the only GID 0 group\n---" >> "$OUTPUT_FILE"
echo -e "Rationale:\nOnly the group 'root' should have GID 0." >> "$OUTPUT_FILE"
GID0_GROUPS=$(awk -F: '$3==0 {print $1":"$3}' /etc/group)
echo -e "Current State:\n$GID0_GROUPS" >> "$OUTPUT_FILE"
if [[ "$GID0_GROUPS" == "root:0" ]]; then
  echo -e "Audit Result: PASS" >> "$OUTPUT_FILE"
else
  echo -e "Audit Result: FAIL" >> "$OUTPUT_FILE"
fi

# ========== 5.4.2.4 Ensure root password is set ==========
echo -e "\n---\nCIS Section: 5.4.2.4 – Ensure root password is set\n---" >> "$OUTPUT_FILE"
echo -e "Rationale:\nA password must be set for root to secure access." >> "$OUTPUT_FILE"
ROOT_PW_STATUS=$(passwd -S root | awk '{print $2}')
if [[ "$ROOT_PW_STATUS" =~ ^P ]]; then
  echo -e "Current State:\nUser: \"root\" Password is set" >> "$OUTPUT_FILE"
  echo -e "Audit Result: PASS" >> "$OUTPUT_FILE"
else
  echo -e "Current State:\nUser: \"root\" Password is NOT set" >> "$OUTPUT_FILE"
  echo -e "Audit Result: FAIL" >> "$OUTPUT_FILE"
fi

# ========== 5.4.2.5 Ensure root path integrity ==========
echo -e "\n---\nCIS Section: 5.4.2.5 – Ensure root path integrity\n---" >> "$OUTPUT_FILE"
echo -e "Rationale:\nEnsure root's PATH is secure to avoid execution of rogue binaries." >> "$OUTPUT_FILE"
OUTPUT2=""
PMASK="0022"
MAXPERM=$(printf '%o' $(( 0777 & ~$PMASK )))
ROOT_PATH=$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)
IFS=":" read -ra PATHS <<< "$ROOT_PATH"
[[ "$ROOT_PATH" =~ :: ]] && OUTPUT2+=$'\n - root\'s path contains an empty directory (::)'
[[ "$ROOT_PATH" =~ :$ ]] && OUTPUT2+=$'\n - root\'s path contains a trailing (:)'
[[ "$ROOT_PATH" =~ (^|:)\.(:|$) ]] && OUTPUT2+=$'\n - root\'s path contains current directory (.)'
for path in "${PATHS[@]}"; do
  if [ -d "$path" ]; then
    read -r fmode fown <<< $(stat -Lc '%#a %U' "$path")
    [[ "$fown" != "root" ]] && OUTPUT2+=$'\n - Directory: "$path" is owned by "$fown"'
    [ $(( fmode & PMASK )) -gt 0 ] && OUTPUT2+=$'\n - Directory: "$path" mode is "$fmode" and should be "$MAXPERM"'
  else
    OUTPUT2+=$'\n - "$path" is not a directory'
  fi
done
if [ -z "$OUTPUT2" ]; then
  echo -e "Current State:\nRoot's path is correctly configured" >> "$OUTPUT_FILE"
  echo -e "Audit Result: PASS" >> "$OUTPUT_FILE"
else
  echo -e "Current State:\n$OUTPUT2" >> "$OUTPUT_FILE"
  echo -e "Audit Result: FAIL" >> "$OUTPUT_FILE"
fi

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/cis_5.4.2_root_and_system_accounts.txt"

echo "# CIS Section 5.4.2 - Configure root and system accounts and environment" > "$OUTPUT_FILE"

write_section() {
  echo -e "\n---\nCIS Section: $1\n---" >> "$OUTPUT_FILE"
  echo -e "Rationale:\n$2\n" >> "$OUTPUT_FILE"
}

write_result() {
  echo -e "Current State:\n$1\n" >> "$OUTPUT_FILE"
  echo -e "Audit Result: **$2**\n" >> "$OUTPUT_FILE"
}

#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/root_accounts_audit.txt"
mkdir -p "$OUTPUT_DIR"
echo -e "# Root Account and Environment Audit - CIS Section 5.4.2\n" > "$OUTPUT_FILE"

print_section() {
  echo -e "\n# ======================================" >> "$OUTPUT_FILE"
  echo -e "# CIS Section: $1" >> "$OUTPUT_FILE"
  echo -e "# ======================================" >> "$OUTPUT_FILE"
  echo -e "\nCurrent State:\n$2" >> "$OUTPUT_FILE"
  echo -e "\nExpected Value / Best Practice:\n$3" >> "$OUTPUT_FILE"
  echo -e "\nRationale:\n$4" >> "$OUTPUT_FILE"
  echo -e "\nRecommendation:\n$5" >> "$OUTPUT_FILE"
  echo -e "\nAudit Result: $6" >> "$OUTPUT_FILE"
}

# 5.4.2.6 Ensure root user umask is configured
umask_check=$(grep -Psi -- '^[[:space:]]*umask[[:space:]]+(([0-7]{3})|([0-7]{4}))' /root/.bash_profile /root/.bashrc 2>/dev/null)
expected_umask="umask 027 or more restrictive"
rationale_umask="Setting a secure value for umask ensures files/directories have restricted default permissions."
recommend_umask="Edit /root/.bash_profile and /root/.bashrc and ensure umask is set to 027 or more restrictive."
if [[ -z "$umask_check" ]]; then
  result_umask="PASS"
  current_state_umask="No insecure umask found."
else
  result_umask="FAIL"
  current_state_umask="$umask_check"
fi
print_section "5.4.2.6 Ensure root user umask is configured" "$current_state_umask" "$expected_umask" "$rationale_umask" "$recommend_umask" "$result_umask"

# 5.4.2.7 Ensure system accounts do not have a valid login shell
valid_shells="^($(awk -F/ '$NF != "nologin"' /etc/shells | sed -rn '/^\//{s,/,\\/,g;p}' | paste -s -d '|' -))$"
system_shell_check=$(awk -v pat="$valid_shells" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<"'$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)'" || $3==65534) && $(NF) ~ pat) {print $1":"$7}' /etc/passwd)
expected_shell="Only exempted system accounts (root, halt, sync, shutdown, nfsnobody) may have valid shells"
rationale_shell="System accounts should not have interactive shells to prevent abuse."
recommend_shell="Run 'usermod -s $(command -v nologin) <user>' for any account listed."
if [[ -z "$system_shell_check" ]]; then
  result_shell="PASS"
  current_shell_state="All system accounts properly configured."
else
  result_shell="FAIL"
  current_shell_state="$system_shell_check"
fi
print_section "5.4.2.7 Ensure system accounts do not have a valid login shell" "$current_shell_state" "$expected_shell" "$rationale_shell" "$recommend_shell" "$result_shell"

# 5.4.2.8 Ensure accounts without valid login shell are locked
nonlogin_users=$(awk -v pat="$valid_shells" -F: '($1 != "root" && $(NF) !~ pat) {print $1}' /etc/passwd)
nonlocked=""
while IFS= read -r user; do
  [[ -z "$user" ]] && continue
  locked=$(passwd -S "$user" 2>/dev/null | awk '{print $2}')
  [[ "$locked" != L* ]] && nonlocked+="$user\n"
done <<< "$nonlogin_users"
expected_lock="Accounts without login shell must be locked"
rationale_lock="Non-login service accounts should be locked to prevent misuse."
recommend_lock="Run 'usermod -L <user>' for each user listed."
if [[ -z "$nonlocked" ]]; then
  result_lock="PASS"
  current_state_lock="All non-login accounts are locked."
else
  result_lock="FAIL"
  current_state_lock="$nonlocked"
fi
print_section "5.4.2.8 Ensure accounts without valid login shell are locked" "$current_state_lock" "$expected_lock" "$rationale_lock" "$recommend_lock" "$result_lock"

echo -e "\nAudit complete. Results saved to: $OUTPUT_FILE"

# =============================
#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/user_env_audit.txt"

# Start writing report
{
echo "# ============================="
echo "# CIS Section 5.4.3 - Configure User Default Environment"
echo "# ============================="

# 5.4.3.1 Ensure nologin is not listed in /etc/shells
echo -e "\n## 5.4.3.1 Ensure nologin is not listed in /etc/shells"
echo "Description: /etc/shells lists valid login shells. Including '/nologin' here can mistakenly identify service accounts as valid users."
echo -n "Audit Result: "
if grep -q '/nologin\b' /etc/shells 2>/dev/null; then
    echo "FAIL"
    echo "Current State: /nologin FOUND in /etc/shells"
else
    echo "PASS"
    echo "Current State: /nologin NOT found"
fi
echo "Remediation: Remove any lines that include '/nologin' from /etc/shells."

# 5.4.3.2 Ensure default user shell timeout is configured
echo -e "\n## 5.4.3.2 Ensure default user shell timeout is configured"
echo "Description: Set TMOUT to automatically timeout idle shells after 900 seconds (15 minutes)."
echo "Audit Instructions: Manually check for TMOUT=900, readonly TMOUT, and export TMOUT in:"
echo "  - /etc/profile"
echo "  - /etc/profile.d/*.sh"
echo "  - /etc/bashrc"
echo "Remediation: Add the following lines to a file like /etc/profile.d/tmout.sh:"
echo "  TMOUT=900"
echo "  readonly TMOUT"
echo "  export TMOUT"

# 5.4.3.3 Ensure default user umask is configured
echo -e "\n## 5.4.3.3 Ensure default user umask is configured"
echo "Description: Ensure the umask is globally set to 027 or more restrictive (e.g., 027, 077)."
echo "Audit Instructions: Check the following files for umask setting:"
echo "  - /etc/profile"
echo "  - /etc/profile.d/*.sh"
echo "  - /etc/bashrc"
echo "  - /etc/login.defs"
echo "  - /etc/default/login"
echo "Remediation: Add this line to /etc/profile.d/secure_umask.sh:"
echo "  umask 027"
echo "Or update relevant files to reflect this restriction."

echo -e "\n# End of audit section 5.4.3"
} > "$OUTPUT_FILE"

echo "Audit complete. Results saved to: $OUTPUT_FILE"

#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/aide_audit_summary.txt"
mkdir -p "$OUTPUT_DIR"
echo "# CIS Section 6.1 - Filesystem Integrity Checking" > "$OUTPUT_FILE"
echo "# ==============================================" >> "$OUTPUT_FILE"

# 6.1.1 Ensure AIDE is installed
echo -e "\n## 6.1.1 Ensure AIDE is installed\n" >> "$OUTPUT_FILE"
echo "Description: AIDE is used to detect unauthorized changes to files." >> "$OUTPUT_FILE"
echo "Audit:" >> "$OUTPUT_FILE"
echo "Command: dpkg-query -s aide && dpkg-query -s aide-common" >> "$OUTPUT_FILE"

if dpkg-query -s aide &>/dev/null && dpkg-query -s aide-common &>/dev/null; then
  echo -e "Current State: AIDE and aide-common are installed." >> "$OUTPUT_FILE"
  echo "Audit Result: PASS" >> "$OUTPUT_FILE"
else
  echo -e "Current State: AIDE or aide-common is missing." >> "$OUTPUT_FILE"
  echo "Audit Result: FAIL" >> "$OUTPUT_FILE"
fi

echo "Expected: AIDE and aide-common should be installed." >> "$OUTPUT_FILE"
echo "Rationale: Ensures file integrity verification is possible." >> "$OUTPUT_FILE"
echo "Recommendation: Run 'apt install aide aide-common'" >> "$OUTPUT_FILE"

# 6.1.2 Ensure filesystem integrity is regularly checked
echo -e "\n## 6.1.2 Ensure filesystem integrity is regularly checked\n" >> "$OUTPUT_FILE"
echo "Description: Schedule AIDE to run regularly." >> "$OUTPUT_FILE"

cron_check=$(grep -Prs '^([^#\n\r]+\h+)?(/usr/s?bin/|^\h*)aide(\.wrapper)?\h+(--(check|update))' /etc/cron.* /etc/crontab /var/spool/cron/)
timer_check=$(systemctl is-enabled aidecheck.timer 2>/dev/null)

if [[ -n "$cron_check" ]] || [[ "$timer_check" == "enabled" ]]; then
  echo "Current State: AIDE check is scheduled." >> "$OUTPUT_FILE"
  echo "Audit Result: PASS" >> "$OUTPUT_FILE"
else
  echo "Current State: AIDE check is NOT scheduled." >> "$OUTPUT_FILE"
  echo "Audit Result: FAIL" >> "$OUTPUT_FILE"
fi

echo "Expected: AIDE should run via cron or systemd timer daily." >> "$OUTPUT_FILE"
echo "Rationale: Periodic integrity checks are essential for security." >> "$OUTPUT_FILE"
echo "Recommendation: Configure cron or systemd to run 'aide.wrapper --update'" >> "$OUTPUT_FILE"

# 6.1.3 Ensure cryptographic mechanisms are used to protect audit tools
echo -e "\n## 6.1.3 Ensure cryptographic mechanisms protect audit tools\n" >> "$OUTPUT_FILE"
echo "Description: Use SHA512, acl, xattrs, etc. in AIDE config to monitor audit tools." >> "$OUTPUT_FILE"

AIDE_CONF="/etc/aide/aide.conf"
required_flags="p+i+n+u+g+s+b+acl+xattrs+sha512"
fail_flag=0

for bin in /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/augenrules; do
  if grep -q "$bin.*$required_flags" "$AIDE_CONF" 2>/dev/null; then
    echo "Audit Tool $bin: OK" >> "$OUTPUT_FILE"
  else
    echo "Audit Tool $bin: MISSING or incomplete flags" >> "$OUTPUT_FILE"
    fail_flag=1
  fi
done

if [[ $fail_flag -eq 0 ]]; then
  echo "Audit Result: PASS" >> "$OUTPUT_FILE"
else
  echo "Audit Result: FAIL" >> "$OUTPUT_FILE"
fi

echo "Expected: All audit tools should include: $required_flags" >> "$OUTPUT_FILE"
echo "Rationale: Ensures audit tools themselves are not tampered with." >> "$OUTPUT_FILE"
echo "Recommendation: Edit $AIDE_CONF and add lines with appropriate monitoring flags for each tool." >> "$OUTPUT_FILE"

echo -e "\nAudit complete. Results saved to: $OUTPUT_FILE"

#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/configure_journald.txt"
mkdir -p "$OUTPUT_DIR"

{
echo "# ============================="
echo "# CIS Section 6.2.1 - Configure Journald"
echo "# ============================="

audit_section() {
    local section="$1"
    local description="$2"
    local rationale="$3"
    local audit_cmd="$4"
    local expected="$5"
    local recommendation="$6"

    echo -e "\n## $section" >> "$OUTPUT_FILE"
    echo -e "**Description:**\n$description\n" >> "$OUTPUT_FILE"
    echo -e "**Expected Value:**\n$expected\n" >> "$OUTPUT_FILE"
    echo -e "**Rationale:**\n$rationale\n" >> "$OUTPUT_FILE"
    echo -e "**Current State:**" >> "$OUTPUT_FILE"
    eval "$audit_cmd" >> "$OUTPUT_FILE" 2>&1
    echo -e "\n**Audit Result:**" >> "$OUTPUT_FILE"
    if eval "$audit_cmd" | grep -q "$expected"; then
        echo "PASS" >> "$OUTPUT_FILE"
    else
        echo "FAIL" >> "$OUTPUT_FILE"
    fi
    echo -e "\n**Recommendation:**\n$recommendation\n---\n" >> "$OUTPUT_FILE"
}

audit_section "6.2.1.1.1 Ensure journald service is enabled and active" \
"Ensure that systemd-journald is enabled and running." \
"If journald is not active, system logs will not be collected." \
"systemctl is-active systemd-journald.service" \
"active" \
"systemctl unmask systemd-journald.service && systemctl start systemd-journald.service"

audit_section "6.2.1.1.2 Ensure journald log file access is configured" \
"Ensure log file permissions are set to 0640 or more restrictive." \
"Protect sensitive log files from unauthorized access." \
"find /var/log/journal -type f -exec stat -c '%a %n' {} +" \
"640" \
"Use chmod to set permissions and chown if needed."

audit_section "6.2.1.1.3 Ensure journald log file rotation is configured" \
"Ensure journald rotates logs to avoid large file sizes." \
"Manage log size for storage and readability." \
"grep -Ei 'SystemMaxUse|SystemKeepFree|RuntimeMaxUse|RuntimeKeepFree|MaxFileSec' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null" \
"SystemMaxUse" \
"Set appropriate values in /etc/systemd/journald.conf or .conf.d files"

audit_section "6.2.1.1.4 Ensure journald ForwardToSyslog is disabled" \
"Ensure journald does not forward logs to syslog." \
"Prevent redundancy or exposure via other logging systems." \
"grep -Ei '^\s*ForwardToSyslog=\s*no' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null" \
"ForwardToSyslog=no" \
"Add 'ForwardToSyslog=no' under [Journal] section in journald.conf"

audit_section "6.2.1.1.5 Ensure journald Storage is configured" \
"Ensure journald log storage is persistent." \
"Allow logs to persist after reboots for forensic use." \
"grep -Ei '^\s*Storage=\s*persistent' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null" \
"Storage=persistent" \
"Add 'Storage=persistent' under [Journal] section in journald.conf"

audit_section "6.2.1.1.6 Ensure journald Compress is configured" \
"Ensure journald compresses logs." \
"Prevent logs from consuming too much disk space." \
"grep -Ei '^\s*Compress=\s*yes' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null" \
"Compress=yes" \
"Add 'Compress=yes' under [Journal] section in journald.conf"

} > "$OUTPUT_FILE"

#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/configure_journald_remote.txt"
echo "# =============================" > "$OUTPUT_FILE"
echo "# CIS Section 6.2.1.2 - Configure systemd-journal-remote" >> "$OUTPUT_FILE"
echo "# =============================" >> "$OUTPUT_FILE"

write_section() {
    echo -e "\n---\n$1\n---\n" >> "$OUTPUT_FILE"
}

write_entry() {
    local desc="$1"
    local rationale="$2"
    local current_state="$3"
    local result="$4"
    local recommendation="$5"
    local expected="$6"

    echo -e "Description:\n$desc\n" >> "$OUTPUT_FILE"
    echo -e "Rationale:\n$rationale\n" >> "$OUTPUT_FILE"
    echo -e "Expected State:\n$expected\n" >> "$OUTPUT_FILE"
    echo -e "Current State:\n$current_state\n" >> "$OUTPUT_FILE"
    echo -e "Audit Result:\n$result\n" >> "$OUTPUT_FILE"
    echo -e "Remediation:\n$recommendation\n" >> "$OUTPUT_FILE"
    echo -e "---\n" >> "$OUTPUT_FILE"
}

# 6.2.1.2.1 - Ensure systemd-journal-remote is installed
desc="Verify systemd-journal-remote is installed."
rationale="Remote log storage protects logs from local tampering."
expected="systemd-journal-remote should be installed."
dpkg-query -s systemd-journal-remote &>/dev/null
if [ $? -eq 0 ]; then
    current="systemd-journal-remote is installed"
    result="PASS"
else
    current="systemd-journal-remote is NOT installed"
    result="FAIL"
fi
recommendation="Run: apt install systemd-journal-remote"
write_section "6.2.1.2.1 Ensure systemd-journal-remote is installed"
write_entry "$desc" "$rationale" "$current" "$result" "$recommendation" "$expected"

# 6.2.1.2.3 - Ensure systemd-journal-upload is enabled and active
desc="Ensure systemd-journal-upload is enabled and active"
rationale="Active log upload service ensures forwarding logs to remote host"
expected="systemd-journal-upload should be enabled and active"
enabled=$(systemctl is-enabled systemd-journal-upload.service 2>/dev/null)
active=$(systemctl is-active systemd-journal-upload.service 2>/dev/null)
if [ "$enabled" = "enabled" ] && [ "$active" = "active" ]; then
    current="Enabled: $enabled, Active: $active"
    result="PASS"
else
    current="Enabled: $enabled, Active: $active"
    result="FAIL"
fi
recommendation="Run: systemctl unmask systemd-journal-upload && systemctl --now enable systemd-journal-upload"
write_section "6.2.1.2.3 Ensure systemd-journal-upload is enabled and active"
write_entry "$desc" "$rationale" "$current" "$result" "$recommendation" "$expected"

# 6.2.1.2.4 - Ensure systemd-journal-remote service is not in use
desc="Ensure systemd-journal-remote is NOT enabled or active"
rationale="Clients should not be configured to receive logs"
expected="systemd-journal-remote.service and .socket should be disabled/inactive"
enabled_check=$(systemctl is-enabled systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null | grep -P -- '^enabled')
active_check=$(systemctl is-active systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null | grep -P -- '^active')
if [ -z "$enabled_check" ] && [ -z "$active_check" ]; then
    current="systemd-journal-remote.socket and service are not enabled or active"
    result="PASS"
else
    current="Enabled: $enabled_check; Active: $active_check"
    result="FAIL"
fi
recommendation="Run: systemctl stop systemd-journal-remote.socket systemd-journal-remote.service && systemctl mask systemd-journal-remote.socket systemd-journal-remote.service"
write_section "6.2.1.2.4 Ensure systemd-journal-remote service is not in use"
write_entry "$desc" "$rationale" "$current" "$result" "$recommendation" "$expected"

#!/usr/bin/env bash
# CIS Section 6.2.2.1 - Ensure access to all logfiles has been configured
# This script performs an audit of /var/log permissions and outputs results

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/audit_logfile_permissions.txt"
mkdir -p "$OUTPUT_DIR"

{
    echo "# CIS Section 6.2.2.1 - Ensure access to all logfiles has been configured"
    echo "# -----------------------------------------------------------"
    echo "Description: Log files must have appropriate ownership and permissions to ensure confidentiality and integrity."
    echo "Expected Value: /var/log/* files should be owned by root or syslog and be group-owned by adm, utmp, etc. Permissions should be strict (0640 or stricter)."
    echo "Rationale: Protects log integrity and confidentiality from unauthorized access or tampering."
    echo "-------------------------------------------"

    l_output2=""
    l_uidmin="$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"
    declare -a a_file=()
    while IFS= read -r -d $'\0' l_file; do
        [ -e "$l_file" ] && a_file+=("$(stat -Lc '%n^%#a^%U^%u^%G^%g' "$l_file")")
    done < <(find -L /var/log -type f \( -perm /0137 -o ! -user root -o ! -group root \) -print0)

    file_test_chk() {
        l_op2=""
        if [ $(( $l_mode & $perm_mask )) -gt 0 ]; then
            l_op2="$l_op2\n - Mode: \"$l_mode\" should be \"$maxperm\" or more restrictive"
        fi
        if [[ ! "$l_user" =~ $l_auser ]]; then
            l_op2="$l_op2\n - Owned by: \"$l_user\" and should be owned by \"${l_auser//|/ or }\""
        fi
        if [[ ! "$l_group" =~ $l_agroup ]]; then
            l_op2="$l_op2\n - Group owned by: \"$l_group\" and should be group owned by \"${l_agroup//|/ or }\""
        fi
        [ -n "$l_op2" ] && l_output2="$l_output2\n - File: \"$l_fname\" is:$l_op2\n"
    }

    for stat_entry in "${a_file[@]}"; do
        IFS="^" read -r l_fname l_mode l_user l_uid l_group l_gid <<< "$stat_entry"
        l_bname="$(basename "$l_fname")"
        case "$l_bname" in
            lastlog*|wtmp*|btmp*|README)
                perm_mask=73; maxperm="0644"; l_auser="root"; l_agroup="(root|utmp)";;
            secure|auth.log|syslog|messages)
                perm_mask=95; maxperm="0640"; l_auser="(root|syslog)"; l_agroup="(root|adm)";;
            SSSD|sssd)
                perm_mask=79; maxperm="0660"; l_auser="(root|SSSD)"; l_agroup="(root|SSSD)";;
            gdm|gdm3)
                perm_mask=79; maxperm="0660"; l_auser="root"; l_agroup="(root|gdm|gdm3)";;
            *.journal|*.journal~)
                perm_mask=95; maxperm="0640"; l_auser="root"; l_agroup="(root|systemd-journal)";;
            *)
                perm_mask=95; maxperm="0640"; l_auser="(root|syslog)"; l_agroup="(root|adm)";;
        esac
        file_test_chk
    done

    if [ -z "$l_output2" ]; then
        echo -e "\nAudit Result: PASS\nAll files in /var/log/ have appropriate permissions and ownership."
    else
        echo -e "\nAudit Result: FAIL\n$l_output2"
        echo -e "\nRecommendation: Run the remediation script provided by CIS or correct permissions and ownership as per policy."
    fi
} > "$OUTPUT_FILE"

#!/usr/bin/env bash

REPORT_PATH="$HOME/SEND_TO_MAOR3/auditd_summary.txt"
mkdir -p "$(dirname "$REPORT_PATH")"
echo "# Auditd Configuration Summary" > "$REPORT_PATH"
echo "# ===============================" >> "$REPORT_PATH"

# === Check 1: Is auditd installed ===
echo -e "\n## Check 1: auditd installed" >> "$REPORT_PATH"
if dpkg -s auditd &>/dev/null; then
    echo "Auditd is installed: PASS" >> "$REPORT_PATH"
else
    echo "Auditd is not installed: FAIL" >> "$REPORT_PATH"
    echo "Remediation: sudo apt install auditd" >> "$REPORT_PATH"
fi

# === Check 2: Is auditd enabled on boot ===
echo -e "\n## Check 2: auditd enabled on boot" >> "$REPORT_PATH"
if systemctl is-enabled auditd &>/dev/null; then
    echo "Auditd is enabled: PASS" >> "$REPORT_PATH"
else
    echo "Auditd is not enabled: FAIL" >> "$REPORT_PATH"
    echo "Remediation: sudo systemctl enable auditd" >> "$REPORT_PATH"
fi

# === Check 3: auditd service is active ===
echo -e "\n## Check 3: auditd service is active" >> "$REPORT_PATH"
if systemctl is-active auditd &>/dev/null; then
    echo "Auditd is running: PASS" >> "$REPORT_PATH"
else
    echo "Auditd is not running: FAIL" >> "$REPORT_PATH"
    echo "Remediation: sudo systemctl start auditd" >> "$REPORT_PATH"
fi

# === Check 4: Audit log directory permissions ===
echo -e "\n## Check 4: Audit log directory (/var/log/audit) permissions" >> "$REPORT_PATH"
if [ -d /var/log/audit ]; then
    perms=$(stat -c "%a" /var/log/audit)
    owner=$(stat -c "%U:%G" /var/log/audit)
    echo "Permissions: $perms, Owner: $owner" >> "$REPORT_PATH"
    if [[ "$perms" == "700" && "$owner" == "root:root" ]]; then
        echo "PASS" >> "$REPORT_PATH"
    else
        echo "FAIL" >> "$REPORT_PATH"
        echo "Remediation: chmod 700 /var/log/audit && chown root:root /var/log/audit" >> "$REPORT_PATH"
    fi
else
    echo "/var/log/audit does not exist: FAIL" >> "$REPORT_PATH"
fi

# === Check 5: Basic audit rules exist ===
echo -e "\n## Check 5: Basic audit rules exist" >> "$REPORT_PATH"
if grep -q "\-a always,exit" /etc/audit/audit.rules; then
    echo "Found basic syscall rules: PASS" >> "$REPORT_PATH"
else
    echo "Syscall rules missing: FAIL" >> "$REPORT_PATH"
    echo "Remediation: Define rules under /etc/audit/rules.d/*.rules and run augenrules --load" >> "$REPORT_PATH"
fi

# === Check 6: UID_MIN detection ===
echo -e "\n## Check 6: UID_MIN detection" >> "$REPORT_PATH"
uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
echo "System UID_MIN: $uid_min" >> "$REPORT_PATH"

# === Summary ===
echo -e "\nAudit complete. Results saved to: $REPORT_PATH"

#!/usr/bin/env bash

# ===== Setup Output File =====
OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/audit_data_retention.txt"
mkdir -p "$OUTPUT_DIR"
echo "CIS 6.3.2 - Configure Audit Data Retention" > "$OUTPUT_FILE"

# ===== 6.3.2.1 Ensure audit log storage size is configured =====
echo -e "\n6.3.2.1 Ensure audit log storage size is configured" >> "$OUTPUT_FILE"
max_log_file=$(grep -Po '^\h*max_log_file\h*=\h*\d+' /etc/audit/auditd.conf | awk -F= '{print $2}' | xargs)
if [[ "$max_log_file" =~ ^[0-9]+$ ]] && [ "$max_log_file" -ge 20 ]; then
  echo "Current State: max_log_file = $max_log_file" >> "$OUTPUT_FILE"
  echo "Expected: Site policy (e.g. ≥ 20MB)" >> "$OUTPUT_FILE"
  echo "Audit Result: PASS" >> "$OUTPUT_FILE"
else
  echo "Current State: max_log_file = $max_log_file" >> "$OUTPUT_FILE"
  echo "Expected: Site policy (e.g. ≥ 20MB)" >> "$OUTPUT_FILE"
  echo "Audit Result: FAIL" >> "$OUTPUT_FILE"
  echo "Remediation: Set max_log_file = <MB> in /etc/audit/auditd.conf" >> "$OUTPUT_FILE"
fi

# ===== 6.3.2.2 Ensure audit logs are not automatically deleted =====
echo -e "\n6.3.2.2 Ensure audit logs are not automatically deleted" >> "$OUTPUT_FILE"
log_action=$(grep -Po '^\h*max_log_file_action\h*=\h*\w+' /etc/audit/auditd.conf | awk -F= '{print $2}' | xargs)
if [[ "$log_action" == "keep_logs" ]]; then
  echo "Current State: max_log_file_action = $log_action" >> "$OUTPUT_FILE"
  echo "Expected: keep_logs" >> "$OUTPUT_FILE"
  echo "Audit Result: PASS" >> "$OUTPUT_FILE"
else
  echo "Current State: max_log_file_action = $log_action" >> "$OUTPUT_FILE"
  echo "Expected: keep_logs" >> "$OUTPUT_FILE"
  echo "Audit Result: FAIL" >> "$OUTPUT_FILE"
  echo "Remediation: Set max_log_file_action = keep_logs" >> "$OUTPUT_FILE"
fi

# ===== 6.3.2.3 Ensure system is disabled when audit logs are full =====
echo -e "\n6.3.2.3 Ensure system is disabled when audit logs are full" >> "$OUTPUT_FILE"
full_action=$(grep -Po '^\h*disk_full_action\h*=\h*\w+' /etc/audit/auditd.conf | awk -F= '{print $2}' | xargs)
error_action=$(grep -Po '^\h*disk_error_action\h*=\h*\w+' /etc/audit/auditd.conf | awk -F= '{print $2}' | xargs)

if [[ "$full_action" =~ ^(halt|single)$ ]]; then
  echo "disk_full_action = $full_action (✅ PASS)" >> "$OUTPUT_FILE"
else
  echo "disk_full_action = $full_action (❌ FAIL)" >> "$OUTPUT_FILE"
  echo "Remediation: Set disk_full_action = halt OR single" >> "$OUTPUT_FILE"
fi

if [[ "$error_action" =~ ^(halt|single|syslog)$ ]]; then
  echo "disk_error_action = $error_action (✅ PASS)" >> "$OUTPUT_FILE"
else
  echo "disk_error_action = $error_action (❌ FAIL)" >> "$OUTPUT_FILE"
  echo "Remediation: Set disk_error_action = halt OR single OR syslog" >> "$OUTPUT_FILE"
fi

# ===== 6.3.2.4 Ensure system warns when audit logs are low on space =====
echo -e "\n6.3.2.4 Ensure system warns when audit logs are low on space" >> "$OUTPUT_FILE"
space_action=$(grep -Po '^\h*space_left_action\h*=\h*\w+' /etc/audit/auditd.conf | awk -F= '{print $2}' | xargs)
admin_action=$(grep -Po '^\h*admin_space_left_action\h*=\h*\w+' /etc/audit/auditd.conf | awk -F= '{print $2}' | xargs)

if [[ "$space_action" =~ ^(email|exec|single|halt)$ ]]; then
  echo "space_left_action = $space_action (✅ PASS)" >> "$OUTPUT_FILE"
else
  echo "space_left_action = $space_action (❌ FAIL)" >> "$OUTPUT_FILE"
  echo "Remediation: Set space_left_action = email | exec | single | halt" >> "$OUTPUT_FILE"
fi

if [[ "$admin_action" =~ ^(single|halt)$ ]]; then
  echo "admin_space_left_action = $admin_action (✅ PASS)" >> "$OUTPUT_FILE"
else
  echo "admin_space_left_action = $admin_action (❌ FAIL)" >> "$OUTPUT_FILE"
  echo "Remediation: Set admin_space_left_action = single | halt" >> "$OUTPUT_FILE"
fi

echo -e "\nAudit completed. Results saved to: $OUTPUT_FILE"

#!/usr/bin/env bash

# =============================
# CIS Benchmark - Section 6.3.3 - Audit Rules
# =============================

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/audit_6.3.3_rules_summary.txt"
mkdir -p "$OUTPUT_DIR"
echo "# CIS Section 6.3.3 - Auditd Rules Check" > "$OUTPUT_FILE"

write_section() {
    echo -e "\n---\n$1\n---" >> "$OUTPUT_FILE"
}

write_result() {
    if eval "$2"; then
        echo -e "Audit Result: **PASS**\n" >> "$OUTPUT_FILE"
    else
        echo -e "Audit Result: **FAIL**\n" >> "$OUTPUT_FILE"
    fi
}

# 6.3.3.1 - Changes to sudoers
write_section "6.3.3.1 - Ensure events that modify the sudo log file are collected"
write_result "Check sudo log file audit" "auditctl -l | grep -q '/etc/sudoers'"

# 6.3.3.2 - sudo usage
write_section "6.3.3.2 - Ensure sudo commands are audited"
write_result "Check sudo command audit" "auditctl -l | grep -q '/var/log/sudo.log'"

# 6.3.3.3 - sudoers modifications
write_section "6.3.3.3 - Ensure modifications to sudoers are audited"
write_result "Check sudoers.d audit" "auditctl -l | grep -q '/etc/sudoers.d'"

# 6.3.3.4 - date and time changes
write_section "6.3.3.4 - Ensure date and time changes are audited"
write_result "Check time change audit" "auditctl -l | grep -E -q 'adjtimex|settimeofday|clock_settime'"

# 6.3.3.5 - time-zone changes
write_section "6.3.3.5 - Ensure time zone is audited"
write_result "Check timezone audit" "auditctl -l | grep -q '/etc/localtime'"

# 6.3.3.6 - network environment
write_section "6.3.3.6 - Ensure network environment is audited"
write_result "Check network audit" "auditctl -l | grep -E -q '/etc/hosts|/etc/hostname|/etc/networks'"

# 6.3.3.7 - network state
write_section "6.3.3.7 - Ensure network state is audited"
write_result "Check network state audit" "auditctl -l | grep -q '/etc/sysconfig/network-scripts'"

# 6.3.3.8 - MAC policy
write_section "6.3.3.8 - Ensure MAC policy modifications are audited"
write_result "Check MAC policy audit" "auditctl -l | grep -q '/etc/selinux'"

# 6.3.3.9 - privileged command executions
write_section "6.3.3.9 - Ensure use of privileged commands is audited"
write_result "Check privileged cmds audit" "auditctl -l | grep -q 'privileged'"

# 6.3.3.10 - unsuccessful file access
write_section "6.3.3.10 - Ensure unsuccessful file access is audited"
write_result "Check unsuccessful file access" "auditctl -l | grep -q 'EACCES'"

# 6.3.3.11 - successful file access
write_section "6.3.3.11 - Ensure successful file access is audited"
write_result "Check successful file access" "auditctl -l | grep -q 'success=yes'"

# 6.3.3.12 - file deletion events
write_section "6.3.3.12 - Ensure file deletion events are audited"
write_result "Check file deletion audit" "auditctl -l | grep -E -q 'unlink|rmdir'"

# 6.3.3.13 - module loading/unloading
write_section "6.3.3.13 - Ensure kernel module loading/unloading is audited"
write_result "Check kernel modules audit" "auditctl -l | grep -E -q 'init_module|delete_module'"

# 6.3.3.14 - successful user access
write_section "6.3.3.14 - Ensure successful user access is audited"
write_result "Check successful logins audit" "auditctl -l | grep -q 'USER_LOGIN'"

# 6.3.3.15 - failed login attempts
write_section "6.3.3.15 - Ensure failed login attempts are audited"
write_result "Check failed login audit" "auditctl -l | grep -q 'USER_LOGIN.*res=failed'"

# 6.3.3.16 - group modifications
write_section "6.3.3.16 - Ensure group modifications are audited"
write_result "Check group mods audit" "auditctl -l | grep -E -q '/etc/group|/etc/gshadow'"

# 6.3.3.17 - user modifications
write_section "6.3.3.17 - Ensure user modifications are audited"
write_result "Check user mods audit" "auditctl -l | grep -E -q '/etc/passwd|/etc/shadow'"

# 6.3.3.18 - session initiation
write_section "6.3.3.18 - Ensure session initiation is audited"
write_result "Check session start audit" "auditctl -l | grep -q 'USER_START'"

# 6.3.3.19 - session termination
write_section "6.3.3.19 - Ensure session termination is audited"
write_result "Check session end audit" "auditctl -l | grep -q 'USER_END'"

# 6.3.3.20 - account access
write_section "6.3.3.20 - Ensure account access events are audited"
write_result "Check account access audit" "auditctl -l | grep -q 'USER_ACCT'"

# 6.3.3.21 - auditd is immutable
write_section "6.3.3.21 - Ensure audit configuration is immutable"
write_result "Check auditd immutable" "grep -q '\-e 2' /etc/audit/rules.d/*.rules"

echo -e "\n✔️ Audit checks written to: $OUTPUT_FILE"

#!/usr/bin/env bash

OUTPUT_DIR="$HOME/SEND_TO_MAOR3"
OUTPUT_FILE="$OUTPUT_DIR/auditd_6.3.4_file_access.txt"
mkdir -p "$OUTPUT_DIR"

exec &> >(tee "$OUTPUT_FILE")

echo "==============================="
echo "Section 6.3.4.1 - Audit Log Files Mode"
echo "==============================="

l_perm_mask="0137"
if [ -e "/etc/audit/auditd.conf" ]; then
    l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
    if [ -d "$l_audit_log_directory" ]; then
        l_maxperm="$(printf '%o' $(( 0777 & ~$l_perm_mask )) )"
        a_files=()
        while IFS= read -r -d $'\0' l_file; do
            [ -e "$l_file" ] && a_files+=("$l_file")
        done < <(find "$l_audit_log_directory" -maxdepth 1 -type f -perm /"$l_perm_mask" -print0)
        if (( "${#a_files[@]}" > 0 )); then
            for l_file in "${a_files[@]}"; do
                l_file_mode="$(stat -Lc '%#a' "$l_file")"
                echo -e "\n- Audit Result:\n ** FAIL **\n - File: \"$l_file\" is mode: \"$l_file_mode\" (should be mode: \"$l_maxperm\" or more restrictive)"
            done
        else
            echo -e "\n- Audit Result:\n ** PASS **\n - All files in \"$l_audit_log_directory\" are mode: \"$l_maxperm\" or more restrictive"
        fi
    else
        echo -e "\n- Audit Result:\n ** FAIL **\n - Log file directory not set in \"/etc/audit/auditd.conf\""
    fi
else
    echo -e "\n- Audit Result:\n ** FAIL **\n - File: \"/etc/audit/auditd.conf\" not found."
fi

echo "==============================="
echo "Section 6.3.4.2 - Audit Log Files Owner"
echo "==============================="

if [ -e "/etc/audit/auditd.conf" ]; then
    l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
    if [ -d "$l_audit_log_directory" ]; then
        fail=0
        while IFS= read -r -d $'\0' l_file; do
            owner="$(stat -Lc '%U' "$l_file")"
            if [ "$owner" != "root" ]; then
                echo -e "\n- Audit Result:\n ** FAIL **\n - File: \"$l_file\" is owned by: $owner (should be root)"
                fail=1
            fi
        done < <(find "$l_audit_log_directory" -maxdepth 1 -type f ! -user root -print0)
        if [ $fail -eq 0 ]; then
            echo -e "\n- Audit Result:\n ** PASS **\n - All files in \"$l_audit_log_directory\" are owned by root"
        fi
    fi
fi

echo "==============================="
echo "Section 6.3.4.3 - Audit Log Files Group Owner"
echo "==============================="

if [ -e "/etc/audit/auditd.conf" ]; then
    l_fpath="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
    find -L "$l_fpath" -not -path "$l_fpath"/lost+found -type f \( ! -group root -a ! -group adm \) -exec ls -l {} +
fi

echo "==============================="
echo "Section 6.3.4.4 - Audit Log Directory Mode"
echo "==============================="

l_perm_mask="0027"
if [ -e "/etc/audit/auditd.conf" ]; then
    l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
    if [ -d "$l_audit_log_directory" ]; then
        l_maxperm="$(printf '%o' $(( 0777 & ~$l_perm_mask )) )"
        l_directory_mode="$(stat -Lc '%#a' "$l_audit_log_directory")"
        if [ $(( l_directory_mode & l_perm_mask )) -gt 0 ]; then
            echo -e "\n- Audit Result:\n ** FAIL **\n - Directory: \"$l_audit_log_directory\" is mode: \"$l_directory_mode\" (should be \"$l_maxperm\")"
        else
            echo -e "\n- Audit Result:\n ** PASS **\n - Directory: \"$l_audit_log_directory\" is mode: \"$l_directory_mode\""
        fi
    fi
fi

echo "==============================="
echo "Section 6.3.4.5 - Audit Config Files Mode"
echo "==============================="

l_perm_mask="0137"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_perm_mask )) )"
while IFS= read -r -d $'\0' l_fname; do
    l_mode=$(stat -Lc '%#a' "$l_fname")
    if [ $(( "$l_mode" & "$l_perm_mask" )) -gt 0 ]; then
        echo -e "\n- Audit Result:\n ** FAIL **\n - file: \"$l_fname\" is mode: \"$l_mode\" (should be \"$l_maxperm\")"
    fi
done < <(find /etc/audit/ -type f \( -name "*.conf" -o -name '*.rules' \) -print0)

echo "==============================="
echo "Section 6.3.4.6 - Audit Config Files Owner"
echo "==============================="

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root

echo "==============================="
echo "Section 6.3.4.7 - Audit Config Files Group Owner"
echo "==============================="

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root

echo "==============================="
echo "Section 6.3.4.8 - Audit Tools Mode"
echo "==============================="

l_perm_mask="0022"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_perm_mask )) )"
a_audit_tools=("/sbin/auditctl" "/sbin/aureport" "/sbin/ausearch" "/sbin/autrace" "/sbin/auditd" "/sbin/augenrules")
for l_audit_tool in "${a_audit_tools[@]}"; do
    l_mode="$(stat -Lc '%#a' "$l_audit_tool")"
    if [ $(( "$l_mode" & "$l_perm_mask" )) -gt 0 ]; then
        echo -e "\n- Audit tool \"$l_audit_tool\" is mode: \"$l_mode\" and should be: \"$l_maxperm\""
    fi
done

echo "==============================="
echo "Section 6.3.4.9 - Audit Tools Owner"
echo "==============================="

stat -Lc "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | awk '$2 != "root" {print}'

echo "==============================="
echo "Section 6.3.4.10 - Audit Tools Group Owner"
echo "==============================="

stat -Lc "%n %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | awk '$2 != "root" {print}'


#!/usr/bin/env bash

# =============================
#!/usr/bin/env bash

REPORT_DIR="$HOME/SEND_TO_MAOR3"
mkdir -p "$REPORT_DIR"
REPORT_FILE="$REPORT_DIR/cis_7.1x_file_permissions_audit.txt"

echo "# CIS Section 7.1.x - System File Permissions Audit" > "$REPORT_FILE"
echo "# ===============================================" >> "$REPORT_FILE"

audit_file() {
    local file_path="$1"
    local expected_perms="$2"
    local expected_uid="$3"
    local expected_gid="$4"
    local section="$5"
    local rationale="$6"

    if [ ! -e "$file_path" ]; then
        echo -e "\nSection $section: $file_path not found" >> "$REPORT_FILE"
        echo "Audit Result: FAIL - File not found" >> "$REPORT_FILE"
        return
    fi

    perms=$(stat -Lc "%a" "$file_path")
    owner=$(stat -Lc "%u" "$file_path")
    group=$(stat -Lc "%g" "$file_path")

    echo -e "\n---\nCIS Section: $section - $file_path\n---" >> "$REPORT_FILE"
    echo "Rationale:" >> "$REPORT_FILE"
    echo "$rationale" >> "$REPORT_FILE"
    echo -e "\nCurrent State:" >> "$REPORT_FILE"
    stat -Lc 'Access: (%a/%A) Uid: (%u/%U) Gid: (%g/%G)' "$file_path" >> "$REPORT_FILE"

    echo -e "\nExpected State:" >> "$REPORT_FILE"
    echo "Permissions: $expected_perms, UID: $expected_uid, GID: $expected_gid" >> "$REPORT_FILE"

    if [[ "$perms" -le "$expected_perms" && "$owner" -eq "$expected_uid" && "$group" -eq "$expected_gid" ]]; then
        echo -e "\nAudit Result: PASS" >> "$REPORT_FILE"
    else
        echo -e "\nAudit Result: FAIL" >> "$REPORT_FILE"
        echo "Recommendation: Run 'chmod $expected_perms $file_path && chown $expected_uid:$expected_gid $file_path'" >> "$REPORT_FILE"
    fi
}

# Sample checks (replace rationale strings for actual ones if needed)
audit_file "/etc/passwd" 644 0 0 "7.1.1" "Protect /etc/passwd from unauthorized write access"
audit_file "/etc/passwd-" 644 0 0 "7.1.2" "Protect backup user account file /etc/passwd-"
audit_file "/etc/group" 644 0 0 "7.1.3" "Protect /etc/group from unauthorized changes"
audit_file "/etc/group-" 644 0 0 "7.1.4" "Protect /etc/group- backup file"
audit_file "/etc/shadow" 640 0 42 "7.1.5" "Protect /etc/shadow from unauthorized access"
audit_file "/etc/shadow-" 640 0 42 "7.1.6" "Protect /etc/shadow- backup file"
audit_file "/etc/gshadow" 640 0 42 "7.1.7" "Protect /etc/gshadow from unauthorized access"
audit_file "/etc/gshadow-" 640 0 42 "7.1.8" "Protect /etc/gshadow- backup file"
audit_file "/etc/shells" 644 0 0 "7.1.9" "Protect /etc/shells file"
audit_file "/etc/security/opasswd" 600 0 0 "7.1.10" "Protect old passwords stored in /etc/security/opasswd"

# 7.1.11 - World writable files/directories
echo -e "\n---\nCIS Section: 7.1.11 - World Writable Files and Directories\n---" >> "$REPORT_FILE"
find / -xdev -type f -perm -0002 -print 2>/dev/null >> "$REPORT_FILE"
find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null >> "$REPORT_FILE"

# 7.1.12 - No unowned or ungrouped files
echo -e "\n---\nCIS Section: 7.1.12 - Unowned or Ungrouped Files\n---" >> "$REPORT_FILE"
find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null >> "$REPORT_FILE"

# 7.1.13 - SUID/SGID Review
echo -e "\n---\nCIS Section: 7.1.13 - SUID and SGID Files\n---" >> "$REPORT_FILE"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null >> "$REPORT_FILE"

#!/usr/bin/env bash

REPORT_DIR="$HOME/SEND_TO_MAOR3"
mkdir -p "$REPORT_DIR"
REPORT_FILE="$REPORT_DIR/cis_7.2x_user_group_audit.txt"

#!/usr/bin/env bash

REPORT_DIR="$HOME/SEND_TO_MAOR3"
mkdir -p "$REPORT_DIR"
REPORT_FILE="$REPORT_DIR/cis_7.2x_user_group_audit.txt"

echo "# CIS Section 7.2.x - Local User and Group Settings Audit" > "$REPORT_FILE"
echo "# ========================================================" >> "$REPORT_FILE"

echo -e "\n---\nCIS Section: 7.2.1 - Accounts use shadowed passwords\n---" >> "$REPORT_FILE"
echo -e "Rationale:\nUsing shadowed passwords stores encrypted hashes in /etc/shadow instead of /etc/passwd." >> "$REPORT_FILE"
echo -e "\nExpected State:\nEach account in /etc/passwd should have 'x' in the password field." >> "$REPORT_FILE"
echo -e "\nCurrent State:" >> "$REPORT_FILE"
audit_output=$( awk -F: '($2 != "x") {print "User: \"" $1 "\" is not set to shadowed passwords"}' /etc/passwd )
echo -e "$audit_output" >> "$REPORT_FILE"

if [ -z "$audit_output" ]; then
    echo -e "\nAudit Result: PASS" >> "$REPORT_FILE"
else
    echo -e "\nAudit Result: FAIL" >> "$REPORT_FILE"
    echo -e "Recommendation:\nRun 'pwconv' to move password hashes to /etc/shadow." >> "$REPORT_FILE"
fi


echo -e "\n---\nCIS Section: 7.2.2 - /etc/shadow fields are not empty\n---" >> "$REPORT_FILE"
echo -e "Rationale:\nEmpty password fields allow passwordless login." >> "$REPORT_FILE"
echo -e "\nExpected State:\nNo accounts in /etc/shadow should have an empty password field." >> "$REPORT_FILE"
echo -e "\nCurrent State:" >> "$REPORT_FILE"
audit_output=$( awk -F: '($2 == "") { print $1 " has no password"}' /etc/shadow )
echo -e "$audit_output" >> "$REPORT_FILE"

if [ -z "$audit_output" ]; then
    echo -e "\nAudit Result: PASS" >> "$REPORT_FILE"
else
    echo -e "\nAudit Result: FAIL" >> "$REPORT_FILE"
    echo -e "Recommendation:\nRun 'passwd -l <user>' to lock the account." >> "$REPORT_FILE"
fi


echo -e "\n---\nCIS Section: 7.2.3 - All groups in /etc/passwd exist in /etc/group\n---" >> "$REPORT_FILE"
echo -e "Rationale:\nMissing group entries in /etc/group reduce permission control." >> "$REPORT_FILE"
echo -e "\nExpected State:\nAll GIDs in /etc/passwd should appear in /etc/group." >> "$REPORT_FILE"
echo -e "\nCurrent State:" >> "$REPORT_FILE"
audit_output=$( for gid in $(cut -d: -f4 /etc/passwd | sort -u); do grep -qE ":$gid:" /etc/group || echo "Missing GID: $gid in /etc/group"; done )
echo -e "$audit_output" >> "$REPORT_FILE"

if [ -z "$audit_output" ]; then
    echo -e "\nAudit Result: PASS" >> "$REPORT_FILE"
else
    echo -e "\nAudit Result: FAIL" >> "$REPORT_FILE"
    echo -e "Recommendation:\nEnsure all GIDs in passwd exist in group using 'groupadd'." >> "$REPORT_FILE"
fi


echo -e "\n---\nCIS Section: 7.2.4 - Shadow group is empty\n---" >> "$REPORT_FILE"
echo -e "Rationale:\nUsers in 'shadow' group can read password hashes from /etc/shadow." >> "$REPORT_FILE"
echo -e "\nExpected State:\nNo users should be in the shadow group or have it as a primary group." >> "$REPORT_FILE"
echo -e "\nCurrent State:" >> "$REPORT_FILE"
audit_output=$( getent group shadow | awk -F: '{ if (NF > 3 && $4 != "") print "Members: "$4 }'; awk -F: '($4 == "$(getent group shadow | awk -F: '{print $3}')") { print "User: "$1" has shadow as primary group" }' /etc/passwd )
echo -e "$audit_output" >> "$REPORT_FILE"

if [ -z "$audit_output" ]; then
    echo -e "\nAudit Result: PASS" >> "$REPORT_FILE"
else
    echo -e "\nAudit Result: FAIL" >> "$REPORT_FILE"
    echo -e "Recommendation:\nRemove users from shadow group and change their primary group using 'usermod -g'." >> "$REPORT_FILE"
fi


echo -e "\n---\nCIS Section: 7.2.5 - No duplicate UIDs\n---" >> "$REPORT_FILE"
echo -e "Rationale:\nDuplicate UIDs prevent accountability and allow privilege overlap." >> "$REPORT_FILE"
echo -e "\nExpected State:\nEach UID should be unique." >> "$REPORT_FILE"
echo -e "\nCurrent State:" >> "$REPORT_FILE"
audit_output=$( cut -d: -f3 /etc/passwd | sort | uniq -d | while read -r uid; do awk -F: -v u=$uid '($3 == u) {{print "Duplicate UID: "$3" for user "$1}}' /etc/passwd; done )
echo -e "$audit_output" >> "$REPORT_FILE"

if [ -z "$audit_output" ]; then
    echo -e "\nAudit Result: PASS" >> "$REPORT_FILE"
else
    echo -e "\nAudit Result: FAIL" >> "$REPORT_FILE"
    echo -e "Recommendation:\nAssign a unique UID using 'usermod -u' and fix ownerships." >> "$REPORT_FILE"
fi


echo -e "\n---\nCIS Section: 7.2.6 - No duplicate GIDs\n---" >> "$REPORT_FILE"
echo -e "Rationale:\nDuplicate GIDs create permission ambiguity." >> "$REPORT_FILE"
echo -e "\nExpected State:\nEach GID should be unique." >> "$REPORT_FILE"
echo -e "\nCurrent State:" >> "$REPORT_FILE"
audit_output=$( cut -d: -f3 /etc/group | sort | uniq -d | while read -r gid; do awk -F: -v g=$gid '($3 == g) {{print "Duplicate GID: "$3" for group "$1}}' /etc/group; done )
echo -e "$audit_output" >> "$REPORT_FILE"

if [ -z "$audit_output" ]; then
    echo -e "\nAudit Result: PASS" >> "$REPORT_FILE"
else
    echo -e "\nAudit Result: FAIL" >> "$REPORT_FILE"
    echo -e "Recommendation:\nAssign a unique GID using 'groupmod -g'." >> "$REPORT_FILE"
fi


echo -e "\n---\nCIS Section: 7.2.7 - No duplicate usernames\n---" >> "$REPORT_FILE"
echo -e "Rationale:\nDuplicate usernames cause access confusion and privilege issues." >> "$REPORT_FILE"
echo -e "\nExpected State:\nEach username in /etc/passwd must be unique." >> "$REPORT_FILE"
echo -e "\nCurrent State:" >> "$REPORT_FILE"
audit_output=$( cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r user; do echo "Duplicate username: $user"; done )
echo -e "$audit_output" >> "$REPORT_FILE"

if [ -z "$audit_output" ]; then
    echo -e "\nAudit Result: PASS" >> "$REPORT_FILE"
else
    echo -e "\nAudit Result: FAIL" >> "$REPORT_FILE"
    echo -e "Recommendation:\nRename duplicates using 'usermod -l' and update login info." >> "$REPORT_FILE"
fi


echo -e "\n---\nCIS Section: 7.2.8 - No duplicate group names\n---" >> "$REPORT_FILE"
echo -e "Rationale:\nDuplicate group names cause conflict in permission management." >> "$REPORT_FILE"
echo -e "\nExpected State:\nEach group name must be unique in /etc/group." >> "$REPORT_FILE"
echo -e "\nCurrent State:" >> "$REPORT_FILE"
audit_output=$( cut -d: -f1 /etc/group | sort | uniq -d | while read -r group; do echo "Duplicate group name: $group"; done )
echo -e "$audit_output" >> "$REPORT_FILE"

if [ -z "$audit_output" ]; then
    echo -e "\nAudit Result: PASS" >> "$REPORT_FILE"
else
    echo -e "\nAudit Result: FAIL" >> "$REPORT_FILE"
    echo -e "Recommendation:\nRename duplicate groups using 'groupmod -n'." >> "$REPORT_FILE"
fi


echo -e "\n---\nCIS Section: 7.2.9 - Home directories exist and are owned properly\n---" >> "$REPORT_FILE"
echo -e "Rationale:\nMissing or misconfigured home directories can result in insecure data storage or shell access." >> "$REPORT_FILE"
echo -e "\nExpected State:\nEach user with a valid shell must have a home directory they own with 750 permissions." >> "$REPORT_FILE"
echo -e "\nCurrent State:" >> "$REPORT_FILE"
audit_output=$( awk -F: '$7 !~ /nologin|false/ {{ if (!system("test -d "$6)) {{ owner=$(stat -c "%U" $6); if (owner != $1) print "Owner mismatch for "$6; }} else print "Missing home dir for: "$1 }}' /etc/passwd )
echo -e "$audit_output" >> "$REPORT_FILE"

if [ -z "$audit_output" ]; then
    echo -e "\nAudit Result: PASS" >> "$REPORT_FILE"
else
    echo -e "\nAudit Result: FAIL" >> "$REPORT_FILE"
    echo -e "Recommendation:\nCreate missing directories and correct ownership using 'mkdir', 'chown', and 'chmod'." >> "$REPORT_FILE"
fi


echo -e "\n---\nCIS Section: 7.2.10 - Dot files access is secure\n---" >> "$REPORT_FILE"
echo -e "Rationale:\nDotfiles like .netrc, .bash_history must be protected from unauthorized access." >> "$REPORT_FILE"
echo -e "\nExpected State:\nEnsure only the owner has access, and .forward/.rhosts do not exist." >> "$REPORT_FILE"
echo -e "\nCurrent State:" >> "$REPORT_FILE"
audit_output=$( find /home -type f -name '.*' \( -perm /133 -o -name '.forward' -o -name '.rhost' \) -exec ls -l {{}} \; )
echo -e "$audit_output" >> "$REPORT_FILE"

if [ -z "$audit_output" ]; then
    echo -e "\nAudit Result: PASS" >> "$REPORT_FILE"
else
    echo -e "\nAudit Result: FAIL" >> "$REPORT_FILE"
    echo -e "Recommendation:\nUse 'chmod 600', 'chown', and delete .forward/.rhost files." >> "$REPORT_FILE"
fi

