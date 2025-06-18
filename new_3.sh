#!/usr/bin/env bash

OUTPUT_DIR="$HOME/Desktop/SEND_TO_MAOR"
KERNEL_OUTPUT_FILE="$OUTPUT_DIR/Configure Filesystem Kernel Modules.txt"
PARTITION_OUTPUT_FILE="$OUTPUT_DIR/Configure Filesystem Partitions.txt"
SHM_OUTPUT_FILE="$OUTPUT_DIR/Configure dev shm.txt"

mkdir -p "$OUTPUT_DIR"

write_audit_result() {
  local cis_id="$1"
  local title="$2"
  local current_state="$3"
  local hardened_state="$4"
  local result="$5"
  local rationale="$6"
  local output_file="$7"

  {
    echo "CIS Section: $cis_id – $title"
    echo ""
    echo "Current State:"
    echo "$current_state"
    echo ""
    echo "Hardened State:"
    echo "$hardened_state"
    echo ""
    echo "Audit Result: **$result**"
    echo ""
    echo "Rationale:"
    echo "$rationale"
    echo -e "\n---\n"
  } >> "$output_file"
}

# --- Kernel Modules Check ---
run_module_check() {
  local module_name="$1"
  local cis_id="$2"
  local title="$3"
  local rationale="$4"

  local output current_state hardened_state result

  output="$(modprobe -n -v "$module_name" 2>&1)"
  if grep -qE '^install /bin/(true|false)' <<< "$output"; then
    current_state="$output"
    hardened_state="Module should be disabled using: install $module_name /bin/true"
    result="PASS"
  else
    current_state="$output"
    hardened_state="Module should be disabled using: install $module_name /bin/true"
    result="FAIL"
  fi

  write_audit_result "$cis_id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$KERNEL_OUTPUT_FILE"
}

kernel_rationale="Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
usb_rationale="Restricting USB access on the system will decrease the physical attack surface for a device and diminish the possible vectors to introduce malware."

modules=(
  "cramfs:1.1.1.1:Ensure cramfs kernel module is not available"
  "freevxfs:1.1.1.2:Ensure freevxfs kernel module is not available"
  "hfs:1.1.1.3:Ensure hfs kernel module is not available"
  "hfsplus:1.1.1.4:Ensure hfsplus kernel module is not available"
  "jffs2:1.1.1.5:Ensure jffs2 kernel module is not available"
  "squashfs:1.1.1.6:Ensure squashfs kernel module is not available"
  "udf:1.1.1.7:Ensure udf kernel module is not available"
  "usb-storage:1.1.1.8:Ensure USB storage kernel module is not available"
)

for m in "${modules[@]}"; do
  IFS=":" read -r module id title <<< "$m"
  rationale="$kernel_rationale"
  [ "$module" == "usb-storage" ] && rationale="$usb_rationale"
  run_module_check "$module" "$id" "$title" "$rationale"
done

# --- /tmp Partitions Check ---
check_mount_option() {
  local option="$1"
  local id="$2"
  local title="$3"
  local rationale="$4"

  local current_state
  if findmnt -kn /tmp | grep -v "$option" &>/dev/null; then
    result="FAIL"
    current_state="$(findmnt -kn /tmp)"
    [ -z "$current_state" ] && current_state="Not mounted or no output returned"
  else
    result="PASS"
    current_state="$(findmnt -kn /tmp)"
    [ -z "$current_state" ] && current_state="Not mounted or no output returned"
  fi

  hardened_state="/tmp should be mounted with $option enabled"
  write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$PARTITION_OUTPUT_FILE"
}

# 1.1.2.1.1
title="Ensure /tmp is a separate partition"
id="1.1.2.1.1"
rationale="Making /tmp its own file system allows an administrator to set additional mount options such as the noexec option, making /tmp useless for an attacker to install executable code."
if findmnt -kn /tmp &>/dev/null; then
  result="PASS"
  current_state="$(findmnt -kn /tmp)"
  [ -z "$current_state" ] && current_state="Not mounted or no output returned"
else
  result="FAIL"
  current_state="No /tmp partition found"
fi
hardened_state="/tmp should be a separate mount using tmpfs or its own partition"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$PARTITION_OUTPUT_FILE"

check_mount_option "nodev" "1.1.2.1.2" "Ensure nodev option set on /tmp partition" "Since the /tmp filesystem is not intended to support devices, set this option to ensure users cannot create a block or character special devices in /tmp."
check_mount_option "nosuid" "1.1.2.1.3" "Ensure nosuid option set on /tmp partition" "Set this option to prevent users from creating setuid files in /tmp."
check_mount_option "noexec" "1.1.2.1.4" "Ensure noexec option set on /tmp partition" "Set this option to ensure that users cannot run executables from /tmp."

# --- /dev/shm Check ---
check_dev_shm_option() {
  local option="$1"
  local id="$2"
  local title="$3"
  local rationale="$4"

  if findmnt -kn /dev/shm | grep -v "$option" &>/dev/null; then
    result="FAIL"
    current_state="$(findmnt -kn /dev/shm)"
  else
    result="PASS"
    current_state="$(findmnt -kn /dev/shm)"
  fi
  hardened_state="/dev/shm should be mounted with $option enabled"
  write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$SHM_OUTPUT_FILE"
}

title="Ensure /dev/shm is a separate partition"
id="1.1.2.2.1"
rationale="Making /dev/shm its own file system allows administrators to apply restrictions like noexec to mitigate risk."
if findmnt -kn /dev/shm &>/dev/null; then
  result="PASS"
  current_state="$(findmnt -kn /dev/shm)"
else
  result="FAIL"
  current_state="No /dev/shm partition found"
fi
hardened_state="/dev/shm should be a separate mount using tmpfs"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$SHM_OUTPUT_FILE"

check_dev_shm_option "nodev" "1.1.2.2.2" "Ensure nodev option set on /dev/shm partition" "This option prevents creation of special device files in /dev/shm."
check_dev_shm_option "nosuid" "1.1.2.2.3" "Ensure nosuid option set on /dev/shm partition" "Prevents execution of setuid programs from shared memory."
check_dev_shm_option "noexec" "1.1.2.2.4" "Ensure noexec option set on /dev/shm partition" "Prevents execution of binaries from shared memory to reduce risk."

# --- Configure /home Checks ---
HOME_OUTPUT_FILE="$OUTPUT_DIR/Configure home.txt"

check_home_mount_option() {
  local option="$1"
  local id="$2"
  local title="$3"
  local rationale="$4"

  if findmnt -kn /home | grep -v "$option" &>/dev/null; then
    result="FAIL"
    current_state="$(findmnt -kn /home)"
    [ -z "$current_state" ] && current_state="Not mounted or no output returned"
  else
    result="PASS"
    current_state="$(findmnt -kn /home)"
    [ -z "$current_state" ] && current_state="Not mounted or no output returned"
  fi

  hardened_state="/home should be mounted with $option enabled"
  write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$HOME_OUTPUT_FILE"
}

# 1.1.2.3.1 - Ensure /home is a separate partition
title="Ensure /home is a separate partition"
id="1.1.2.3.1"
rationale="Configuring /home as its own file system allows an administrator to set additional mount options and reduce risk of resource exhaustion or privilege escalation. It limits the impact user activity can have on the entire system."
if findmnt -kn /home &>/dev/null; then
  result="PASS"
  current_state="$(findmnt -kn /home)"
  [ -z "$current_state" ] && current_state="Not mounted or no output returned"
else
  result="FAIL"
  current_state="No /home partition found"
fi
hardened_state="/home should be a separate mount using its own partition"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$HOME_OUTPUT_FILE"

# 1.1.2.3.2 - nodev
check_home_mount_option "nodev" "1.1.2.3.2" "Ensure nodev option set on /home partition" "Since the /home filesystem is not intended to support devices, setting this option ensures that users cannot create block or character special devices, reducing the attack surface."

# 1.1.2.3.3 - nosuid
check_home_mount_option "nosuid" "1.1.2.3.3" "Ensure nosuid option set on /home partition" "Setting the nosuid option on /home prevents users from creating or using setuid files, which helps mitigate privilege escalation risks."
 
 # --- Configure /var Checks ---
VAR_OUTPUT_FILE="$OUTPUT_DIR/Configure_var.txt"

check_var_mount_option() {
  local option="$1"
  local id="$2"
  local title="$3"
  local rationale="$4"

  if findmnt -kn /var | grep -v "$option" &>/dev/null; then
    result="FAIL"
    current_state="$(findmnt -kn /var)"
    [ -z "$current_state" ] && current_state="Not mounted or no output returned"
  else
    result="PASS"
    current_state="$(findmnt -kn /var)"
    [ -z "$current_state" ] && current_state="Not mounted or no output returned"
  fi

  hardened_state="/var should be mounted with $option enabled"
  write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$VAR_OUTPUT_FILE"
}

# 1.1.2.4.1 - Ensure /var is a separate partition
title="Ensure /var is a separate partition"
id="1.1.2.4.1"
rationale="The reasoning for mounting /var on a separate partition is as follows.
The default installation only creates a single / partition. Since the /var directory may contain world-writable files and directories, there is a risk of resource exhaustion. It will essentially have the whole disk available to fill up and impact the system as a whole. In addition, other operations on the system could fill up the disk unrelated to /var and cause unintended behavior across the system as the disk is full. See man auditd.conf for details.
Configuring /var as its own file system allows an administrator to set additional mount options such as noexec/nosuid/nodev. These options limit an attacker's ability to create exploits on the system. Other options allow for specific behavior. See man mount for exact details regarding filesystem-independent and filesystem-specific options.
An example of exploiting /var may be an attacker establishing a hard-link to a system setuid program and wait for it to be updated. Once the program was updated, the hard-link would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw."

if findmnt -kn /var &>/dev/null; then
  result="PASS"
  current_state="$(findmnt -kn /var)"
  [ -z "$current_state" ] && current_state="Not mounted or no output returned"
else
  result="FAIL"
  current_state="No /var partition found"
fi
hardened_state="/var should be a separate mount using its own partition"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$VAR_OUTPUT_FILE"

# 1.1.2.4.2 - nodev
check_var_mount_option "nodev" "1.1.2.4.2" "Ensure nodev option set on /var partition" "Since the /var filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /var."

# 1.1.2.4.3 - nosuid
check_var_mount_option "nosuid" "1.1.2.4.3" "Ensure nosuid option set on /var partition" "Since the /var filesystem is only intended for variable files such as logs, set this option to ensure that users cannot create setuid files in /var."

# --- Configure /var/tmp Checks ---
VAR_TMP_OUTPUT_FILE="$OUTPUT_DIR/Configure_var_tmp.txt"
echo "Starting /var/tmp checks..." > "$VAR_TMP_OUTPUT_FILE"
echo "Saving results to $VAR_TMP_OUTPUT_FILE"

check_var_tmp_mount_option() {
  local option="$1"
  local id="$2"
  local title="$3"
  local rationale="$4"

  if findmnt -kn /var/tmp | grep -v "$option" &>/dev/null; then
    result="FAIL"
    current_state="$(findmnt -kn /var/tmp)"
    [ -z "$current_state" ] && current_state="Not mounted or no output returned"
  else
    result="PASS"
    current_state="$(findmnt -kn /var/tmp)"
    [ -z "$current_state" ] && current_state="Not mounted or no output returned"
  fi

  hardened_state="/var/tmp should be mounted with $option enabled"
  write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$VAR_TMP_OUTPUT_FILE"
}

# 1.1.2.5.1 - Ensure /var/tmp is a separate partition
title="Ensure /var/tmp is a separate partition"
id="1.1.2.5.1"
rationale="The default installation only creates a single / partition. Since the /var/tmp directory is world-writable, there is a risk of resource exhaustion. In addition, other operations on the system could fill up the disk unrelated to /var/tmp and cause potential disruption to daemons as the disk is full. Configuring /var/tmp as its own file system allows an administrator to set additional mount options such as noexec/nosuid/nodev. These options limit an attacker's ability to create exploits on the system."

if findmnt -kn /var/tmp &>/dev/null; then
  result="PASS"
  current_state="$(findmnt -kn /var/tmp)"
  [ -z "$current_state" ] && current_state="Not mounted or no output returned"
else
  result="FAIL"
  current_state="No /var/tmp partition found"
fi

hardened_state="/var/tmp should be a separate mount using its own partition"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$VAR_TMP_OUTPUT_FILE"

# 1.1.2.5.2 - nodev
check_var_tmp_mount_option "nodev" "1.1.2.5.2" "Ensure nodev option set on /var/tmp partition" "Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /var/tmp."

# 1.1.2.5.3 - nosuid
check_var_tmp_mount_option "nosuid" "1.1.2.5.3" "Ensure nosuid option set on /var/tmp partition" "Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /var/tmp."

# 1.1.2.5.4 - noexec
check_var_tmp_mount_option "noexec" "1.1.2.5.4" "Ensure noexec option set on /var/tmp partition" "Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /var/tmp."

# --- Configure /var/log Checks ---
VAR_LOG_OUTPUT_FILE="$OUTPUT_DIR/Configure_var_log.txt"
echo "Starting /var/log checks..." > "$VAR_LOG_OUTPUT_FILE"
echo "Saving results to $VAR_LOG_OUTPUT_FILE"

check_var_log_mount_option() {
  local option="$1"
  local id="$2"
  local title="$3"
  local rationale="$4"

  if findmnt -kn /var/log | grep -v "$option" &>/dev/null; then
    result="FAIL"
    current_state="$(findmnt -kn /var/log)"
    [ -z "$current_state" ] && current_state="Not mounted or no output returned"
  else
    result="PASS"
    current_state="$(findmnt -kn /var/log)"
    [ -z "$current_state" ] && current_state="Not mounted or no output returned"
  fi

  hardened_state="/var/log should be mounted with $option enabled"
  write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$VAR_LOG_OUTPUT_FILE"
}

# 1.1.2.6.1 - Ensure /var/log is a separate partition
title="Ensure /var/log is a separate partition"
id="1.1.2.6.1"
rationale="The default installation only creates a single / partition. Since the /var/log directory contains log files which can grow quite large, there is a risk of resource exhaustion. Configuring /var/log as its own file system allows an administrator to set additional mount options such as noexec/nosuid/nodev. These options limit an attacker's ability to create exploits on the system."

if findmnt -kn /var/log &>/dev/null; then
  result="PASS"
  current_state="$(findmnt -kn /var/log)"
  [ -z "$current_state" ] && current_state="Not mounted or no output returned"
else
  result="FAIL"
  current_state="No /var/log partition found"
fi

hardened_state="/var/log should be a separate mount using its own partition"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$VAR_LOG_OUTPUT_FILE"

# 1.1.2.6.2 - nodev
check_var_log_mount_option "nodev" "1.1.2.6.2" "Ensure nodev option set on /var/log partition" "Since the /var/log filesystem is not intended to support devices, set this option to ensure that users cannot create block or character special devices in /var/log."

# 1.1.2.6.3 - nosuid
check_var_log_mount_option "nosuid" "1.1.2.6.3" "Ensure nosuid option set on /var/log partition" "Since the /var/log filesystem is only intended for log files, set this option to ensure that users cannot create setuid files in /var/log."

# 1.1.2.6.4 - noexec
check_var_log_mount_option "noexec" "1.1.2.6.4" "Ensure noexec option set on /var/log partition" "Since the /var/log filesystem is only intended for log files, set this option to ensure that users cannot run executable binaries from /var/log."

# --- Configure /var/log/audit Checks ---
VAR_LOG_AUDIT_OUTPUT_FILE="$OUTPUT_DIR/Configure_var_log_audit.txt"
echo "Starting /var/log/audit checks..." > "$VAR_LOG_AUDIT_OUTPUT_FILE"
echo "Saving results to $VAR_LOG_AUDIT_OUTPUT_FILE"

check_var_log_audit_mount_option() {
  local option="$1"
  local id="$2"
  local title="$3"
  local rationale="$4"

  if findmnt -kn /var/log/audit | grep -v "$option" &>/dev/null; then
    result="FAIL"
    current_state="$(findmnt -kn /var/log/audit)"
    [ -z "$current_state" ] && current_state="Not mounted or no output returned"
  else
    result="PASS"
    current_state="$(findmnt -kn /var/log/audit)"
    [ -z "$current_state" ] && current_state="Not mounted or no output returned"
  fi

  hardened_state="/var/log/audit should be mounted with $option enabled"
  write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$VAR_LOG_AUDIT_OUTPUT_FILE"
}

# 1.1.2.7.1 - Ensure /var/log/audit is a separate partition
title="Ensure /var/log/audit is a separate partition"
id="1.1.2.7.1"
rationale="Since the /var/log/audit directory contains audit logs which can grow significantly, configuring it on a separate partition helps avoid resource exhaustion and allows security-restrictive mount options such as nodev, nosuid, and noexec."

if findmnt -kn /var/log/audit &>/dev/null; then
  result="PASS"
  current_state="$(findmnt -kn /var/log/audit)"
  [ -z "$current_state" ] && current_state="Not mounted or no output returned"
else
  result="FAIL"
  current_state="No /var/log/audit partition found"
fi

hardened_state="/var/log/audit should be a separate mount using its own partition"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$VAR_LOG_AUDIT_OUTPUT_FILE"

# 1.1.2.7.2 - nodev
check_var_log_audit_mount_option "nodev" "1.1.2.7.2" "Ensure nodev option set on /var/log/audit partition" "Since /var/log/audit is not intended to support device files, the nodev option should be set to prevent creation of such devices."

# 1.1.2.7.3 - nosuid
check_var_log_audit_mount_option "nosuid" "1.1.2.7.3" "Ensure nosuid option set on /var/log/audit partition" "The nosuid option ensures users cannot create setuid files within /var/log/audit, reducing the risk of privilege escalation."

# 1.1.2.7.4 - noexec
check_var_log_audit_mount_option "noexec" "1.1.2.7.4" "Ensure noexec option set on /var/log/audit partition" "Setting the noexec option on /var/log/audit ensures that executables cannot be run from this log directory, reducing exploitability."

# --- Configure Package Repositories Checks ---
PACKAGE_REPO_OUTPUT_FILE="$OUTPUT_DIR/Configure_Package_Repositories.txt"

# 1.2.1.1 - Ensure GPG keys are configured
title="Ensure GPG keys are configured"
id="1.2.1.1"
rationale="Ensuring that GPG keys are configured helps verify the authenticity of packages and protects against installation of tampered or malicious software."
current_state="$(apt-key list 2>/dev/null)"
if [ -n "$current_state" ]; then
  result="PASS"
else
  result="FAIL"
  current_state="No GPG keys found or apt-key not supported"
fi
hardened_state="GPG keys should be configured for all repositories"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$PACKAGE_REPO_OUTPUT_FILE"

# 1.2.1.2 - Ensure package manager repositories are configured
title="Ensure package manager repositories are configured"
id="1.2.1.2"
rationale="Ensuring that repositories are properly configured helps guarantee secure, trusted, and consistent software updates."
current_state="$(apt-cache policy 2>/dev/null)"
if echo "$current_state" | grep -q "http"; then
  result="PASS"
else
  result="FAIL"
fi
hardened_state="Repositories should be configured according to site policy and must not include untrusted sources"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$PACKAGE_REPO_OUTPUT_FILE"

# --- Configure Package Updates Checks ---
PACKAGE_UPDATE_OUTPUT_FILE="$OUTPUT_DIR/Configure_Package_Updates.txt"

# 1.2.2.1 - Ensure updates, patches, and additional security software are installed
title="Ensure updates and patches are installed"
id="1.2.2.1"
rationale="Keeping system packages up to date reduces exposure to known vulnerabilities and enhances system security."

# NOTE: This is a simulation only (`-s`) – does not install anything.
current_state="$(apt -s upgrade 2>/dev/null)"
if echo "$current_state" | grep -q "^Inst "; then
  result="FAIL"
  hardened_state="System should have no pending security or feature updates"
else
  result="PASS"
  hardened_state="System is up to date; no pending upgrades found"
fi

write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$PACKAGE_UPDATE_OUTPUT_FILE"


# AppArmor Audit - CIS Section 1.3.1
APPARMOR_OUTPUT_FILE="$OUTPUT_DIR/Configure_AppArmor.txt"

# 1.3.1.1 Ensure AppArmor is installed
title="Ensure AppArmor is installed"
id="1.3.1.1"
rationale="Without a Mandatory Access Control system installed only the default Discretionary Access Control system will be available."
if dpkg-query -s apparmor &>/dev/null && dpkg-query -s apparmor-utils &>/dev/null; then
  result="PASS"
  current_state="AppArmor and apparmor-utils are installed"
else
  result="FAIL"
  current_state="One or both of AppArmor and apparmor-utils are not installed"
fi
hardened_state="Both apparmor and apparmor-utils should be installed"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$APPARMOR_OUTPUT_FILE"

# 1.3.1.2 Ensure AppArmor is enabled in the bootloader configuration
title="Ensure AppArmor is enabled in the bootloader configuration"
id="1.3.1.2"
rationale="AppArmor must be enabled at boot time in your bootloader configuration to ensure that the controls it provides are not overridden."
cmd1=$(grep "^\\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1")
cmd2=$(grep "^\\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor")
if [[ -z "$cmd1" && -z "$cmd2" ]]; then
  result="PASS"
  current_state="Bootloader parameters are properly configured with apparmor=1 and security=apparmor"
else
  result="FAIL"
  current_state="Missing one or both parameters in grub config.\nCurrent grub entries:\n$(grep "^\\s*linux" /boot/grub/grub.cfg)"
fi
hardened_state="Bootloader should include 'apparmor=1 security=apparmor' in GRUB_CMDLINE_LINUX"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$APPARMOR_OUTPUT_FILE"

# 1.3.1.3 Ensure all AppArmor Profiles are in enforce or complain mode
title="Ensure all AppArmor Profiles are in enforce or complain mode"
id="1.3.1.3"
rationale="Ensure that any AppArmor policies that exist on the system are activated."
aprofiles=$(apparmor_status 2>/dev/null | grep profiles || echo "Could not retrieve profile status")
aprocesses=$(apparmor_status 2>/dev/null | grep processes || echo "Could not retrieve process status")
current_state="$aprofiles\n$aprocesses"
if echo "$aprofiles" | grep -q "profiles are loaded" && echo "$aprocesses" | grep -q "0 processes are unconfined"; then
  result="PASS"
else
  result="FAIL"
fi
hardened_state="All profiles should be loaded and all processes should be confined"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$APPARMOR_OUTPUT_FILE"

# 1.3.1.4 Ensure all AppArmor Profiles are enforcing
title="Ensure all AppArmor Profiles are enforcing"
id="1.3.1.4"
rationale="Ensure that AppArmor policies are set to enforce and not just complain."
aprofiles_enforce=$(apparmor_status 2>/dev/null | grep profiles || echo "Could not retrieve profile enforcement status")
aprocesses_enforce=$(apparmor_status 2>/dev/null | grep processes || echo "Could not retrieve process enforcement status")
current_state="$aprofiles_enforce\n$aprocesses_enforce"
if echo "$aprofiles_enforce" | grep -q "0 profiles are in complain mode" && echo "$aprocesses_enforce" | grep -q "0 processes are in complain mode"; then
  result="PASS"
else
  result="FAIL"
fi
hardened_state="All AppArmor profiles should be in enforce mode"
write_audit_result "$id" "$title" "$current_state" "$hardened_state" "$result" "$rationale" "$APPARMOR_OUTPUT_FILE"

# ==========================
# Section 1.4 - Secure Boot
# ==========================

REPORT_DIR="SEND_TO_MAOR"
REPORT_FILE="$REPORT_DIR/secure_boot.txt"

mkdir -p "$REPORT_DIR"

# Helper to write headers
write_section() {
    echo -e "\n---\n" >> "$REPORT_FILE"
    echo -e "$1" >> "$REPORT_FILE"
    echo -e "---\n" >> "$REPORT_FILE"
}

# ==========
# 1.4.1 Ensure bootloader password is set
# ==========

write_section "CIS Section: 1.4.1 – Ensure bootloader password is set"

echo "Rationale:" >> "$REPORT_FILE"
echo "Requiring a boot password prevents unauthorized users from changing boot parameters or disabling security features like AppArmor at boot time." >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Audit: Checking for bootloader password..." >> "$REPORT_FILE"
superusers_line=$(grep "^set superusers" /boot/grub/grub.cfg 2>/dev/null)
password_line=$(grep -E '^\s*password_pbkdf2' /boot/grub/grub.cfg 2>/dev/null)

echo "Current State:" >> "$REPORT_FILE"
if [[ -n "$superusers_line" ]]; then
    echo "$superusers_line" >> "$REPORT_FILE"
else
    echo "Missing: set superusers directive" >> "$REPORT_FILE"
fi

if [[ -n "$password_line" ]]; then
    echo "$password_line" >> "$REPORT_FILE"
else
    echo "Missing: password_pbkdf2 directive" >> "$REPORT_FILE"
fi

echo >> "$REPORT_FILE"
echo "Hardened State:" >> "$REPORT_FILE"
echo "GRUB should include set superusers and password_pbkdf2 directives." >> "$REPORT_FILE"

echo -n "Audit Result: " >> "$REPORT_FILE"
if [[ "$superusers_line" == set\ superusers* && "$password_line" == password_pbkdf2* ]]; then
    echo "**PASS**" >> "$REPORT_FILE"
else
    echo "**FAIL**" >> "$REPORT_FILE"
fi

# ==========
# 1.4.2 Ensure access to bootloader config is configured
# ==========

write_section "CIS Section: 1.4.2 – Ensure access to bootloader config is configured"

echo "Rationale:" >> "$REPORT_FILE"
echo "Restricting permissions on grub.cfg prevents non-root users from viewing or modifying sensitive boot parameters that could expose vulnerabilities." >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Audit: Checking permissions and ownership of /boot/grub/grub.cfg..." >> "$REPORT_FILE"

if [[ -f /boot/grub/grub.cfg ]]; then
    stat_output=$(stat -Lc 'Access: (%#a/%A) Uid: (%u/%U) Gid: (%g/%G)' /boot/grub/grub.cfg)
    echo "Current State:" >> "$REPORT_FILE"
    echo "$stat_output" >> "$REPORT_FILE"

    perms=$(stat -Lc '%a' /boot/grub/grub.cfg)
    uid=$(stat -Lc '%u' /boot/grub/grub.cfg)
    gid=$(stat -Lc '%g' /boot/grub/grub.cfg)

    echo >> "$REPORT_FILE"
    echo "Hardened State:" >> "$REPORT_FILE"
    echo "File should be owned by root:root and permissions should be 0600 or more restrictive." >> "$REPORT_FILE"

    echo -n "Audit Result: " >> "$REPORT_FILE"
    if [[ "$perms" -le 600 && "$uid" -eq 0 && "$gid" -eq 0 ]]; then
        echo "**PASS**" >> "$REPORT_FILE"
    else
        echo "**FAIL**" >> "$REPORT_FILE"
    fi
else
    echo "Current State:" >> "$REPORT_FILE"
    echo "/boot/grub/grub.cfg not found" >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
    echo "Hardened State:" >> "$REPORT_FILE"
    echo "File should exist, be owned by root:root and have 0600 permissions or stricter." >> "$REPORT_FILE"
    echo "Audit Result: **FAIL**" >> "$REPORT_FILE"
fi

# =============================
# Section 1.5 - Process Hardening
# =============================

REPORT_DIR="SEND_TO_MAOR"
REPORT_FILE="$REPORT_DIR/process_hardening.txt"

mkdir -p "$REPORT_DIR"

write_section() {
    echo -e "\n---\n$1\n---\n" >> "$REPORT_FILE"
}

write_rationale() {
    echo -e "Rationale:\n$1\n" >> "$REPORT_FILE"
}

write_result() {
    echo -e "$1\n" >> "$REPORT_FILE"
}

# ========================================
# 1.5.1 Ensure address space layout randomization is enabled
# ========================================
write_section "CIS Section: 1.5.1 – Ensure ASLR is enabled"
write_rationale "Randomly placing virtual memory regions makes it harder for attackers to exploit memory-related vulnerabilities."

ASLR=$(sysctl kernel.randomize_va_space | awk '{print $3}')
echo "Current State:" >> "$REPORT_FILE"
echo "kernel.randomize_va_space = $ASLR" >> "$REPORT_FILE"

if [[ "$ASLR" == "2" ]]; then
    write_result "Audit Result: **PASS** – ASLR is enabled."
else
    write_result "Audit Result: **FAIL** – ASLR is NOT set to 2."
fi

# ========================================
# 1.5.2 Ensure ptrace_scope is restricted
# ========================================
write_section "CIS Section: 1.5.2 – Ensure ptrace_scope is restricted"
write_rationale "Restricting ptrace reduces the ability of compromised processes to inspect other processes, helping contain attacks."

PTRACE=$(sysctl kernel.yama.ptrace_scope | awk '{print $3}')
echo "Current State:" >> "$REPORT_FILE"
echo "kernel.yama.ptrace_scope = $PTRACE" >> "$REPORT_FILE"

if [[ "$PTRACE" == "1" ]]; then
    write_result "Audit Result: **PASS** – ptrace_scope is restricted."
else
    write_result "Audit Result: **FAIL** – ptrace_scope is NOT set to 1."
fi

# ========================================
# 1.5.3 Ensure core dumps are restricted
# ========================================
write_section "CIS Section: 1.5.3 – Ensure core dumps are restricted"
write_rationale "Core dumps can expose sensitive data. Restricting them limits attack surface and information leakage."

LIMITS_CHECK=$(grep -Ps -- '^\h*\*\h+hard\h+core\h+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null)
COREDUMP_PARAM=$(sysctl fs.suid_dumpable | awk '{print $3}')
echo "Current State:" >> "$REPORT_FILE"
if [[ -n "$LIMITS_CHECK" ]]; then
    echo "$LIMITS_CHECK" >> "$REPORT_FILE"
else
    echo "No hard core dump limit found in limits.conf or limits.d." >> "$REPORT_FILE"
fi

echo "fs.suid_dumpable = $COREDUMP_PARAM" >> "$REPORT_FILE"

if [[ -n "$LIMITS_CHECK" && "$COREDUMP_PARAM" == "0" ]]; then
    write_result "Audit Result: **PASS** – Core dumps are restricted."
else
    write_result "Audit Result: **FAIL** – Core dump restrictions not fully enforced."
fi

# ========================================
# 1.5.4 Ensure prelink is not installed
# ========================================
write_section "CIS Section: 1.5.4 – Ensure prelink is not installed"
write_rationale "Prelink modifies binaries, making it difficult to track changes and potentially introducing security risks."

if dpkg-query -s prelink &>/dev/null; then
    write_result "Current State: prelink is installed."
    write_result "Audit Result: **FAIL** – prelink should not be installed."
else
    write_result "Current State: prelink is NOT installed."
    write_result "Audit Result: **PASS** – prelink is not present."
fi

# ========================================
# 1.5.5 Ensure Automatic Error Reporting is not enabled
# ========================================
write_section "CIS Section: 1.5.5 – Ensure Automatic Error Reporting is not enabled"
write_rationale "Automatic crash reports may expose sensitive data like passwords and private logs."

APPORT_ENABLED=$(grep -Psi -- '^\h*enabled\h*=\h*[^0]\b' /etc/default/apport 2>/dev/null)
APPORT_STATUS=$(systemctl is-active apport.service 2>/dev/null)

echo "Current State:" >> "$REPORT_FILE"
if [[ -n "$APPORT_ENABLED" ]]; then
    echo "Enabled in /etc/default/apport:" >> "$REPORT_FILE"
    echo "$APPORT_ENABLED" >> "$REPORT_FILE"
else
    echo "Apport not enabled in /etc/default/apport or value is 0." >> "$REPORT_FILE"
fi

echo "apport.service status: $APPORT_STATUS" >> "$REPORT_FILE"

if [[ -z "$APPORT_ENABLED" && "$APPORT_STATUS" != "active" ]]; then
    write_result "Audit Result: **PASS** – Automatic error reporting is disabled."
else
    write_result "Audit Result: **FAIL** – Apport error reporting is active or enabled."
fi


# =============================
# Section 1.5 - Process Hardening
# =============================

REPORT_DIR="SEND_TO_MAOR"
REPORT_FILE="$REPORT_DIR/process_hardening.txt"

mkdir -p "$REPORT_DIR"

write_section() {
    echo -e "\n---\n$1\n---\n" >> "$REPORT_FILE"
}

write_rationale() {
    echo -e "Rationale:\n$1\n" >> "$REPORT_FILE"
}

write_result() {
    echo -e "$1\n" >> "$REPORT_FILE"
}

# ========================================
# 1.5.1 Ensure address space layout randomization is enabled
# ========================================
write_section "CIS Section: 1.5.1 – Ensure ASLR is enabled"
write_rationale "Randomly placing virtual memory regions makes it harder for attackers to exploit memory-related vulnerabilities."

ASLR=$(sysctl kernel.randomize_va_space | awk '{print $3}')
echo "Current State:" >> "$REPORT_FILE"
echo "kernel.randomize_va_space = $ASLR" >> "$REPORT_FILE"

if [[ "$ASLR" == "2" ]]; then
    write_result "Audit Result: **PASS** – ASLR is enabled."
else
    write_result "Audit Result: **FAIL** – ASLR is NOT set to 2."
fi

# ========================================
# 1.5.2 Ensure ptrace_scope is restricted
# ========================================
write_section "CIS Section: 1.5.2 – Ensure ptrace_scope is restricted"
write_rationale "Restricting ptrace reduces the ability of compromised processes to inspect other processes, helping contain attacks."

PTRACE=$(sysctl kernel.yama.ptrace_scope | awk '{print $3}')
echo "Current State:" >> "$REPORT_FILE"
echo "kernel.yama.ptrace_scope = $PTRACE" >> "$REPORT_FILE"

if [[ "$PTRACE" == "1" ]]; then
    write_result "Audit Result: **PASS** – ptrace_scope is restricted."
else
    write_result "Audit Result: **FAIL** – ptrace_scope is NOT set to 1."
fi

# ========================================
# 1.5.3 Ensure core dumps are restricted
# ========================================
write_section "CIS Section: 1.5.3 – Ensure core dumps are restricted"
write_rationale "Core dumps can expose sensitive data. Restricting them limits attack surface and information leakage."

LIMITS_CHECK=$(grep -Ps -- '^\h*\*\h+hard\h+core\h+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null)
COREDUMP_PARAM=$(sysctl fs.suid_dumpable | awk '{print $3}')
echo "Current State:" >> "$REPORT_FILE"
if [[ -n "$LIMITS_CHECK" ]]; then
    echo "$LIMITS_CHECK" >> "$REPORT_FILE"
else
    echo "No hard core dump limit found in limits.conf or limits.d." >> "$REPORT_FILE"
fi

echo "fs.suid_dumpable = $COREDUMP_PARAM" >> "$REPORT_FILE"

if [[ -n "$LIMITS_CHECK" && "$COREDUMP_PARAM" == "0" ]]; then
    write_result "Audit Result: **PASS** – Core dumps are restricted."
else
    write_result "Audit Result: **FAIL** – Core dump restrictions not fully enforced."
fi

# ========================================
# 1.5.4 Ensure prelink is not installed
# ========================================
write_section "CIS Section: 1.5.4 – Ensure prelink is not installed"
write_rationale "Prelink modifies binaries, making it difficult to track changes and potentially introducing security risks."

if dpkg-query -s prelink &>/dev/null; then
    write_result "Current State: prelink is installed."
    write_result "Audit Result: **FAIL** – prelink should not be installed."
else
    write_result "Current State: prelink is NOT installed."
    write_result "Audit Result: **PASS** – prelink is not present."
fi

# ========================================
# 1.5.5 Ensure Automatic Error Reporting is not enabled
# ========================================
write_section "CIS Section: 1.5.5 – Ensure Automatic Error Reporting is not enabled"
write_rationale "Automatic crash reports may expose sensitive data like passwords and private logs."

APPORT_ENABLED=$(grep -Psi -- '^\h*enabled\h*=\h*[^0]\b' /etc/default/apport 2>/dev/null)
APPORT_STATUS=$(systemctl is-active apport.service 2>/dev/null)

echo "Current State:" >> "$REPORT_FILE"
if [[ -n "$APPORT_ENABLED" ]]; then
    echo "Enabled in /etc/default/apport:" >> "$REPORT_FILE"
    echo "$APPORT_ENABLED" >> "$REPORT_FILE"
else
    echo "Apport not enabled in /etc/default/apport or value is 0." >> "$REPORT_FILE"
fi

echo "apport.service status: $APPORT_STATUS" >> "$REPORT_FILE"

if [[ -z "$APPORT_ENABLED" && "$APPORT_STATUS" != "active" ]]; then
    write_result "Audit Result: **PASS** – Automatic error reporting is disabled."
else
    write_result "Audit Result: **FAIL** – Apport error reporting is active or enabled."
fi

# =============================
# Section 1.6 - Command Line Warning Banners
# =============================

REPORT_DIR="SEND_TO_MAOR"
REPORT_FILE="$REPORT_DIR/command_line_banners.txt"

mkdir -p "$REPORT_DIR"

write_section() {
    echo -e "\n---\n$1\n---\n" >> "$REPORT_FILE"
}

write_rationale() {
    echo -e "Rationale:\n$1\n" >> "$REPORT_FILE"
}

write_result() {
    echo -e "$1\n" >> "$REPORT_FILE"
}

check_banner_content() {
    FILE="$1"
    FILE_NAME="$2"
    BANNER_CONTENT=$(cat "$FILE" 2>/dev/null)
    OS_ID=$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed 's/\"//g')
    BAD=$(grep -E -i "(\\\\v|\\\\r|\\\\m|\\\\s|$OS_ID)" "$FILE" 2>/dev/null)

    echo "Current State of $FILE_NAME:" >> "$REPORT_FILE"
    if [[ -n "$BANNER_CONTENT" ]]; then
        echo "$BANNER_CONTENT" >> "$REPORT_FILE"
    else
        echo "File is empty or not found." >> "$REPORT_FILE"
    fi

    if [[ -z "$BAD" ]]; then
        write_result "Audit Result: **PASS** – $FILE_NAME does not expose OS details."
    else
        write_result "Audit Result: **FAIL** – $FILE_NAME contains OS-identifying information."
    fi
}

check_permissions() {
    FILE="$1"
    FILE_NAME="$2"

    if [[ -e "$FILE" ]]; then
        STATS=$(stat -Lc 'Access: (%#a/%A) Uid: (%u/%U) Gid: (%g/%G)' "$FILE")
        echo "Current State of $FILE_NAME permissions:" >> "$REPORT_FILE"
        echo "$STATS" >> "$REPORT_FILE"

        PERMS=$(stat -Lc '%a' "$FILE")
        UID=$(stat -Lc '%u' "$FILE")
        GID=$(stat -Lc '%g' "$FILE")

        if [[ "$PERMS" -le 644 && "$UID" -eq 0 && "$GID" -eq 0 ]]; then
            write_result "Audit Result: **PASS** – $FILE_NAME has secure ownership and permissions."
        else
            write_result "Audit Result: **FAIL** – $FILE_NAME permissions/ownership are too permissive."
        fi
    else
        write_result "Current State of $FILE_NAME: File not found."
        write_result "Audit Result: **PASS** – $FILE_NAME not present."
    fi
}

# 1.6.1 – /etc/motd banner content
write_section "CIS Section: 1.6.1 – Ensure /etc/motd is configured properly"
write_rationale "Login banners must inform users of authorized access only and avoid exposing OS information."
check_banner_content "/etc/motd" "/etc/motd"

# 1.6.2 – /etc/issue local login banner content
write_section "CIS Section: 1.6.2 – Ensure /etc/issue is configured properly"
write_rationale "Local login banners must warn users and not reveal system details to potential attackers."
check_banner_content "/etc/issue" "/etc/issue"

# 1.6.3 – /etc/issue.net remote login banner content
write_section "CIS Section: 1.6.3 – Ensure /etc/issue.net is configured properly"
write_rationale "Remote login banners should not leak OS or architecture data and must include legal warning."
check_banner_content "/etc/issue.net" "/etc/issue.net"

# 1.6.4 – /etc/motd permissions
write_section "CIS Section: 1.6.4 – Ensure access to /etc/motd is configured"
write_rationale "If motd can be modified by unauthorized users, it can mislead or expose sensitive system context."
check_permissions "/etc/motd" "/etc/motd"

# 1.6.5 – /etc/issue permissions
write_section "CIS Section: 1.6.5 – Ensure access to /etc/issue is configured"
write_rationale "Ensure that the local login banner cannot be tampered with by non-privileged users."
check_permissions "/etc/issue" "/etc/issue"

# 1.6.6 – /etc/issue.net permissions
write_section "CIS Section: 1.6.6 – Ensure access to /etc/issue.net is configured"
write_rationale "Remote banner should not be editable by unprivileged users to prevent misleading or leaking content."
check_permissions "/etc/issue.net" "/etc/issue.net"

#!/usr/bin/env bash

# =============================
# Section 1.7 - Configure GNOME Display Manager (GDM)
# CIS Ubuntu 22.04 LTS
# =============================

REPORT_DIR="SEND_TO_MAOR"
REPORT_FILE="$REPORT_DIR/gdm_configuration_audit.txt"

mkdir -p "$REPORT_DIR"

write_section() {
    echo -e "\n---\n$1\n---\n" >> "$REPORT_FILE"
}

write_rationale() {
    echo -e "Rationale:\n$1\n" >> "$REPORT_FILE"
}

write_result() {
    echo -e "$1\n" >> "$REPORT_FILE"
}

# --- 1.7.1 Ensure GDM is removed ---
write_section "CIS Section: 1.7.1 – Ensure GDM is removed"
write_rationale "Remove GDM if GUI is not required, to reduce the attack surface."
if dpkg-query -s gdm3 &>/dev/null; then
    write_result "Current State: gdm3 is installed"
    write_result "Audit Result: **FAIL** – gdm3 is installed"
else
    write_result "Current State: gdm3 is not installed"
    write_result "Audit Result: **PASS** – gdm3 is not installed"
fi

# --- 1.7.2 to 1.7.9: Check dconf settings ---
declare -A GDM_CHECKS=(
  ["1.7.2"]="disable-user-list"
  ["1.7.3"]="banner-message-enable"
  ["1.7.4"]="banner-message-text"
  ["1.7.5"]="disable-automatic-login"
  ["1.7.6"]="disable-guest-login"
  ["1.7.7"]="automatic-login-enable"
  ["1.7.8"]="automatic-login"
  ["1.7.9"]="enable"
)

for key in "${!GDM_CHECKS[@]}"; do
  conf_key="${GDM_CHECKS[$key]}"
  write_section "CIS Section: $key – Ensure $conf_key is properly configured"
  conf_file=$(grep -r "^$conf_key" /etc/dconf/db/ 2>/dev/null | cut -d":" -f1 | head -n1)
  if [[ -n "$conf_file" ]]; then
    value=$(grep -E "^$conf_key" "$conf_file" | awk -F= '{print $2}' | xargs)
    write_result "Current State: Found $conf_key=$value in $conf_file"
    if [[ "$value" =~ ^(true|false|".*")$ ]]; then
      write_result "Audit Result: **PASS** – $conf_key is explicitly configured"
    else
      write_result "Audit Result: **FAIL** – $conf_key has invalid or missing value"
    fi
  else
    write_result "Current State: $conf_key not found in /etc/dconf/db/"
    write_result "Audit Result: **FAIL** – $conf_key is not configured"
  fi
  write_rationale "This setting controls GDM behavior related to security and login restrictions."
done

# --- 1.7.10 Ensure XDMCP is not enabled ---
write_section "CIS Section: 1.7.10 – Ensure XDMCP is not enabled"
write_rationale "XDMCP is an insecure protocol that may expose sensitive data like user credentials."
XDMCP_FILES=$(grep -Psil -- '^[ \t]*\[xdmcp\]' /etc/{gdm3,gdm}/{custom,daemon}.conf 2>/dev/null)
FOUND=0
for FILE in $XDMCP_FILES; do
    if awk '/\[xdmcp\]/{f=1;next}/\[/{f=0}f && /Enable\s*=\s*true/' "$FILE" | grep -q .; then
        write_result "Current State: XDMCP enabled in $FILE"
        write_result "Audit Result: **FAIL** – XDMCP is enabled in $FILE"
        FOUND=1
    fi
done
if [[ $FOUND -eq 0 ]]; then
    if [[ -z "$XDMCP_FILES" ]]; then
        write_result "Current State: No XDMCP configuration block found"
    else
        write_result "Current State: No Enable=true under [xdmcp] block found in scanned files"
    fi
    write_result "Audit Result: **PASS** – XDMCP is not enabled"
fi

# =============================
# Section 2.1 - Services - Audit Only
# =============================

REPORT_DIR="$HOME/Desktop/SEND_TO_MAOR"
REPORT_FILE="$REPORT_DIR/cis_2.1_services_audit.txt"

mkdir -p "$REPORT_DIR"

write_section() {
    echo -e "\n---\nCIS Section: $1\n---\n" >> "$REPORT_FILE"
}

write_rationale() {
    echo -e "Rationale:\n$1\n" >> "$REPORT_FILE"
}

write_result() {
    echo -e "$1\n" >> "$REPORT_FILE"
}

audit_service_disabled() {
    SERVICE_NAME="$1"
    CIS_ID="$2"
    RATIONALE="$3"

    write_section "$CIS_ID"
    write_rationale "$RATIONALE"

    if systemctl is-enabled "$SERVICE_NAME" &>/dev/null; then
        CUR_STATE="ENABLED"
    else
        CUR_STATE="DISABLED"
    fi

    write_result "Current State: $SERVICE_NAME is $CUR_STATE"

    if [[ "$CUR_STATE" == "DISABLED" ]]; then
        write_result "Audit Result: **PASS** – $SERVICE_NAME is disabled"
    else
        write_result "Audit Result: **FAIL** – $SERVICE_NAME is enabled"
    fi
}

# === 2.1.1 to 2.1.22 ===
audit_service_disabled avahi-daemon "2.1.1 – Ensure Avahi Server is not enabled" \
    "Avahi can be used to discover hosts/services which may not be intended for sharing."

audit_service_disabled cups "2.1.2 – Ensure CUPS is not enabled" \
    "CUPS is used for printer services and may not be required in minimal environments."

audit_service_disabled isc-dhcp-server "2.1.3 – Ensure DHCP Server is not enabled" \
    "A DHCP server can interfere with managed networks or unintentionally provide IPs."

audit_service_disabled slapd "2.1.4 – Ensure LDAP server is not enabled" \
    "LDAP servers expose authentication directories which can be a security concern."

audit_service_disabled nfs-server "2.1.5 – Ensure NFS and RPC are not enabled" \
    "NFS and RPC can expose file shares and remote procedure calls across networks."

audit_service_disabled bind9 "2.1.6 – Ensure DNS Server is not enabled" \
    "Running a DNS server unnecessarily can allow abuse or DNS poisoning."

audit_service_disabled vsftpd "2.1.7 – Ensure FTP Server is not enabled" \
    "FTP transmits data in plaintext, including credentials, which can be intercepted."

audit_service_disabled apache2 "2.1.8 – Ensure HTTP server is not enabled" \
    "HTTP servers may expose unneeded web interfaces or content."

audit_service_disabled dovecot "2.1.9 – Ensure IMAP and POP3 server is not enabled" \
    "Mail protocols may reveal user data or increase the attack surface."

audit_service_disabled samba "2.1.10 – Ensure Samba is not enabled" \
    "Samba exposes Windows-compatible file sharing and authentication."

audit_service_disabled squid "2.1.11 – Ensure HTTP Proxy Server is not enabled" \
    "Proxy servers can be misused to bypass network policies."

audit_service_disabled snmpd "2.1.12 – Ensure SNMP Server is not enabled" \
    "SNMP can leak system details and be abused if misconfigured."

audit_service_disabled rsync "2.1.13 – Ensure rsync service is not enabled" \
    "Rsync in daemon mode exposes file synchronization endpoints."

audit_service_disabled nis "2.1.14 – Ensure NIS Server is not enabled" \
    "NIS is an old authentication system with known weaknesses."

audit_service_disabled rpcbind "2.1.15 – Ensure rpcbind is not enabled" \
    "rpcbind allows RPC services to be located and used across the network."

audit_service_disabled telnet.socket "2.1.16 – Ensure Telnet Server is not enabled" \
    "Telnet transmits all data in cleartext and is deprecated."

audit_service_disabled tftp "2.1.17 – Ensure TFTP Server is not enabled" \
    "TFTP has no authentication and is insecure over untrusted networks."

audit_service_disabled rsyslog "2.1.18 – Ensure rsyslog is not enabled (if not needed)" \
    "Logging services should be explicitly required and configured."

audit_service_disabled nscd "2.1.19 – Ensure nscd is not enabled" \
    "nscd caches credentials and if misused can lead to privilege issues."

audit_service_disabled chrony "2.1.20 – Ensure chrony is not enabled unless required" \
    "Time services should be used only if they serve system purpose explicitly."

audit_service_disabled systemd-timesyncd "2.1.21 – Ensure systemd-timesyncd is not enabled unless required" \
    "Prevent automatic time sync unless system depends on it."

audit_service_disabled bluetooth "2.1.22 – Ensure Bluetooth is disabled if not needed" \
    "Bluetooth can expose the system to local attacks if unused."

write_result "\nINFO: כל שירות נבדק לפי האם הוא מופעל ומוגדר להפעלה אוטומטית (systemctl is-enabled)."
write_result "אם תרצה שגם תתבצע בדיקה אם השירות רץ בפועל (systemctl is-active), תוכל לבקש תוספת."

exit 0









