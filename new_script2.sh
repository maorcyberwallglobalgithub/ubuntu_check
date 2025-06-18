#!/usr/bin/env bash

# =============================
# SETUP
# =============================

OUTPUT_DIR="$HOME/Desktop/SEND_TO_MAOR2"
mkdir -p "$OUTPUT_DIR"

# =============================
# SECTION 2.2: Client Services
# =============================

OUTPUT_FILE="$OUTPUT_DIR/configure_client_services.txt"

echo "# =============================" > "$OUTPUT_FILE"
echo "# CIS Section 2.2 - Client Services - Audit" >> "$OUTPUT_FILE"
echo "# =============================" >> "$OUTPUT_FILE"

audit_package() {
    local package_name="$1"
    local section="$2"
    local rationale="$3"
    local expected_value="The package '$package_name' should NOT be installed."

    echo -e "\n---" >> "$OUTPUT_FILE"
    echo "CIS Section: $section – Ensure $package_name is not installed" >> "$OUTPUT_FILE"
    echo -e "\nRationale:\n$rationale\n" >> "$OUTPUT_FILE"

    if dpkg-query -s "$package_name" &>/dev/null; then
        echo -e "Current State:\nThe package '$package_name' is INSTALLED.\n" >> "$OUTPUT_FILE"
        echo -e "Best Practice / Expected Value:\n$expected_value\n" >> "$OUTPUT_FILE"
        echo "Audit Result: **FAIL**" >> "$OUTPUT_FILE"
    else
        echo -e "Current State:\nThe package '$package_name' is NOT installed.\n" >> "$OUTPUT_FILE"
        echo -e "Best Practice / Expected Value:\n$expected_value\n" >> "$OUTPUT_FILE"
        echo "Audit Result: **PASS**" >> "$OUTPUT_FILE"
    fi
}

audit_package "nis" "2.2.1" "NIS is insecure and deprecated. It should be removed."
audit_package "rsh-client" "2.2.2" "rsh is obsolete and insecure. Use SSH instead."
audit_package "talk" "2.2.3" "talk transmits unencrypted messages and should be removed."
audit_package "telnet" "2.2.4" "Telnet transmits credentials in clear text. Use SSH instead."
audit_package "ldap-utils" "2.2.5" "Should be removed unless explicitly needed."
audit_package "ftp" "2.2.6" "FTP is insecure. Use SFTP or SCP instead."

echo -e "\nAudit complete. Results saved to $OUTPUT_FILE"

# =============================
# SECTION 2.3.1.1: Time Synchronization
# =============================

OUTPUT_FILE="$OUTPUT_DIR/ensure_time_sync.txt"

{
  echo "# ============================="
  echo "# CIS Section 2.3.1.1 - Time Synchronization - Audit"
  echo "# ============================="
  echo -e "\nRationale:"
  echo "Ensures consistency of logs and time-based security mechanisms."

  SYSTEMD_STATUS=""
  CHRONY_STATUS=""

  if systemctl is-enabled systemd-timesyncd.service &>/dev/null; then
    SYSTEMD_STATUS+="- systemd-timesyncd is ENABLED\n"
  else
    SYSTEMD_STATUS+="- systemd-timesyncd is NOT enabled\n"
  fi
  if systemctl is-active systemd-timesyncd.service &>/dev/null; then
    SYSTEMD_STATUS+="- systemd-timesyncd is ACTIVE\n"
  else
    SYSTEMD_STATUS+="- systemd-timesyncd is NOT active\n"
  fi

  if systemctl is-enabled chrony.service &>/dev/null; then
    CHRONY_STATUS+="- chrony is ENABLED\n"
  else
    CHRONY_STATUS+="- chrony is NOT enabled\n"
  fi
  if systemctl is-active chrony.service &>/dev/null; then
    CHRONY_STATUS+="- chrony is ACTIVE\n"
  else
    CHRONY_STATUS+="- chrony is NOT active\n"
  fi

  TIMESYNCD_ENABLED=$(systemctl is-enabled systemd-timesyncd.service | grep -c enabled)
  CHRONY_ENABLED=$(systemctl is-enabled chrony.service | grep -c enabled)

  if [ "$TIMESYNCD_ENABLED" -eq 1 ] && [ "$CHRONY_ENABLED" -eq 1 ]; then
    echo -e "\nCurrent State:\n$SYSTEMD_STATUS$CHRONY_STATUS"
    echo -e "\nBest Practice / Expected Value:\nOnly one time daemon should be active."
    echo -e "\nAudit Result: **FAIL**"
  elif [ "$TIMESYNCD_ENABLED" -eq 0 ] && [ "$CHRONY_ENABLED" -eq 0 ]; then
    echo -e "\nCurrent State:\n$SYSTEMD_STATUS$CHRONY_STATUS"
    echo -e "\nBest Practice / Expected Value:\nAt least one time daemon should be active."
    echo -e "\nAudit Result: **FAIL**"
  else
    echo -e "\nCurrent State:\n$SYSTEMD_STATUS$CHRONY_STATUS"
    echo -e "\nBest Practice / Expected Value:\nOnly one time daemon should be active."
    echo -e "\nAudit Result: **PASS**"
  fi
} > "$OUTPUT_FILE"

echo "Audit for time synchronization complete. Results saved to $OUTPUT_FILE"

# =============================
# SECTION 2.3.2.1 & 2.3.2.2: systemd-timesyncd Configuration
# =============================

# =============================
# SECTION 2.3.2.1 & 2.3.2.2: systemd-timesyncd Configuration
# =============================

OUTPUT_FILE="$OUTPUT_DIR/systemd_timesyncd_conf.txt"

{
  echo "# ============================="
  echo "# CIS Section 2.3.2.1 & 2.3.2.2 - systemd-timesyncd Configuration"
  echo "# ============================="

  echo -e "\nRationale:"
  echo "Ensuring time synchronization uses defined and trusted NTP servers prevents tampering or incorrect logging timestamps. systemd-timesyncd must be configured properly and enabled."

  TIMESYNCD_FILE="/etc/systemd/timesyncd.conf"

  if [ -f "$TIMESYNCD_FILE" ]; then
    NTP_VAL=$(grep -E '^\s*NTP=' "$TIMESYNCD_FILE" | cut -d '=' -f2 | xargs)
    FBNTP_VAL=$(grep -E '^\s*FallbackNTP=' "$TIMESYNCD_FILE" | cut -d '=' -f2 | xargs)

    echo -e "\nCurrent State:"
    echo "NTP=$NTP_VAL"
    echo "FallbackNTP=$FBNTP_VAL"

    echo -e "\nBest Practice / Expected Value:"
    echo "The file $TIMESYNCD_FILE should define NTP and FallbackNTP with trusted time sources."

    if [[ -n "$NTP_VAL" && -n "$FBNTP_VAL" ]]; then
      echo -e "\nAudit Result: **PASS**"
      echo -e "\nRecommendation:"
      echo "No action needed — trusted servers are defined."
    else
      echo -e "\nAudit Result: **FAIL**"
      echo -e "\nRecommendation:"
      echo "Edit $TIMESYNCD_FILE and define NTP and FallbackNTP, e.g.:\n  NTP=time.cloudflare.com\n  FallbackNTP=time.google.com"
    fi
  else
    echo -e "\nCurrent State:"
    echo "$TIMESYNCD_FILE does not exist."

    echo -e "\nBest Practice / Expected Value:"
    echo "$TIMESYNCD_FILE should exist and define NTP and FallbackNTP values."

    echo -e "\nAudit Result: **FAIL**"
    echo -e "\nRecommendation:"
    echo "Create the file $TIMESYNCD_FILE and define trusted NTP servers in it."
  fi

  echo -e "\nChecking if systemd-timesyncd service is enabled and active..."

  ENABLED=$(systemctl is-enabled systemd-timesyncd.service 2>/dev/null)
  ACTIVE=$(systemctl is-active systemd-timesyncd.service 2>/dev/null)

  echo -e "\nCurrent State:"
  echo "Enabled: $ENABLED"
  echo "Active: $ACTIVE"

  echo -e "\nBest Practice / Expected Value:"
  echo "systemd-timesyncd should be enabled and running."

  if [[ "$ENABLED" == "enabled" && "$ACTIVE" == "active" ]]; then
    echo -e "\nAudit Result: **PASS**"
    echo -e "\nRecommendation:"
    echo "No action needed — service is enabled and running."
  else
    echo -e "\nAudit Result: **FAIL**"
    echo -e "\nRecommendation:"
    echo "Run the following to enable and start the service:\n  systemctl enable --now systemd-timesyncd.service"
  fi
} > "$OUTPUT_FILE"

echo "systemd-timesyncd audit complete. Output saved to $OUTPUT_FILE"
# =============================
# SECTION 2.3.3.1 – Chrony Configured with Authorized Timeserver
# =============================

OUTPUT_FILE="$OUTPUT_DIR/chrony_audit.txt"

{
  echo "# ============================="
  echo "# CIS Section 2.3.3.1 - Ensure chrony is configured with authorized timeserver"
  echo "# ============================="
  echo -e "\nRationale:"
  echo "Chrony must be configured with trusted time sources to ensure log and system consistency."

  CHRONY_CONF="/etc/chrony/chrony.conf"

  if grep -Eq '^\s*(server|pool)\s+\S+' "$CHRONY_CONF"; then
    echo -e "\nCurrent State:"
    grep -E '^\s*(server|pool)\s+\S+' "$CHRONY_CONF"
    echo -e "\nBest Practice / Expected Value:"
    echo "chrony.conf must include at least one authorized server or pool directive."
    echo -e "\nAudit Result: **PASS**"
    echo -e "\nRecommendation: No action needed."
  else
    echo -e "\nCurrent State: No time servers configured in $CHRONY_CONF."
    echo -e "\nBest Practice / Expected Value:"
    echo "Include at least one line: 'server <approved-timeserver> iburst'"
    echo -e "\nAudit Result: **FAIL**"
    echo -e "\nRecommendation: Edit $CHRONY_CONF and add a valid time server."
  fi

# =============================
# SECTION 2.3.3.2 – Chrony Running as _chrony
# =============================

  echo "\n---"
  echo "CIS Section: 2.3.3.2 – Ensure chrony is running as user _chrony"
  echo -e "\nRationale:"
  echo "Minimizing privileges for chrony limits exposure if compromised."

  if pgrep chronyd &>/dev/null; then
    BAD_USERS=$(ps -eo user,comm | awk '$2=="chronyd" && $1!="_chrony" {print $1}')
    if [[ -z "$BAD_USERS" ]]; then
      echo -e "\nCurrent State: chronyd is running as user: _chrony"
      echo -e "\nBest Practice / Expected Value: chronyd should run as user _chrony."
      echo -e "\nAudit Result: **PASS**"
      echo -e "\nRecommendation: No action needed."
    else
      echo -e "\nCurrent State: chronyd is running as: $BAD_USERS"
      echo -e "\nBest Practice / Expected Value: chronyd should run as user _chrony."
      echo -e "\nAudit Result: **FAIL**"
      echo -e "\nRecommendation: Set 'user _chrony' in $CHRONY_CONF and restart the service."
    fi
  else
    echo -e "\nCurrent State: chronyd not running."
    echo -e "\nAudit Result: **SKIPPED**"
    echo -e "\nRecommendation: Start chronyd service and configure appropriately."
  fi

# =============================
# SECTION 2.3.3.3 – Chrony is Enabled and Running
# =============================

  echo "\n---"
  echo "CIS Section: 2.3.3.3 – Ensure chrony is enabled and running"
  echo -e "\nRationale:"
  echo "Ensures consistent timekeeping for logs and security mechanisms."

  CHRONY_ENABLED=$(systemctl is-enabled chrony.service 2>/dev/null)
  CHRONY_ACTIVE=$(systemctl is-active chrony.service 2>/dev/null)

  echo -e "\nCurrent State:"
  echo "Enabled: $CHRONY_ENABLED"
  echo "Active: $CHRONY_ACTIVE"

  if [[ "$CHRONY_ENABLED" == "enabled" && "$CHRONY_ACTIVE" == "active" ]]; then
    echo -e "\nAudit Result: **PASS**"
    echo -e "\nRecommendation: No action needed."
  else
    echo -e "\nAudit Result: **FAIL**"
    echo -e "\nRecommendation: Run: systemctl --now enable chrony.service"
  fi
} > "$OUTPUT_FILE"

echo "Chrony audit complete. Output saved to $OUTPUT_FILE"

# =============================
# SECTION 2.4.2.1 – Ensure 'at' is restricted to authorized users
# =============================

OUTPUT_FILE="$OUTPUT_DIR/at_audit.txt"

{
  echo "# ============================="
  echo "# CIS Section 2.4.2.1 – Ensure 'at' is restricted to authorized users"
  echo "# ============================="
  echo -e "\nRationale:"
  echo "Restricting 'at' limits unauthorized job scheduling, reducing abuse risk."

  if command -v at &>/dev/null; then
    echo -e "\n'at' is installed. Checking /etc/at.allow and /etc/at.deny"

    if [ -f /etc/at.allow ]; then
      STAT=$(stat -Lc 'Access: (%a/%A) Owner: (%U) Group: (%G)' /etc/at.allow)
      echo -e "\nCurrent State:\n$STAT"
      echo -e "\nBest Practice / Expected Value:\nMode 640, Owner root, Group root or daemon."
      echo -e "\nRecommendation: Use chown root:root and chmod 640 if needed."
    else
      echo -e "\nCurrent State: /etc/at.allow does not exist."
      echo -e "\nBest Practice / Expected Value: It should exist with proper permissions."
      echo -e "\nRecommendation: Create the file with correct ownership and permissions."
    fi

    if [ -f /etc/at.deny ]; then
      STAT=$(stat -Lc 'Access: (%a/%A) Owner: (%U) Group: (%G)' /etc/at.deny)
      echo -e "\nCurrent State:\n$STAT"
      echo -e "\nBest Practice / Expected Value:\nMode 640, Owner root, Group root or daemon."
      echo -e "\nRecommendation: Adjust using chown and chmod as needed."
    else
      echo -e "\nCurrent State: /etc/at.deny does not exist."
      echo -e "\nAudit Result: **PASS**"
      echo -e "\nRecommendation: No action needed."
    fi
  else
    echo -e "\n'at' not installed. Skipping check."
  fi
} > "$OUTPUT_FILE"

echo "Audit complete for 'at' configuration. Output saved to $OUTPUT_FILE"

# =============================
# SECTION 3.1: Configure Network Devices
# =============================

OUTPUT_FILE="$OUTPUT_DIR/configure_network_devices.txt"

{
  echo "# ============================="
  echo "# CIS Section 3.1 - Configure Network Devices"
  echo "# ============================="

  # 3.1.1 Ensure IPv6 status is identified
  echo -e "\n---"
  echo "CIS Section: 3.1.1 – Ensure IPv6 status is identified"
  echo -e "\nRationale: IPv6 should be enabled and configured unless prohibited by local policy."
  if grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable; then
    echo -e "\nCurrent State:\n - IPv6 is enabled"
    echo -e "\nBest Practice / Expected Value:\nIPv6 should be enabled and configured properly."
    echo -e "\nAudit Result: **PASS**"
  else
    echo -e "\nCurrent State:\n - IPv6 is not enabled"
    echo -e "\nBest Practice / Expected Value:\nEnable or disable IPv6 in accordance with system requirements."
    echo -e "\nAudit Result: **FAIL**"
  fi

  # 3.1.2 Ensure wireless interfaces are disabled
  echo -e "\n---"
  echo "CIS Section: 3.1.2 – Ensure wireless interfaces are disabled"
  echo -e "\nRationale: If wireless is not used, interfaces should be disabled to reduce attack surface."

  l_output=""; l_output2=""
  module_chk() {
    l_loadable="$(modprobe -n -v "$l_mname")"
    if grep -Pq -- '^\h*install /bin/(true|false)' <<< "$l_loadable"; then
      l_output+="\n - module: \"$l_mname\" is not loadable: \"$l_loadable\""
    else
      l_output2+="\n - module: \"$l_mname\" is loadable: \"$l_loadable\""
    fi
    if ! lsmod | grep "$l_mname" >/dev/null 2>&1; then
      l_output+="\n - module: \"$l_mname\" is not loaded"
    else
      l_output2+="\n - module: \"$l_mname\" is loaded"
    fi
    if modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mname\b"; then
      l_output+="\n - module: \"$l_mname\" is deny listed"
    else
      l_output2+="\n - module: \"$l_mname\" is not deny listed"
    fi
  }
  if [ -n "$(find /sys/class/net/*/ -type d -name wireless 2>/dev/null)" ]; then
    l_dname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless); do basename "$(readlink -f "$driverdir"/device/driver/module)"; done | sort -u)
    for l_mname in $l_dname; do module_chk; done
  fi
  if [ -z "$l_output2" ]; then
    echo -e "\nAudit Result: **PASS**"
    [ -z "$l_output" ] && echo -e "\n - System has no wireless NICs installed" || echo -e "\n$l_output"
  else
    echo -e "\nAudit Result: **FAIL**\nReasons:\n$l_output2"
    [ -n "$l_output" ] && echo -e "\nCorrectly configured:\n$l_output"
  fi

  # 3.1.3 Ensure bluetooth services are not in use
  echo -e "\n---"
  echo "CIS Section: 3.1.3 – Ensure bluetooth services are not in use"
  echo -e "\nRationale: Bluetooth introduces attack vectors like bluesnarfing, malware infections, etc."

  if dpkg-query -s bluez &>/dev/null; then
    echo -e "\nCurrent State:\nbluez is installed"
    echo -e "\nBest Practice / Expected Value:\nThe bluez package should be removed or service masked."
    echo -e "\nAudit Result: **FAIL**"
  else
    echo -e "\nCurrent State:\nbluez is NOT installed"
    echo -e "\nBest Practice / Expected Value:\nThe bluez package should be removed."
    echo -e "\nAudit Result: **PASS**"
  fi

  echo -e "\nAudit complete. Results written to: $OUTPUT_FILE"
} > "$OUTPUT_FILE"

# =============================
# SECTION 3.2: Network Kernel Modules
# =============================

MODULES_OUTPUT_FILE="$OUTPUT_DIR/configure_network_kernel_modules.txt"

run_module_check() {
  local module_name="$1"
  local l_output=""
  local l_output2=""
  local l_output3=""
  local l_dl=""
  local l_searchloc="/lib/modprobe.d/*.conf /usr/local/lib/modprobe.d/*.conf /run/modprobe.d/*.conf /etc/modprobe.d/*.conf"
  local l_mpath="/lib/modules/**/kernel/net"
  local l_mpname="$(tr '-' '_' <<< "$module_name")"
  local l_mndir="$(tr '-' '/' <<< "$module_name")"

  module_loadable_chk() {
    l_loadable="$(modprobe -n -v "$module_name")"
    [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P -- '(^\h*install|\b$module_name)\b' <<< "$l_loadable")"
    if grep -Pq -- '^\h*install /bin/(true|false)' <<< "$l_loadable"; then
      l_output+="\n - module: \"$module_name\" is not loadable: \"$l_loadable\""
    else
      l_output2+="\n - module: \"$module_name\" is loadable: \"$l_loadable\""
    fi
  }

  module_loaded_chk() {
    if ! lsmod | grep "$module_name" > /dev/null 2>&1; then
      l_output+="\n - module: \"$module_name\" is not loaded"
    else
      l_output2+="\n - module: \"$module_name\" is loaded"
    fi
  }

  module_deny_chk() {
    l_dl="y"
    if modprobe --showconfig | grep -Pq -- '^\h*blacklist\h+'"$l_mpname"'\b'; then
      l_output+="\n - module: \"$module_name\" is deny listed in: \"$(grep -Pls -- '^\h*blacklist\h+$module_name\b' $l_searchloc)\""
    else
      l_output2+="\n - module: \"$module_name\" is not deny listed"
    fi
  }

  for l_mdir in $l_mpath; do
    if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
      l_output3+="\n - \"$l_mdir\""
      [ "$l_dl" != "y" ] && module_deny_chk
      if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/net" ]; then
        module_loadable_chk
        module_loaded_chk
      fi
    else
      l_output+="\n - module: \"$module_name\" doesn't exist in \"$l_mdir\""
    fi
  done

  {
    echo -e "\n\n -- INFO --\n - module: \"$module_name\" exists in:$l_output3"
    if [ -z "$l_output2" ]; then
      echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
      echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
  } >> "$MODULES_OUTPUT_FILE"
}

for module in dccp tipc rds sctp; do
  echo -e "\n============================================\nCIS Section 3.2 - $module Kernel Module\n============================================\n" >> "$MODULES_OUTPUT_FILE"
  run_module_check "$module"
done

echo "Network kernel modules audit complete. Output saved to $MODULES_OUTPUT_FILE"

# =============================
# SECTION 3.1: Configure Network Devices
# =============================

OUTPUT_FILE="$OUTPUT_DIR/configure_network_devices.txt"

{
  echo "# ============================="
  echo "# CIS Section 3.1 - Configure Network Devices"
  echo "# ============================="

  # 3.1.1 Ensure IPv6 status is identified
  echo -e "\n---"
  echo "CIS Section: 3.1.1 – Ensure IPv6 status is identified"
  echo -e "\nRationale: IPv6 should be enabled and configured unless prohibited by local policy."
  if grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable; then
    echo -e "\nCurrent State:\n - IPv6 is enabled"
    echo -e "\nBest Practice / Expected Value:\nIPv6 should be enabled and configured properly."
    echo -e "\nAudit Result: **PASS**"
  else
    echo -e "\nCurrent State:\n - IPv6 is not enabled"
    echo -e "\nBest Practice / Expected Value:\nEnable or disable IPv6 in accordance with system requirements."
    echo -e "\nAudit Result: **FAIL**"
  fi

  # 3.1.2 Ensure wireless interfaces are disabled
  echo -e "\n---"
  echo "CIS Section: 3.1.2 – Ensure wireless interfaces are disabled"
  echo -e "\nRationale: If wireless is not used, interfaces should be disabled to reduce attack surface."

  l_output=""; l_output2=""
  module_chk() {
    l_loadable="$(modprobe -n -v "$l_mname")"
    if grep -Pq -- '^\h*install /bin/(true|false)' <<< "$l_loadable"; then
      l_output+="\n - module: \"$l_mname\" is not loadable: \"$l_loadable\""
    else
      l_output2+="\n - module: \"$l_mname\" is loadable: \"$l_loadable\""
    fi
    if ! lsmod | grep "$l_mname" >/dev/null 2>&1; then
      l_output+="\n - module: \"$l_mname\" is not loaded"
    else
      l_output2+="\n - module: \"$l_mname\" is loaded"
    fi
    if modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mname\b"; then
      l_output+="\n - module: \"$l_mname\" is deny listed"
    else
      l_output2+="\n - module: \"$l_mname\" is not deny listed"
    fi
  }
  if [ -n "$(find /sys/class/net/*/ -type d -name wireless 2>/dev/null)" ]; then
    l_dname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless); do basename "$(readlink -f "$driverdir"/device/driver/module)"; done | sort -u)
    for l_mname in $l_dname; do module_chk; done
  fi
  if [ -z "$l_output2" ]; then
    echo -e "\nAudit Result: **PASS**"
    [ -z "$l_output" ] && echo -e "\n - System has no wireless NICs installed" || echo -e "\n$l_output"
  else
    echo -e "\nAudit Result: **FAIL**\nReasons:\n$l_output2"
    [ -n "$l_output" ] && echo -e "\nCorrectly configured:\n$l_output"
  fi

  # 3.1.3 Ensure bluetooth services are not in use
  echo -e "\n---"
  echo "CIS Section: 3.1.3 – Ensure bluetooth services are not in use"
  echo -e "\nRationale: Bluetooth introduces attack vectors like bluesnarfing, malware infections, etc."

  if dpkg-query -s bluez &>/dev/null; then
    echo -e "\nCurrent State:\nbluez is installed"
    echo -e "\nBest Practice / Expected Value:\nThe bluez package should be removed or service masked."
    echo -e "\nAudit Result: **FAIL**"
  else
    echo -e "\nCurrent State:\nbluez is NOT installed"
    echo -e "\nBest Practice / Expected Value:\nThe bluez package should be removed."
    echo -e "\nAudit Result: **PASS**"
  fi

  echo -e "\nAudit complete. Results written to: $OUTPUT_FILE"
} > "$OUTPUT_FILE"

# =============================
# SECTION 3.2: Network Kernel Modules
# =============================

MODULES_OUTPUT_FILE="$OUTPUT_DIR/configure_network_kernel_modules.txt"

run_module_check() {
  local module_name="$1"
  local l_output=""
  local l_output2=""
  local l_output3=""
  local l_dl=""
  local l_searchloc="/lib/modprobe.d/*.conf /usr/local/lib/modprobe.d/*.conf /run/modprobe.d/*.conf /etc/modprobe.d/*.conf"
  local l_mpath="/lib/modules/**/kernel/net"
  local l_mpname="$(tr '-' '_' <<< "$module_name")"
  local l_mndir="$(tr '-' '/' <<< "$module_name")"

  module_loadable_chk() {
    l_loadable="$(modprobe -n -v "$module_name")"
    [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P -- '(^\h*install|\b$module_name)\b' <<< "$l_loadable")"
    if grep -Pq -- '^\h*install /bin/(true|false)' <<< "$l_loadable"; then
      l_output+="\n - module: \"$module_name\" is not loadable: \"$l_loadable\""
    else
      l_output2+="\n - module: \"$module_name\" is loadable: \"$l_loadable\""
    fi
  }

  module_loaded_chk() {
    if ! lsmod | grep "$module_name" > /dev/null 2>&1; then
      l_output+="\n - module: \"$module_name\" is not loaded"
    else
      l_output2+="\n - module: \"$module_name\" is loaded"
    fi
  }

  module_deny_chk() {
    l_dl="y"
    if modprobe --showconfig | grep -Pq -- '^\h*blacklist\h+'"$l_mpname"'\b'; then
      l_output+="\n - module: \"$module_name\" is deny listed in: \"$(grep -Pls -- '^\h*blacklist\h+$module_name\b' $l_searchloc)\""
    else
      l_output2+="\n - module: \"$module_name\" is not deny listed"
    fi
  }

  for l_mdir in $l_mpath; do
    if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
      l_output3+="\n - \"$l_mdir\""
      [ "$l_dl" != "y" ] && module_deny_chk
      if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/net" ]; then
        module_loadable_chk
        module_loaded_chk
      fi
    else
      l_output+="\n - module: \"$module_name\" doesn't exist in \"$l_mdir\""
    fi
  done

  {
    echo -e "\n\n -- INFO --\n - module: \"$module_name\" exists in:$l_output3"
    if [ -z "$l_output2" ]; then
      echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
      echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
  } >> "$MODULES_OUTPUT_FILE"
}

for module in dccp tipc rds sctp; do
  echo -e "\n============================================\nCIS Section 3.2 - $module Kernel Module\n============================================\n" >> "$MODULES_OUTPUT_FILE"
  run_module_check "$module"
done

echo "Network kernel modules audit complete. Output saved to $MODULES_OUTPUT_FILE"

#!/usr/bin/env bash

# =============================
# SECTION 3.3: Disable Unused Network Protocols (3.3.1 - 3.3.11)
# =============================

OUTPUT_DIR="$HOME/Desktop/SEND_TO_MAOR2"
OUTPUT_FILE="$OUTPUT_DIR/disable_unused_protocols.txt"
mkdir -p "$OUTPUT_DIR"

{
  echo "# ============================="
  echo "# CIS Section 3.3 - Disable Unused Network Protocols"
  echo "# ============================="

  MODULES=(dccp sctp rds tipc bluetooth usb-storage firewire-core thunderbolt hci hdlc x25 ax25 netrom)
  IDS=(3.3.1 3.3.2 3.3.3 3.3.4 3.3.5 3.3.6 3.3.7 3.3.8 3.3.9 3.3.10 3.3.11)

  for i in "${!MODULES[@]}"; do
    module="${MODULES[$i]}"
    id="${IDS[$i]}"

    echo -e "\n---"
    echo "CIS Section: $id – Disable $module"
    echo "Audit Commands:"
    echo "  modprobe -n -v $module"
    echo "  lsmod | grep $module"
    echo "  grep -r '^blacklist $module' /etc/modprobe.d/"

    echo -e "\nRationale:"
    echo "Disabling unused or insecure protocols like $module reduces kernel attack surface and limits risk exposure."

    # Check if module is loadable
    LOADABLE_RESULT=$(modprobe -n -v "$module")
    if echo "$LOADABLE_RESULT" | grep -qE 'install /bin/(true|false)'; then
      LOADABLE_STATUS="not loadable ($LOADABLE_RESULT)"
    else
      LOADABLE_STATUS="loadable ($LOADABLE_RESULT)"
    fi

    # Check if module is currently loaded
    if lsmod | grep -q "^$module"; then
      LOADED_STATUS="currently loaded"
    else
      LOADED_STATUS="not currently loaded"
    fi

    # Check if module is blacklisted
    if grep -rqs "^blacklist $module" /etc/modprobe.d/; then
      BLACKLISTED_STATUS="blacklisted"
    else
      BLACKLISTED_STATUS="not blacklisted"
    fi

    echo -e "\nCurrent Value:"
    echo "  Module is $LOADABLE_STATUS"
    echo "  Module is $LOADED_STATUS"
    echo "  Module is $BLACKLISTED_STATUS"

    echo -e "\nBest Practice Value:"
    echo "  The $module module should not be loadable, not currently loaded, and should be blacklisted."

    if [[ "$LOADABLE_STATUS" == *"not loadable"* && "$LOADED_STATUS" == "not currently loaded" && "$BLACKLISTED_STATUS" == "blacklisted" ]]; then
      echo -e "\nAudit Result: **PASS**"
      echo -e "\nRecommendation:"
      echo "  No action needed."
    else
      echo -e "\nAudit Result: **FAIL**"
      echo -e "\nRecommendation:"
      echo "  To disable $module, run the following commands:"
      echo "    echo 'install $module /bin/true' >> /etc/modprobe.d/$module.conf"
      echo "    echo 'blacklist $module' >> /etc/modprobe.d/$module.conf"
      echo "    modprobe -r $module (if currently loaded)"
    fi
  done

  echo -e "\nAudit complete. Output saved to $OUTPUT_FILE"

} > "$OUTPUT_FILE"

# =============================
# CIS Section 4.1 – UFW Firewall Configuration Audit
# =============================

OUTPUT_DIR="$HOME/Desktop/SEND_TO_MAOR2"
OUTPUT_FILE="$OUTPUT_DIR/Configure_Host_Based_Firewall.txt"
mkdir -p "$OUTPUT_DIR"

{
  echo "# ============================="
  echo "# CIS Section 4.1 – Configure UncomplicatedFirewall (UFW)"
  echo "# ============================="

  # 4.1.1 Ensure ufw is installed
  echo -e "\n---"
  echo "CIS Section: 4.1.1 – Ensure ufw is installed"
  echo "Audit Command: dpkg-query -s ufw &>/dev/null && echo 'ufw is installed'"
  if dpkg-query -s ufw &>/dev/null; then
    echo "Current Value: ufw is installed"
    echo "Best Practice Value: ufw should be installed"
    echo "Audit Result: **PASS**"
    echo "Recommendation: No action needed."
  else
    echo "Current Value: ufw is NOT installed"
    echo "Best Practice Value: ufw should be installed"
    echo "Audit Result: **FAIL**"
    echo "Recommendation: Run 'apt install ufw' to install."
  fi

  # 4.1.2 Ensure iptables-persistent is not installed with ufw
  echo -e "\n---"
  echo "CIS Section: 4.1.2 – Ensure iptables-persistent is not installed with ufw"
  echo "Audit Command: dpkg-query -s iptables-persistent &>/dev/null && echo 'iptables-persistent is installed'"
  if dpkg-query -s iptables-persistent &>/dev/null; then
    echo "Current Value: iptables-persistent is installed"
    echo "Best Practice Value: iptables-persistent should NOT be installed with ufw"
    echo "Audit Result: **FAIL**"
    echo "Recommendation: Run 'apt purge iptables-persistent' to remove."
  else
    echo "Current Value: iptables-persistent is NOT installed"
    echo "Best Practice Value: iptables-persistent should NOT be installed with ufw"
    echo "Audit Result: **PASS**"
    echo "Recommendation: No action needed."
  fi

  # 4.1.3 Ensure ufw service is enabled
  echo -e "\n---"
  echo "CIS Section: 4.1.3 – Ensure ufw service is enabled"
  echo "Audit Commands:"
  echo "  systemctl is-enabled ufw"
  echo "  systemctl is-active ufw"
  echo "  ufw status"
  UFW_ENABLED=$(systemctl is-enabled ufw 2>/dev/null)
  UFW_ACTIVE=$(systemctl is-active ufw 2>/dev/null)
  UFW_STATUS=$(ufw status 2>/dev/null | grep -i active)
  if [[ "$UFW_ENABLED" == "enabled" && "$UFW_ACTIVE" == "active" && "$UFW_STATUS" =~ "Status: active" ]]; then
    echo "Current Value: ufw is enabled and active"
    echo "Best Practice Value: ufw service should be enabled and active"
    echo "Audit Result: **PASS**"
    echo "Recommendation: No action needed."
  else
    echo "Current Value: ufw is not fully enabled or active"
    echo "Best Practice Value: ufw service should be enabled and active"
    echo "Audit Result: **FAIL**"
    echo "Recommendation: Run the following commands:"
    echo "  systemctl unmask ufw.service"
    echo "  systemctl --now enable ufw.service"
    echo "  ufw enable"
  fi

  # 4.1.4 Ensure ufw loopback traffic is configured
  echo -e "\n---"
  echo "CIS Section: 4.1.4 – Ensure ufw loopback traffic is configured"
  echo "Audit Command: ufw status verbose"
  LOOPBACK_CHECK=$(ufw status verbose 2>/dev/null | grep -E 'ALLOW IN.*on lo|DENY IN.*127.0.0.0/8|ALLOW OUT.*on lo|DENY IN.*::1')
  if [[ -n "$LOOPBACK_CHECK" ]]; then
    echo "Current Value: loopback traffic rules are present"
    echo "Best Practice Value: Loopback interface must accept traffic, and other interfaces must deny 127.0.0.0/8 and ::1"
    echo "Audit Result: **PASS**"
    echo "Recommendation: No action needed."
  else
    echo "Current Value: loopback traffic rules are missing"
    echo "Best Practice Value: Loopback interface must accept traffic, and other interfaces must deny 127.0.0.0/8 and ::1"
    echo "Audit Result: **FAIL**"
    echo "Recommendation: Run the following commands:"
    echo "  ufw allow in on lo"
    echo "  ufw allow out on lo"
    echo "  ufw deny in from 127.0.0.0/8"
    echo "  ufw deny in from ::1"
  fi

  # 4.1.5 Ensure ufw outbound connections are configured (Manual)
  echo -e "\n---"
  echo "CIS Section: 4.1.5 – Ensure ufw outbound connections are configured (Manual)"
  echo "Audit Command: ufw status numbered"
  echo "Current Value:"
  ufw status numbered
  echo "Best Practice Value: Outbound rules should be configured per site policy"
  echo "Audit Result: **MANUAL**"
  echo "Recommendation: Review the output and configure outbound rules per policy using 'ufw allow out'"

  # 4.1.6 Ensure ufw firewall rules exist for all open ports
  echo -e "\n---"
  echo "CIS Section: 4.1.6 – Ensure ufw firewall rules exist for all open ports"
  echo "Audit Commands: ufw status verbose + ss -tuln"
  unset a_ufwout; unset a_openports
  while read -r l_ufwport; do
    [ -n "$l_ufwport" ] && a_ufwout+=("$l_ufwport")
  done < <(ufw status numbered | awk '/\[/{print $2}' | grep -oP '\d+')
  while read -r l_openport; do
    [ -n "$l_openport" ] && a_openports+=("$l_openport")
  done < <(ss -tuln | awk '($5!~/%lo:/ && $5!~/127.0.0.1:/ && $5!~/\[?::1\]?:/) {split($5, a, ":"); print a[2]}' | sort -u)
  a_diff=("$(printf '%s\n' "${a_openports[@]}" "${a_ufwout[@]}" "${a_ufwout[@]}" | sort | uniq -u)")
  if [[ -n "${a_diff[*]}" ]]; then
    echo -e "Audit Result: **FAIL**"
    echo "The following port(s) do not have UFW rules:"
    printf '%s\n' "${a_diff[@]}"
    echo "Recommendation: Add rules using 'ufw allow in <port>/<tcp|udp>' or 'ufw deny in ...'"
  else
    echo "Audit Result: **PASS**"
    echo "All open ports have rules in UFW."
  fi

  # 4.1.7 Ensure ufw default deny firewall policy
  echo -e "\n---"
  echo "CIS Section: 4.1.7 – Ensure ufw default deny firewall policy"
  echo "Audit Command: ufw status verbose | grep Default:"
  DEFAULT_POLICY=$(ufw status verbose 2>/dev/null | grep -i "Default:")
  echo "Current Value: $DEFAULT_POLICY"
  if echo "$DEFAULT_POLICY" | grep -qE 'deny.*incoming.*deny.*outgoing.*(disabled|deny.*routed)'; then
    echo "Best Practice Value: Default policy should be deny incoming, deny outgoing, deny routed"
    echo "Audit Result: **PASS**"
    echo "Recommendation: No action needed."
  else
    echo "Best Practice Value: Default policy should be deny incoming, deny outgoing, deny routed"
    echo "Audit Result: **FAIL**"
    echo "Recommendation: Run:"
    echo "  ufw default deny incoming"
    echo "  ufw default deny outgoing"
    echo "  ufw default deny routed"
  fi

  echo -e "\nAudit complete. Output saved to $OUTPUT_FILE"

} > "$OUTPUT_FILE"

chmod 600 "$OUTPUT_FILE"
echo "Firewall audit saved to: $OUTPUT_FILE"

OUTPUT_DIR="$HOME/Desktop/SEND_TO_MAOR2"
OUTPUT_FILE="$OUTPUT_DIR/Configure_IPTables_Firewall.txt"

if [ "$EUID" -ne 0 ]; then
  echo "ERROR: You need to be root to run this script"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
echo -e "# CIS Section 4.3 - Configure iptables - Audit" > "$OUTPUT_FILE"

run_check() {
  local description="$1"
  local command="$2"
  echo -e "\n---\n$description\nCommand:\n$command" >> "$OUTPUT_FILE"
  echo -e "\nOutput:" >> "$OUTPUT_FILE"
  bash -c "$command" >> "$OUTPUT_FILE" 2>&1
}

run_check "4.3.1.1 Ensure iptables packages are installed" \
  "dpkg-query -s iptables &>/dev/null && echo 'iptables is installed' || echo 'iptables is NOT installed'"

run_check "Check if iptables-persistent is installed" \
  "dpkg-query -s iptables-persistent &>/dev/null && echo 'iptables-persistent is installed' || echo 'iptables-persistent is NOT installed'"

run_check "4.3.1.2 Ensure nftables is not installed with iptables" \
  "dpkg-query -s nftables &>/dev/null && echo 'nftables is installed' || echo 'nftables is NOT installed'"

run_check "4.3.1.3 Ensure ufw is uninstalled or disabled with iptables" \
  "dpkg-query -s ufw &>/dev/null && echo 'ufw is installed' || echo 'ufw is NOT installed'"

run_check "ufw status" \
  "ufw status || echo 'Could not get ufw status'"

run_check "ufw service status" \
  "systemctl is-enabled ufw.service || echo 'ufw.service not found'"

run_check "4.3.2.1 Ensure iptables default deny firewall policy" \
  "iptables -L"

run_check "4.3.2.2 Ensure iptables loopback traffic is configured - INPUT" \
  "iptables -L INPUT -v -n"

run_check "Ensure iptables loopback traffic is configured - OUTPUT" \
  "iptables -L OUTPUT -v -n"

run_check "4.3.2.3 Ensure iptables outbound and established connections are configured" \
  "iptables -L -v -n"

run_check "4.3.2.4 Ensure iptables firewall rules exist for all open ports (ss)" \
  "ss -4tuln"

run_check "Check existing iptables INPUT rules" \
  "iptables -L INPUT -v -n"

echo -e "\nAudit complete. Results saved to: $OUTPUT_FILE"

# =============================
# CIS Section 4.2 - Configure nftables - Audit
# =============================

OUTPUT_DIR="$HOME/Desktop/SEND_TO_MAOR2"
OUTPUT_FILE="$OUTPUT_DIR/Configure_nftables.txt"

mkdir -p "$OUTPUT_DIR"
echo "# CIS Section 4.2 - Configure nftables - Audit" > "$OUTPUT_FILE"

run_command() {
    local description="$1"
    local cmd="$2"
    echo -e "\n---\n$description" >> "$OUTPUT_FILE"
    echo "Command:" >> "$OUTPUT_FILE"
    echo "$cmd" >> "$OUTPUT_FILE"
    echo "Output:" >> "$OUTPUT_FILE"
    eval "$cmd" >> "$OUTPUT_FILE" 2>&1
}

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: You need to be root to run this script" >&2
    echo "Run with sudo or as root." >> "$OUTPUT_FILE"
    exit 1
fi

run_command "4.2.1 Ensure nftables is installed" \
    "dpkg-query -s nftables &>/dev/null && echo 'nftables is installed' || echo 'nftables is NOT installed'"

run_command "4.2.2 Ensure ufw is uninstalled or disabled with nftables" \
    "dpkg-query -s ufw &>/dev/null && echo 'ufw is installed' || echo 'ufw is NOT installed'"

run_command "ufw status" "ufw status"
run_command "ufw service status" "systemctl is-enabled ufw.service"

run_command "4.2.3 Ensure iptables are flushed with nftables" "iptables -L"
run_command "ip6tables" "ip6tables -L"

run_command "4.2.4 Ensure a nftables table exists" "nft list tables"

run_command "4.2.5 Ensure nftables base chains exist (INPUT)" "nft list ruleset | grep 'hook input'"
run_command "Ensure nftables base chains exist (FORWARD)" "nft list ruleset | grep 'hook forward'"
run_command "Ensure nftables base chains exist (OUTPUT)" "nft list ruleset | grep 'hook output'"

run_command "4.2.6 Ensure nftables loopback traffic is configured - IPv4" "nft list ruleset | awk '/hook input/,/}/' | grep 'iif \"lo\" accept'"
run_command "Check IPv4 drop" "nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'"
run_command "Check IPv6 drop" "nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'"

run_command "4.2.7 Ensure nftables outbound and established connections are configured - INPUT" \
    "nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'"
run_command "Ensure nftables outbound and established connections are configured - OUTPUT" \
    "nft list ruleset | awk '/hook output/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'"

run_command "4.2.8 Ensure nftables default deny firewall policy - input" \
    "nft list ruleset | grep 'hook input'"
run_command "default policy - forward" "nft list ruleset | grep 'hook forward'"
run_command "default policy - output" "nft list ruleset | grep 'hook output'"

run_command "4.2.9 Ensure nftables service is enabled" \
    "systemctl is-enabled nftables"

NFT_FILE=$(awk '$1 ~ /^\s*include/ { gsub("\"","",$2); print $2 }' /etc/nftables.conf 2>/dev/null)
if [ -n "$NFT_FILE" ]; then
    run_command "4.2.10 Ensure nftables rules are permanent - input" \
        "awk '/hook input/,/}/' \"$NFT_FILE\""
    run_command "4.2.10 Ensure nftables rules are permanent - forward" \
        "awk '/hook forward/,/}/' \"$NFT_FILE\""
    run_command "4.2.10 Ensure nftables rules are permanent - output" \
        "awk '/hook output/,/}/' \"$NFT_FILE\""
else
    echo "---" >> "$OUTPUT_FILE"
    echo "4.2.10 Ensure nftables rules are permanent" >> "$OUTPUT_FILE"
    echo "Command:" >> "$OUTPUT_FILE"
    echo "Could not determine nftables rules file from /etc/nftables.conf" >> "$OUTPUT_FILE"
fi

echo -e "\nFirewall audit saved to: $OUTPUT_FILE"


