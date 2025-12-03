#!/bin/bash 
# Use bash interpreter for script execution.

# attacker_test_single.sh – Pre-flight check for Kali attacker machine (single network version).
# This script verifies installation, network configuration for simplified single-network lab.

set -euo pipefail # Exit on first error, undefined variable, or failed pipeline.
IFS=$'\n\t' # Limit word splitting to newline and tab for safer parsing.

# ------------------------- GLOBAL CONSTANTS -------------------------
readonly ATTACKER_IF="eth0" # Primary network interface for attacker machine (adjust to enp0s3 if needed).
readonly ATTACKER_IP="192.168.100.10" # Expected IP address of attacker machine.
readonly ATTACKER_NET="192.168.100.0/24" # Network segment (same as victim).
readonly TARGET_IP="192.168.100.20" # Target LinuxServer IP address (same network).
readonly DEFAULT_GW="192.168.100.1" # Default gateway (optional, for Internet access).
readonly REQUIRED_TOOLS=(nmap hping3 hydra snmpwalk nikto tcpdump) # Required penetration testing tools.
readonly LOG_FILE="/tmp/attacker_test_single.log" # Local test log file.

# ------------------------- COLOR & LOG HELPERS ----------------------
if command -v tput >/dev/null 2>&1 && [ -n "${TERM:-}" ]; then # Detect terminal color support.
  readonly GREEN="$(tput setaf 2)" # ANSI code for green text.
  readonly YELLOW="$(tput setaf 3)" # ANSI code for yellow text.
  readonly RED="$(tput setaf 1)" # ANSI code for red text.
  readonly BLUE="$(tput setaf 6)" # ANSI code for cyan/blue text.
  readonly RESET="$(tput sgr0)" # ANSI reset sequence.
else
  readonly GREEN="" # Fallback blank string when no color support.
  readonly YELLOW="" # Fallback blank string when no color support.
  readonly RED="" # Fallback blank string when no color support.
  readonly BLUE="" # Fallback blank string when no color support.
  readonly RESET="" # Fallback blank string when no color support.
fi

section() { # Print section headers with timestamps.
  printf "\n%s[%s]%s %s\n" "$BLUE" "$(date +'%H:%M:%S')" "$RESET" "$1" # Emit colored, timestamped header.
}

info()  { printf "%s[INFO]%s %s\n"  "$GREEN" "$RESET" "$1"; } # Informational message helper.
warn()  { printf "%s[WARN]%s %s\n"  "$YELLOW" "$RESET" "$1"; } # Warning message helper.
error() { printf "%s[ERR ]%s %s\n" "$RED" "$RESET" "$1"; } # Error message helper.

check_root() { # Verify script is executed with appropriate privileges.
  if [ "$EUID" -ne 0 ]; then # Compare effective user ID against zero (root).
    warn "Some checks may require root privileges. Continuing with limited checks..." # Warn about limited functionality.
  else
    info "Running with root privileges." # Confirm root execution.
  fi # End privilege check.
}

check_os() { # Verify operating system is Kali Linux or compatible.
  section "Operating System Check" # Announce OS check stage.
  if [ -f /etc/os-release ]; then # Check if os-release file exists.
    . /etc/os-release # Source the os-release file for OS information.
    if [[ "$ID" == "kali" ]] || [[ "$ID_LIKE" == *"debian"* ]]; then # Check if OS is Kali or Debian-based.
      info "OS detected: $PRETTY_NAME" # Display detected OS name.
    else
      warn "OS may not be Kali Linux. Detected: $PRETTY_NAME" # Warn about non-Kali OS.
    fi # End OS type check.
  else
    warn "Cannot determine OS version. /etc/os-release not found." # Warn about missing OS info.
  fi # End os-release check.
}

check_tools() { # Verify required penetration testing tools are installed.
  section "Tool Installation Check" # Announce tool check stage.
  local missing_tools=() # Initialize array for missing tools.
  for tool in "${REQUIRED_TOOLS[@]}"; do # Iterate through required tools.
    if command -v "$tool" >/dev/null 2>&1; then # Check if tool is available in PATH.
      info "$tool is installed: $(command -v $tool)" # Confirm tool installation with path.
    else
      error "$tool is NOT installed." # Report missing tool.
      missing_tools+=("$tool") # Add to missing tools array.
    fi # End tool availability check.
  done # End tool iteration.
  if [ ${#missing_tools[@]} -gt 0 ]; then # Check if any tools are missing.
    warn "Missing tools: ${missing_tools[*]}" # List missing tools.
    info "Install missing tools with: apt-get update && apt-get install -y ${missing_tools[*]}" # Suggest installation command.
    return 1 # Return error status.
  else
    info "All required tools are installed." # Confirm all tools present.
    return 0 # Return success status.
  fi # End missing tools check.
}

check_network_interface() { # Verify network interface configuration.
  section "Network Interface Check" # Announce interface check stage.
  if ip link show "$ATTACKER_IF" >/dev/null 2>&1; then # Check if interface exists.
    info "Interface $ATTACKER_IF exists." # Confirm interface presence.
    local if_status=$(ip link show "$ATTACKER_IF" | grep -oP 'state \K\w+') # Extract interface state.
    if [[ "$if_status" == "UP" ]]; then # Check if interface is up.
      info "Interface $ATTACKER_IF is UP." # Confirm interface is active.
    else
      warn "Interface $ATTACKER_IF is DOWN. Attempting to bring it up..." # Warn about down interface.
      ip link set "$ATTACKER_IF" up # Bring interface up.
      sleep 2 # Wait for interface to initialize.
    fi # End interface state check.
  else
    error "Interface $ATTACKER_IF not found." # Report missing interface.
    info "Available interfaces:" # List available interfaces.
    ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | sed 's/://' # Display interface list.
    return 1 # Return error status.
  fi # End interface existence check.
}

check_ip_configuration() { # Verify IP address assignment.
  section "IP Configuration Check" # Announce IP check stage.
  local current_ip=$(ip addr show "$ATTACKER_IF" | grep -oP 'inet \K[\d.]+' | head -1) # Extract current IP address.
  if [ -n "$current_ip" ]; then # Check if IP is assigned.
    info "Current IP on $ATTACKER_IF: $current_ip" # Display current IP.
    if [[ "$current_ip" == "$ATTACKER_IP" ]]; then # Compare with expected IP.
      info "IP address matches expected: $ATTACKER_IP" # Confirm correct IP.
    else
      warn "IP address ($current_ip) does not match expected ($ATTACKER_IP)." # Warn about IP mismatch.
      info "To configure: ip addr add $ATTACKER_IP/24 dev $ATTACKER_IF" # Suggest IP configuration.
    fi # End IP comparison.
  else
    warn "No IP address assigned to $ATTACKER_IF." # Warn about missing IP.
    info "To configure: ip addr add $ATTACKER_IP/24 dev $ATTACKER_IF && ip link set $ATTACKER_IF up" # Suggest configuration.
  fi # End IP presence check.
}

check_routing() { # Verify routing table configuration (simplified for single network).
  section "Routing Configuration Check" # Announce routing check stage.
  local default_gw=$(ip route | grep default | awk '{print $3}' | head -1) # Extract default gateway.
  if [ -n "$default_gw" ]; then # Check if default gateway exists.
    info "Default gateway: $default_gw" # Display default gateway.
    if [[ "$default_gw" == "$DEFAULT_GW" ]]; then # Compare with expected gateway.
      info "Default gateway matches expected: $DEFAULT_GW" # Confirm correct gateway.
    else
      warn "Default gateway ($default_gw) does not match expected ($DEFAULT_GW)." # Warn about gateway mismatch.
    fi # End gateway comparison.
  else
    warn "No default gateway configured (optional for single network lab)." # Warn about missing gateway.
    info "To configure (if Internet access needed): ip route add default via $DEFAULT_GW dev $ATTACKER_IF" # Suggest gateway configuration.
  fi # End gateway presence check.
  # Check local network route.
  if ip route | grep -q "$ATTACKER_NET"; then # Check if route to network exists.
    info "Route to network ($ATTACKER_NET) exists." # Confirm route presence.
  else
    info "Direct network access (no routing needed for single network)." # Note route behavior.
  fi # End route check.
}

check_connectivity() { # Test network connectivity to target.
  section "Connectivity Check" # Announce connectivity check stage.
  if ping -c 2 -W 2 "$TARGET_IP" >/dev/null 2>&1; then # Test ping to target.
    info "Target ($TARGET_IP) is reachable." # Confirm target connectivity.
  else
    warn "Cannot reach target ($TARGET_IP). Firewall may be blocking ICMP or target is down." # Warn about target connectivity.
  fi # End target ping test.
  # Check if default gateway is reachable (optional).
  if [ -n "$DEFAULT_GW" ] && ping -c 1 -W 1 "$DEFAULT_GW" >/dev/null 2>&1; then # Test ping to gateway.
    info "Default gateway ($DEFAULT_GW) is reachable." # Confirm gateway connectivity.
  else
    info "Default gateway check skipped (not required for single network lab)." # Note gateway check.
  fi # End gateway ping test.
}

check_dns() { # Verify DNS resolution (optional check).
  section "DNS Configuration Check" # Announce DNS check stage.
  if [ -f /etc/resolv.conf ]; then # Check if resolv.conf exists.
    local dns_servers=$(grep nameserver /etc/resolv.conf | awk '{print $2}') # Extract DNS servers.
    if [ -n "$dns_servers" ]; then # Check if DNS servers are configured.
      info "DNS servers configured: $dns_servers" # Display DNS servers.
    else
      warn "No DNS servers configured (optional for single network lab)." # Warn about missing DNS.
    fi # End DNS server check.
  else
    warn "DNS configuration file not found." # Warn about missing DNS config.
  fi # End resolv.conf check.
}

print_summary() { # Print test summary and recommendations.
  section "Test Summary" # Announce summary stage.
  info "Attacker machine pre-flight checks completed (single network version)." # Confirm completion.
  info "Network interface: $ATTACKER_IF" # Display interface name.
  info "Expected IP: $ATTACKER_IP" # Display expected IP.
  info "Target IP: $TARGET_IP" # Display target IP.
  info "Network: $ATTACKER_NET" # Display network segment.
  printf "\n%sNext steps:%s\n" "$BLUE" "$RESET" # Print next steps header.
  printf "  1. Verify all tools are installed\n" # List step 1.
  printf "  2. Ensure network interface is configured correctly\n" # List step 2.
  printf "  3. Test connectivity to target: ping $TARGET_IP\n" # List step 3.
  printf "  4. Begin reconnaissance: nmap -sS $TARGET_IP\n" # List step 4.
  printf "  5. Validate hard-ban behavior (SSH/FTP/Telnet):\n" # New guidance based on unified hard-ban model.
  printf "     - Make >4 NEW attempts within 60s to ports 21/22/23\n"
  printf "     - Expect kernel logs with prefixes: FTP_HARD_BAN:, SSH_HARD_BAN:, TELNET_HARD_BAN:\n"
  printf "     - Subsequent attempts should DROP for ~60s (ban window)\n"
}

# ------------------------- MAIN ------------------------------------
main() { # Primary orchestration function.
  section "Attacker Machine Pre-Flight Check (Single Network)" # Print main header.
  check_root # Verify execution privileges.
  check_os # Verify operating system.
  check_tools # Verify required tools installation.
  check_network_interface # Verify network interface configuration.
  check_ip_configuration # Verify IP address assignment.
  check_routing # Verify routing table configuration.
  check_connectivity # Test network connectivity.
  check_dns # Verify DNS configuration (optional).
  print_summary # Print test summary.
  section "Pre-flight checks completed." # Print completion message.
}

main "$@" # Execute main function with provided CLI arguments.

