#!/bin/bash # Use bash interpreter for script execution.

# AutoTableV2_single – Simplified firewall tool for single-network lab environment.
# This version assumes attacker and victim are on the same network segment (192.168.100.0/24).

set -euo pipefail # Exit on first error, undefined variable, or failed pipeline.
IFS=$'\n\t' # Limit word splitting to newline and tab for safer parsing.

# ------------------------- GLOBAL CONSTANTS -------------------------
readonly NET_IF="eth0" # Network interface (adjust to enp0s3 if needed).
readonly VICTIM_IP="192.168.100.20/24" # IP/mask assigned to victim machine.
readonly ATTACKER_IP="192.168.100.10" # Attacker machine IP address.
readonly NETWORK="192.168.100.0/24" # Network segment for both machines.
readonly DEFAULT_GW="192.168.100.1" # Default gateway (optional, for Internet access).
readonly LOG_FILE="/var/log/autotablev2_single.log" # Local audit log file.
readonly REQUIRED_PACKAGES=(iptables iptables-persistent rsyslog iproute2 net-tools) # Dependency list to install.
readonly IPTABLES_BIN=$(command -v iptables) # Resolve absolute iptables binary path.

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

section() { # Print section headers with timestamps and log them.
  printf "\n%s[%s]%s %s\n" "$BLUE" "$(date -u +'%H:%M:%S')" "$RESET" "$1" # Emit colored, timestamped header.
  logger -t autotablev2_single "$1" # Send section label to syslog for auditing.
}

info()  { printf "%s[INFO]%s %s\n"  "$GREEN" "$RESET" "$1"; logger -t autotablev2_single "INFO: $1"; } # Informational message helper.
warn()  { printf "%s[WARN]%s %s\n"  "$YELLOW" "$RESET" "$1"; logger -t autotablev2_single "WARN: $1"; } # Warning message helper.
error() { printf "%s[ERR ]%s %s\n" "$RED" "$RESET" "$1"; logger -t autotablev2_single "ERR : $1"; } # Error message helper.

run_cmd() { # Wrapper adding logging and exit-on-failure semantics.
  local desc=$1 # Capture human-readable description.
  shift # Remove description from argument list.
  info "$desc" # Report upcoming action.
  if ! "$@"; then # Execute command and test success.
    error "Failure while running: $*" # Log detailed failure context.
    exit 1 # Abort script on failure.
  fi # End command success check.
}

ensure_log_file() { # Create log file and tee stdout/stderr into it.
  sudo touch "$LOG_FILE" # Ensure log file exists with elevated privileges.
  sudo chmod 640 "$LOG_FILE" # Restrict log file permissions to root and group.
  exec > >(tee -a "$LOG_FILE") 2>&1 # Mirror all subsequent output into log file.
}

describe_network() { # Output and log the current lab network architecture.
  section "Network architecture overview" # Print section heading for clarity.
  cat <<EOF # Emit descriptive block summarizing topology.
Single Network Topology:
  - Network: $NETWORK (simplified single-segment lab)
  - Attacker (Kali): $ATTACKER_IP
  - Victim (LinuxServer): ${VICTIM_IP%/*}
  - Both machines on same network segment for simplified testing
  - No routing/forwarding required - direct network communication

Honeypot Security Model:
  - Firewall configured with transparent shield/honeypot effect: attacks are logged first, then blocked.
  - Suspicious traffic (attacker IP, vulnerable ports, spoofing, rate limit violations) sent to HONEYPOT chains.
  - HONEYPOT chains log detailed attack information (IP options, TCP sequences, UID) before dropping packets.
  - This allows verification of attack patterns while maintaining security through blocking.
EOF
}

# ------------------------- PRE-FLIGHT CHECKS ------------------------
require_root() { # Enforce root execution to manage networking and firewall.
  if [ "$EUID" -ne 0 ]; then # Compare effective user ID against zero (root).
    error "This script must be run as root." # Display error message.
    exit 1 # Exit immediately without running configuration.
  fi # End privilege check.
}

install_dependencies() { # Install or verify required packages.
  section "Installing/Verifying packages" # Announce dependency phase.
  export DEBIAN_FRONTEND=noninteractive # Suppress interactive apt prompts.
  run_cmd "Updating apt cache" apt-get update -qq # Refresh package metadata quietly.
  run_cmd "Installing required packages: ${REQUIRED_PACKAGES[*]}" apt-get install -y "${REQUIRED_PACKAGES[@]}" # Install dependencies non-interactively.
}

# ------------------------- NETWORK CONFIG --------------------------
configure_interfaces() { # Configure NIC address and enable link.
  section "Configuring network interface" # Announce interface configuration stage.
  run_cmd "Bringing $NET_IF up with $VICTIM_IP" ip addr replace "$VICTIM_IP" dev "$NET_IF" # Assign interface address.
  run_cmd "Enabling interface $NET_IF" ip link set "$NET_IF" up # Bring interface up.
}

configure_routes() { # Configure routing table entries (optional, for Internet access).
  section "Configuring routes" # Announce routing configuration stage.
  if [ -n "$DEFAULT_GW" ] && ping -c 1 -W 1 "$DEFAULT_GW" >/dev/null 2>&1; then # Check if gateway is reachable.
    run_cmd "Setting default route via $DEFAULT_GW" ip route replace default via "$DEFAULT_GW" dev "$NET_IF" # Install/replace default route.
  else
    warn "Default gateway not configured or unreachable. Skipping route configuration." # Warn about missing gateway.
  fi # End gateway check.
}

# ------------------------- RSYSLOG CONFIG --------------------------
configure_rsyslog() { # Configure rsyslog for local logging (no remote forwarding in single network).
  section "Configuring rsyslog" # Announce rsyslog configuration stage.
  run_cmd "Restarting rsyslog" systemctl restart rsyslog # Restart rsyslog service.
  run_cmd "Enabling rsyslog service" systemctl enable rsyslog # Ensure rsyslog starts on boot.
}

# ------------------------- IPTABLES HELPERS ------------------------
flush_tables() { # Reset firewall state to a clean slate.
  section "Resetting iptables" # Announce flushing stage.
  for table in filter nat mangle raw; do # Iterate through relevant netfilter tables.
    run_cmd "Flushing table $table" "$IPTABLES_BIN" -w -t "$table" -F # Flush built-in chains in table.
    run_cmd "Deleting custom chains in $table" "$IPTABLES_BIN" -w -t "$table" -X # Delete user-defined chains in table.
  done # End table loop.
  run_cmd "Setting default policy INPUT DROP" "$IPTABLES_BIN" -w -P INPUT DROP # Default-drop inbound traffic.
  run_cmd "Setting default policy FORWARD DROP" "$IPTABLES_BIN" -w -P FORWARD DROP # Default-drop forwarded traffic.
  run_cmd "Setting default policy OUTPUT ACCEPT" "$IPTABLES_BIN" -w -P OUTPUT ACCEPT # Allow local outbound conversations.
}

honeypot_chains() { # Create honeypot chains for attack detection and logging.
  section "Creating honeypot detection chains" # Announce honeypot setup stage.
  "$IPTABLES_BIN" -w -N HONEYPOT_INPUT # Create dedicated chain for INPUT honeypot logging.
  "$IPTABLES_BIN" -w -A HONEYPOT_INPUT -j LOG --log-prefix "HONEYPOT_ATTACK_INPUT: " --log-level 4 --log-ip-options --log-tcp-sequence --log-tcp-options --log-uid # Log attack details with full packet info.
  "$IPTABLES_BIN" -w -A HONEYPOT_INPUT -j DROP # Drop after logging to complete honeypot effect.
}

base_rules() { # Apply baseline hygiene and anti-spoofing rules (with honeypot logging).
  section "Base traffic hygiene" # Announce baseline rule stage.
  "$IPTABLES_BIN" -w -A INPUT -i lo -j ACCEPT # Permit loopback traffic inbound.
  "$IPTABLES_BIN" -w -A OUTPUT -o lo -j ACCEPT # Permit loopback traffic outbound.
  "$IPTABLES_BIN" -w -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT # Allow established inbound responses.
  "$IPTABLES_BIN" -w -A INPUT -m conntrack --ctstate INVALID -j HONEYPOT_INPUT # Send invalid packets to honeypot for logging before drop.
  # Anti-spoofing: Block private addresses that shouldn't be on this network.
  for net in 10.0.0.0/8 172.16.0.0/12; do # Loop through RFC1918 ranges (excluding 192.168.0.0/16).
    "$IPTABLES_BIN" -w -A INPUT -i "$NET_IF" -s "$net" -j HONEYPOT_INPUT # Log private source addresses (spoofing attempt).
  done # End anti-spoof loop.
  # Block 192.168.x.x addresses except our network (192.168.100.0/24).
  "$IPTABLES_BIN" -w -A INPUT -i "$NET_IF" -s 192.168.0.0/16 ! -s "$NETWORK" -j HONEYPOT_INPUT # Log spoofed 192.168.x.x addresses.
}

service_rules() { # Define application-layer access policies with honeypot logging.
  section "Service accessibility rules" # Announce service control stage.
  "$IPTABLES_BIN" -w -A INPUT -p icmp --icmp-type echo-request -s "$NETWORK" -j ACCEPT # Allow ICMP ping from network.
  "$IPTABLES_BIN" -w -A INPUT -p icmp --icmp-type timestamp-request -j HONEYPOT_INPUT # Log ICMP timestamp requests (reconnaissance attempt).
  "$IPTABLES_BIN" -w -A INPUT -p icmp --icmp-type timestamp-reply -j HONEYPOT_INPUT # Log outbound timestamp replies (reconnaissance attempt).
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 80 -j ACCEPT # Allow HTTP service for web testing.
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 443 -j ACCEPT # Allow HTTPS service for secure web testing.
  for port in 21 23; do # Iterate over insecure legacy services.
    "$IPTABLES_BIN" -w -A INPUT -p tcp --dport "$port" -j HONEYPOT_INPUT # Log FTP/Telnet attempts (vulnerable service access attempt).
  done # Finish insecure service loop.
  "$IPTABLES_BIN" -w -A INPUT -p udp --dport 161 -j HONEYPOT_INPUT # Log SNMP access attempts (information disclosure risk).
  # Note: SSH and attacker IP handling moved to advanced_security for rate limiting.
}

advanced_security() { # Apply rate-limiting and SYN flood controls with honeypot logging.
  section "Advanced protections" # Announce advanced security stage.
  # Unified hard-ban using iptables 'recent' for FTP(21), SSH(22), Telnet(23)
  local PROTECTED_PORTS="21,22,23"

  # 1) Already banned → drop and refresh timer
  "$IPTABLES_BIN" -w -A INPUT -p tcp -m multiport --dports "$PROTECTED_PORTS" \
    -m recent --name ABUSE_BANNED --update --seconds 60 -j DROP

  # 2) Track all NEW attempts to protected ports
  "$IPTABLES_BIN" -w -A INPUT -p tcp -m multiport --dports "$PROTECTED_PORTS" \
    -m conntrack --ctstate NEW -m recent --name ABUSE_COUNT --set

  # 3) Log per-service when threshold exceeded (4 hits in 60s)
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 21 \
    -m conntrack --ctstate NEW \
    -m recent --name ABUSE_COUNT --rcheck --seconds 60 --hitcount 4 \
    -j LOG --log-prefix "FTP_HARD_BAN: " --log-level 4

  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 \
    -m conntrack --ctstate NEW \
    -m recent --name ABUSE_COUNT --rcheck --seconds 60 --hitcount 4 \
    -j LOG --log-prefix "SSH_HARD_BAN: " --log-level 4

  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 23 \
    -m conntrack --ctstate NEW \
    -m recent --name ABUSE_COUNT --rcheck --seconds 60 --hitcount 4 \
    -j LOG --log-prefix "TELNET_HARD_BAN: " --log-level 4

  # 4) On threshold → add to ban list and drop
  "$IPTABLES_BIN" -w -A INPUT -p tcp -m multiport --dports "$PROTECTED_PORTS" \
    -m conntrack --ctstate NEW \
    -m recent --name ABUSE_COUNT --rcheck --seconds 60 --hitcount 4 \
    -m recent --name ABUSE_BANNED --set -j DROP

  # 5) Allow SSH from the known attacker IP after ban checks (observability allowed, abuse gets banned)
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 -s "$ATTACKER_IP" -j ACCEPT
  # Allow other network hosts SSH after ban checks
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 -s "$NETWORK" ! -s "$ATTACKER_IP" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

  # 6) FTP/Telnet attempts (21,23) → honeypot (no open access), after ban checks
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 21 -j HONEYPOT_INPUT
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 23 -j HONEYPOT_INPUT

  # 7) Block attacker IP for all other services (non-SSH) - honeypot effect (preserve behavior)
  "$IPTABLES_BIN" -w -A INPUT -s "$ATTACKER_IP" ! -p tcp --dport 22 -j HONEYPOT_INPUT

  # 8) SYN flood protection (unchanged)
  "$IPTABLES_BIN" -w -N SYN_FLOOD_CHECK # Create dedicated chain for SYN flood detection.
  "$IPTABLES_BIN" -w -A INPUT -p tcp --syn -j SYN_FLOOD_CHECK # Send all SYN packets through protection chain.
  "$IPTABLES_BIN" -w -A SYN_FLOOD_CHECK -m limit --limit 1/s --limit-burst 4 -j RETURN # Allow limited burst of SYNs (legitimate traffic).
  "$IPTABLES_BIN" -w -A SYN_FLOOD_CHECK -j HONEYPOT_INPUT # Send excess SYN traffic to honeypot for logging (DoS attack detection).
}

drop_logging() { # Add catch-all logging for unmatched packets (honeypot chains handle most attacks).
  section "Catch-all drop logging" # Announce catch-all logging configuration stage.
  "$IPTABLES_BIN" -w -A INPUT -j LOG --log-prefix "IPTABLES_INPUT_DROP: " --log-level 6 # Log unmatched INPUT packets (should be rare with honeypot chains).
}

persist_rules() { # Save firewall state for persistence across reboots.
  section "Persisting firewall state" # Announce persistence stage.
  run_cmd "Saving active rules to /etc/iptables/rules.v4" /sbin/iptables-save >/etc/iptables/rules.v4 # Dump ruleset to persistence file.
  run_cmd "Enabling netfilter-persistent" systemctl enable netfilter-persistent # Enable netfilter persistence service.
  run_cmd "Saving via netfilter-persistent" netfilter-persistent save # Trigger persistence save action.
}

# ------------------------- MAIN ------------------------------------
main() { # Primary orchestration function.
  require_root # Verify script is executed as root.
  ensure_log_file # Start logging early for full audit trail.
  describe_network # Document network architecture in logs/output.
  install_dependencies # Ensure required packages are installed.
  configure_interfaces # Configure interface IP settings.
  configure_routes # Program routing table entries (optional).
  configure_rsyslog # Configure rsyslog for local logging.
  flush_tables # Reset firewall state to a clean baseline.
  honeypot_chains # Create honeypot chains for attack detection and logging (must be before rules that use them).
  base_rules # Apply baseline hygiene policies (uses honeypot chains for suspicious traffic).
  advanced_security # Enable advanced protections FIRST (rate limiting, attacker IP handling) - must be before service_rules.
  service_rules # Configure service-specific rules (uses honeypot chains for attack logging).
  drop_logging # Enable catch-all drop logging for any unmatched traffic.
  persist_rules # Persist firewall configuration across reboots.
  section "Completed. Firewall & logging hardened with honeypot attack detection (single network)." # Print completion message.
}

main "$@" # Execute main function with provided CLI arguments.

