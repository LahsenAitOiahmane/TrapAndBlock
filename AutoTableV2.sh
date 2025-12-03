#!/bin/bash # Use bash interpreter for script execution.

# AutoTableV2 – Hardening & firewall tool for the LinuxServer gateway. # Describe tool purpose.
# Features include dependency checks, interface configuration, firewall structuring, rsyslog tuning, and auditing. # Summarize capabilities.

set -euo pipefail # Exit on first error, undefined variable, or failed pipeline.
IFS=$'\n\t' # Limit word splitting to newline and tab for safer parsing.

# ------------------------- GLOBAL CONSTANTS -------------------------
readonly EXT_IF="enp0s3" # External-facing interface toward DMZ/router.
readonly LAN_IF="enp0s8" # Internal LAN1 interface toward PCs.
readonly EXT_IP="10.10.0.10/24" # IP/mask assigned to EXT_IF.
readonly LAN_IP="10.10.10.1/24" # IP/mask assigned to LAN_IF.
readonly DEFAULT_GW="10.10.0.1" # Default gateway via router R2.
readonly ROUTE_LAN2_NET="10.10.20.0/24" # Network for LAN2 behind BSD server.
readonly ROUTE_LAN2_GW="10.10.0.20" # Next hop toward LAN2 (BSD server IP).
readonly LOG_SERVER="10.10.0.30" # Remote log collector IP.
readonly LOG_FILE="/var/log/autotablev2.log" # Local audit log file.
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
  logger -t autotablev2 "$1" # Send section label to syslog for auditing.
}

info()  { printf "%s[INFO]%s %s\n"  "$GREEN" "$RESET" "$1"; logger -t autotablev2 "INFO: $1"; } # Informational message helper.
warn()  { printf "%s[WARN]%s %s\n"  "$YELLOW" "$RESET" "$1"; logger -t autotablev2 "WARN: $1"; } # Warning message helper.
error() { printf "%s[ERR ]%s %s\n" "$RED" "$RESET" "$1"; logger -t autotablev2 "ERR : $1"; } # Error message helper.

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
Topology Summary:
  - External network 192.168.100.0/24 hosts router R1 (192.168.100.1) and attacker Kali (192.168.100.10).
  - Router R2 at 10.10.0.1 interconnects the DMZ 10.10.0.0/24 with upstream cloud and downstream gateways.
  - LinuxServer (this host) uses $EXT_IF with $EXT_IP toward R2 and $LAN_IF with $LAN_IP toward LAN1.
  - LAN1 10.10.10.0/24 sits behind LinuxServer acting as gateway for PCs such as PC1 (10.10.10.11) and PC2 (10.10.10.12).
  - BSDServer at 10.10.0.20 extends connectivity to LAN2 10.10.20.0/24 with gateway 10.10.20.1.
  - LogServer at $LOG_SERVER collects rsyslog events over UDP/TCP 514 from all infrastructure nodes.
  - Known attacker source 192.168.100.10 executed reconnaissance, brute force, spoofing, and SYN flood attacks pre-firewall.

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
    error "Ce script doit être lancé en root." # Display localized error message.
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
configure_interfaces() { # Configure NIC addresses and enable links.
  section "Configuring interfaces" # Announce interface configuration stage.
  run_cmd "Bringing $EXT_IF up with $EXT_IP" ip addr replace "$EXT_IP" dev "$EXT_IF" # Assign EXT interface address.
  run_cmd "Bringing $LAN_IF up with $LAN_IP" ip addr replace "$LAN_IP" dev "$LAN_IF" # Assign LAN interface address.
  run_cmd "Enabling interface $EXT_IF" ip link set "$EXT_IF" up # Bring external interface up.
  run_cmd "Enabling interface $LAN_IF" ip link set "$LAN_IF" up # Bring LAN interface up.
}

configure_routes() { # Configure routing table entries.
  section "Configuring routes" # Announce routing configuration stage.
  run_cmd "Setting default route via $DEFAULT_GW" ip route replace default via "$DEFAULT_GW" dev "$EXT_IF" # Install/replace default route.
  run_cmd "Ensuring route to LAN2 $ROUTE_LAN2_NET via $ROUTE_LAN2_GW" ip route replace "$ROUTE_LAN2_NET" via "$ROUTE_LAN2_GW" dev "$EXT_IF" # Install static route toward LAN2.
}

# ------------------------- RSYSLOG CONFIG --------------------------
configure_rsyslog() { # Configure rsyslog forwarding to centralized collector.
  section "Ensuring rsyslog remote forwarding" # Announce rsyslog configuration stage.
  local conf_file="/etc/rsyslog.d/99-remote.conf" # Define config snippet path.
  cat <<EOF >"$conf_file" # Write forwarding directives to rsyslog snippet.
# Generated by AutoTableV2
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
*.* @$LOG_SERVER:514
*.* @@$LOG_SERVER:514
EOF
  run_cmd "Restarting rsyslog" systemctl restart rsyslog # Apply new rsyslog configuration.
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
  "$IPTABLES_BIN" -w -N HONEYPOT_FORWARD # Create dedicated chain for FORWARD honeypot logging.
  "$IPTABLES_BIN" -w -A HONEYPOT_INPUT -j LOG --log-prefix "HONEYPOT_ATTACK_INPUT: " --log-level 4 --log-ip-options --log-tcp-sequence --log-tcp-options --log-uid # Log attack details with full packet info.
  "$IPTABLES_BIN" -w -A HONEYPOT_INPUT -j DROP # Drop after logging to complete honeypot effect.
  "$IPTABLES_BIN" -w -A HONEYPOT_FORWARD -j LOG --log-prefix "HONEYPOT_ATTACK_FORWARD: " --log-level 4 --log-ip-options --log-tcp-sequence --log-tcp-options --log-uid # Log forwarded attack details.
  "$IPTABLES_BIN" -w -A HONEYPOT_FORWARD -j DROP # Drop after logging to complete honeypot effect.
}

base_rules() { # Apply baseline hygiene and anti-spoofing rules (with honeypot logging).
  section "Base traffic hygiene" # Announce baseline rule stage.
  "$IPTABLES_BIN" -w -A INPUT -i lo -j ACCEPT # Permit loopback traffic inbound.
  "$IPTABLES_BIN" -w -A OUTPUT -o lo -j ACCEPT # Permit loopback traffic outbound.
  "$IPTABLES_BIN" -w -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT # Allow established inbound responses.
  "$IPTABLES_BIN" -w -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT # Allow established forwarded flows.
  "$IPTABLES_BIN" -w -A INPUT -m conntrack --ctstate INVALID -j HONEYPOT_INPUT # Send invalid packets to honeypot for logging before drop.
  "$IPTABLES_BIN" -w -A FORWARD -m conntrack --ctstate INVALID -j HONEYPOT_FORWARD # Send invalid forwarded packets to honeypot.
  "$IPTABLES_BIN" -w -A INPUT -i "$LAN_IF" -s 10.10.0.0/24 -j HONEYPOT_INPUT # Log DMZ spoofing attempts from LAN side.
  "$IPTABLES_BIN" -w -A FORWARD -i "$LAN_IF" -s 10.10.0.0/24 -j HONEYPOT_FORWARD # Log spoofed DMZ traffic traversing forward path.
  "$IPTABLES_BIN" -w -A INPUT -i "$EXT_IF" -s 10.10.10.0/24 -j HONEYPOT_INPUT # Log LAN1 spoofing attempts entering external interface.
  # Block RFC1918 private addresses on external interface (spoofing detection), but exclude legitimate external network 192.168.100.0/24.
  for net in 10.0.0.0/8 172.16.0.0/12; do # Loop through RFC1918 ranges (excluding 192.168.0.0/16 to allow external network).
    "$IPTABLES_BIN" -w -A INPUT -i "$EXT_IF" -s "$net" -j HONEYPOT_INPUT # Log private source addresses arriving on external interface (spoofing attempt).
  done # End anti-spoof loop.
  # Note: 192.168.0.0/16 is intentionally NOT blocked in base_rules to allow external network 192.168.100.0/24 traffic.
  # This enables honeypot/rate limiting detection. Spoofing from other 192.168.x.x ranges will be caught by service/advanced rules if needed.
}

service_rules() { # Define application-layer access policies with honeypot logging.
  section "Service accessibility rules" # Announce service control stage.
  "$IPTABLES_BIN" -w -A INPUT -p icmp --icmp-type echo-request -s 10.10.0.0/24 -j ACCEPT # Allow DMZ hosts to ping gateway.
  "$IPTABLES_BIN" -w -A INPUT -p icmp --icmp-type echo-request -s 10.10.10.0/24 -j ACCEPT # Allow LAN1 hosts to ping gateway.
  "$IPTABLES_BIN" -w -A INPUT -p icmp --icmp-type timestamp-request -j HONEYPOT_INPUT # Log ICMP timestamp requests (reconnaissance attempt).
  "$IPTABLES_BIN" -w -A INPUT -p icmp --icmp-type timestamp-reply -j HONEYPOT_INPUT # Log outbound timestamp replies (reconnaissance attempt).
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 -s 10.10.0.0/24 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT # Allow SSH from DMZ network (trusted, no rate limit).
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 80 -j ACCEPT # Allow HTTP service for web testing.
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 443 -j ACCEPT # Allow HTTPS service for secure web testing.
  "$IPTABLES_BIN" -w -A INPUT -p udp --dport 161 -j HONEYPOT_INPUT # Log SNMP access attempts (information disclosure risk).
  # Note: Attacker IP (192.168.100.10) handling moved to advanced_security to allow SSH rate limiting before blocking.
}

forwarding_rules() { # Permit legitimate routed paths between segments with honeypot logging.
  section "Forwarding & routing policies" # Announce forwarding policy stage.
  "$IPTABLES_BIN" -w -A FORWARD -i "$LAN_IF" -o "$EXT_IF" -s 10.10.10.0/24 -d 10.10.0.0/24 -j ACCEPT # Allow LAN1 traffic toward DMZ services.
  "$IPTABLES_BIN" -w -A FORWARD -i "$EXT_IF" -o "$LAN_IF" -s 10.10.0.0/24 -d 10.10.10.0/24 -j ACCEPT # Allow DMZ servers to reply/initiate toward LAN1.
  "$IPTABLES_BIN" -w -A FORWARD -i "$LAN_IF" -o "$EXT_IF" -s 10.10.10.0/24 -d 192.168.100.0/24 -j ACCEPT # Allow LAN1 to reach external network via R2.
  # Note: Suspicious forwarding attempts (attacker IP, spoofing) are already caught by base_rules and sent to HONEYPOT_FORWARD.
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
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 -s 192.168.100.10 -j ACCEPT

  # 6) For all other SSH sources not DMZ or attacker → honeypot (DMZ SSH allowed later in service_rules)
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 ! -s 10.10.0.0/24 ! -s 192.168.100.10 -m conntrack --ctstate NEW -j HONEYPOT_INPUT

  # 7) FTP/Telnet attempts (21,23) → honeypot (no open access), after ban checks
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 21 -j HONEYPOT_INPUT
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 23 -j HONEYPOT_INPUT

  # 8) Block attacker IP for all other services (non-SSH) - honeypot effect (preserve V2 behavior)
  "$IPTABLES_BIN" -w -A INPUT -s 192.168.100.10 ! -p tcp --dport 22 -j HONEYPOT_INPUT
  "$IPTABLES_BIN" -w -A FORWARD -s 192.168.100.10 -j HONEYPOT_FORWARD

  # 9) SYN flood protection (unchanged)
  "$IPTABLES_BIN" -w -N SYN_FLOOD_CHECK # Create dedicated chain for SYN flood detection.
  "$IPTABLES_BIN" -w -A INPUT -p tcp --syn -j SYN_FLOOD_CHECK # Send all SYN packets through protection chain.
  "$IPTABLES_BIN" -w -A SYN_FLOOD_CHECK -m limit --limit 1/s --limit-burst 4 -j RETURN # Allow limited burst of SYNs (legitimate traffic).
  "$IPTABLES_BIN" -w -A SYN_FLOOD_CHECK -j HONEYPOT_INPUT # Send excess SYN traffic to honeypot for logging (DoS attack detection).
}

drop_logging() { # Add catch-all logging for unmatched packets (honeypot chains handle most attacks).
  section "Catch-all drop logging" # Announce catch-all logging configuration stage.
  "$IPTABLES_BIN" -w -A INPUT -j LOG --log-prefix "IPTABLES_INPUT_DROP: " --log-level 6 # Log unmatched INPUT packets (should be rare with honeypot chains).
  "$IPTABLES_BIN" -w -A FORWARD -j LOG --log-prefix "IPTABLES_FORWARD_DROP: " --log-level 6 # Log unmatched FORWARD packets (should be rare with honeypot chains).
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
  configure_routes # Program routing table entries.
  configure_rsyslog # Configure rsyslog forwarding behavior.
  flush_tables # Reset firewall state to a clean baseline.
  honeypot_chains # Create honeypot chains for attack detection and logging (must be before rules that use them).
  base_rules # Apply baseline hygiene policies (uses honeypot chains for suspicious traffic).
  advanced_security # Enable advanced protections FIRST (rate limiting, attacker IP handling) - must be before service_rules.
  service_rules # Configure service-specific rules (uses honeypot chains for attack logging) - DMZ SSH allowed after rate limiting.
  forwarding_rules # Configure routing/forwarding policies.
  drop_logging # Enable catch-all drop logging for any unmatched traffic.
  persist_rules # Persist firewall configuration across reboots.
  section "Completed. Firewall & logging hardened with honeypot attack detection." # Print completion message.
}

main "$@" # Execute main function with provided CLI arguments.

