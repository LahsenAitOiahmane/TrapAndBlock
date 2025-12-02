#!/bin/bash
# AutoTableV2 – Hardened Firewall + Honeypot + SSH Hard Ban (60 seconds)

set -euo pipefail
IFS=$'\n\t'

# ------------------------- GLOBAL CONSTANTS -------------------------
readonly NET_IF="eth0"
readonly VICTIM_IP="192.168.1.144/24"
readonly ATTACKER_IP="192.168.1.145"
readonly NETWORK="192.168.1.0/24"
readonly DEFAULT_GW="192.168.1.1"
readonly LOG_FILE="/var/log/autotablev2_single.log"
readonly REQUIRED_PACKAGES=(iptables iptables-persistent rsyslog iproute2 net-tools)
readonly IPTABLES_BIN=$(command -v iptables)

# ------------------------- COLOR & LOG HELPERS ----------------------
if command -v tput >/dev/null 2>&1 && [ -n "${TERM:-}" ]; then
  readonly GREEN="$(tput setaf 2)"
  readonly YELLOW="$(tput setaf 3)"
  readonly RED="$(tput setaf 1)"
  readonly BLUE="$(tput setaf 6)"
  readonly RESET="$(tput sgr0)"
else
  readonly GREEN=""; readonly YELLOW=""
  readonly RED=""; readonly BLUE=""
  readonly RESET=""
fi

section() { printf "\n%s[%s]%s %s\n" "$BLUE" "$(date -u +'%H:%M:%S')" "$RESET" "$1"; logger -t autotablev2 "$1"; }
info()  { printf "%s[INFO]%s %s\n" "$GREEN" "$RESET" "$1"; logger -t autotablev2 "INFO: $1"; }
warn()  { printf "%s[WARN]%s %s\n" "$YELLOW" "$RESET" "$1"; logger -t autotablev2 "WARN: $1"; }
error() { printf "%s[ERR ]%s %s\n" "$RED" "$RESET" "$1"; logger -t autotablev2 "ERR : $1"; }

run_cmd() {
  local desc=$1; shift
  info "$desc"
  if ! "$@"; then error "Failure running: $*"; exit 1; fi
}

ensure_log_file() {
  sudo touch "$LOG_FILE"
  sudo chmod 640 "$LOG_FILE"
  exec > >(tee -a "$LOG_FILE") 2>&1
}

# ------------------------- PRE-FLIGHT CHECKS ------------------------
require_root() {
  if [ "$EUID" -ne 0 ]; then error "This script must run as root."; exit 1; fi
}

install_dependencies() {
  section "Installing/Verifying packages"
  export DEBIAN_FRONTEND=noninteractive
  run_cmd "Updating apt cache" apt-get update -qq
  run_cmd "Installing packages" apt-get install -y "${REQUIRED_PACKAGES[@]}"
}

# ------------------------- NETWORK CONFIG --------------------------
configure_interfaces() {
  section "Configuring network interface"
  run_cmd "Assigning $VICTIM_IP" ip addr replace "$VICTIM_IP" dev "$NET_IF"
  run_cmd "Bringing $NET_IF up" ip link set "$NET_IF" up
}

configure_routes() {
  section "Configuring routes"
  if ping -c 1 -W 1 "$DEFAULT_GW" >/dev/null 2>&1; then
    run_cmd "Setting default route via $DEFAULT_GW" ip route replace default via "$DEFAULT_GW" dev "$NET_IF"
  else
    warn "Gateway unreachable — skipping."
  fi
}

configure_rsyslog() {
  section "Configuring rsyslog"
  run_cmd "Restart rsyslog" systemctl restart rsyslog
  run_cmd "Enable rsyslog" systemctl enable rsyslog
}

# ------------------------- IPTABLES HELPERS ------------------------
flush_tables() {
  section "Flushing iptables"
  for table in filter nat mangle raw; do
    run_cmd "Flush $table" "$IPTABLES_BIN" -w -t "$table" -F
    run_cmd "Delete chains in $table" "$IPTABLES_BIN" -w -t "$table" -X
  done
  run_cmd "Set INPUT DROP" "$IPTABLES_BIN" -w -P INPUT DROP
  run_cmd "Set FORWARD DROP" "$IPTABLES_BIN" -w -P FORWARD DROP
  run_cmd "Set OUTPUT ACCEPT" "$IPTABLES_BIN" -w -P OUTPUT ACCEPT
}

honeypot_chains() {
  section "Creating honeypot chains"
  "$IPTABLES_BIN" -w -N HONEYPOT_INPUT
  "$IPTABLES_BIN" -w -A HONEYPOT_INPUT -j LOG --log-prefix "HONEYPOT_ATTACK: " --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
  "$IPTABLES_BIN" -w -A HONEYPOT_INPUT -j DROP
}

base_rules() {
  section "Base rules & anti-spoofing"

  "$IPTABLES_BIN" -w -A INPUT -i lo -j ACCEPT
  "$IPTABLES_BIN" -w -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

  # Drop invalid early
  "$IPTABLES_BIN" -w -A INPUT -m conntrack --ctstate INVALID -j HONEYPOT_INPUT

  # Anti-spoofing
  "$IPTABLES_BIN" -w -N CHECK_SPOOFING
  "$IPTABLES_BIN" -w -A INPUT -i "$NET_IF" -s 0.0.0.0/0 -j CHECK_SPOOFING
  "$IPTABLES_BIN" -w -A CHECK_SPOOFING -s "$NETWORK" -j RETURN
  "$IPTABLES_BIN" -w -A CHECK_SPOOFING -j HONEYPOT_INPUT
}

service_rules() {
  section "Service rules"

  "$IPTABLES_BIN" -w -A INPUT -p icmp --icmp-type echo-request -s "$NETWORK" -j ACCEPT
  "$IPTABLES_BIN" -w -A INPUT -p icmp --icmp-type timestamp-request -j HONEYPOT_INPUT
  "$IPTABLES_BIN" -w -A INPUT -p icmp --icmp-type timestamp-reply -j HONEYPOT_INPUT

  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 80 -j ACCEPT
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 443 -j ACCEPT

  # Log legacy services
  for port in 21 23; do
    "$IPTABLES_BIN" -w -A INPUT -p tcp --dport "$port" -j HONEYPOT_INPUT
  done

  "$IPTABLES_BIN" -w -A INPUT -p udp --dport 161 -j HONEYPOT_INPUT
}

advanced_security() {
  section "Advanced SSH Hard Ban (Prison Mode)"

  # 1. Already banned → block & refresh timer
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 \
      -m recent --name SSH_BANNED --update --seconds 60 -j DROP

  # 2. Track new attempts
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 \
      -m conntrack --ctstate NEW -m recent --name SSH_COUNT --set

  # 3. If >3 attempts in 60s → ban
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 \
      -m conntrack --ctstate NEW \
      -m recent --name SSH_COUNT --rcheck --seconds 60 --hitcount 4 \
      -j LOG --log-prefix "SSH_HARD_BAN: " --log-level 4

  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 \
      -m conntrack --ctstate NEW \
      -m recent --name SSH_COUNT --rcheck --seconds 60 --hitcount 4 \
      -m recent --name SSH_BANNED --set -j DROP

  # 4. Allow legitimate SSH only AFTER ban checks
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 -s "$ATTACKER_IP" -j ACCEPT
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 -s "$NETWORK" -j ACCEPT

  # 5. Others → honeypot
  "$IPTABLES_BIN" -w -A INPUT -p tcp --dport 22 -j HONEYPOT_INPUT

  # 6. Block attacker from all *other* services
  "$IPTABLES_BIN" -w -A INPUT -s "$ATTACKER_IP" ! -p tcp --dport 22 -j HONEYPOT_INPUT

  # SYN flood protection
  "$IPTABLES_BIN" -w -N SYN_FLOOD_CHECK
  "$IPTABLES_BIN" -w -A INPUT -p tcp --syn -j SYN_FLOOD_CHECK
  "$IPTABLES_BIN" -w -A SYN_FLOOD_CHECK -m limit --limit 1/s --limit-burst 4 -j RETURN
  "$IPTABLES_BIN" -w -A SYN_FLOOD_CHECK -j HONEYPOT_INPUT
}

drop_logging() {
  section "Final catch-all logging"
  "$IPTABLES_BIN" -w -A INPUT -j LOG --log-prefix "DROP: " --log-level 6
}

persist_rules() {
  section "Persisting iptables rules"
  run_cmd "Saving with iptables-save" iptables-save > /etc/iptables/rules.v4
  run_cmd "Enable netfilter-persistent" systemctl enable netfilter-persistent
  run_cmd "Saving rules" netfilter-persistent save
}

# ------------------------- MAIN ------------------------------------
main() {
  require_root
  ensure_log_file
  install_dependencies
  configure_interfaces
  configure_routes
  configure_rsyslog
  flush_tables
  honeypot_chains
  base_rules
  advanced_security
  service_rules
  drop_logging
  persist_rules
  section "DONE – Firewall ACTIVE with Honeypot + Hard Ban (60s)"
}

main "$@"

