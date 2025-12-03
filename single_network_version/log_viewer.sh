#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

readonly SYSLOG="/var/log/syslog"
readonly KERNEL_LOG="/var/log/kern.log"
readonly AUTH_LOG="/var/log/auth.log"
readonly IPTABLES_LOG="/var/log/iptables.log"
readonly LOG_VIEWER_CACHE="/tmp/log_viewer_cache.txt"

if command -v tput >/dev/null 2>&1 && [ -n "${TERM:-}" ]; then
  readonly GREEN="$(tput setaf 2)"
  readonly YELLOW="$(tput setaf 3)"
  readonly RED="$(tput setaf 1)"
  readonly BLUE="$(tput setaf 6)"
  readonly CYAN="$(tput setaf 5)"
  readonly RESET="$(tput sgr0)"
  readonly BOLD="$(tput bold)"
else
  readonly GREEN=""
  readonly YELLOW=""
  readonly RED=""
  readonly BLUE=""
  readonly CYAN=""
  readonly RESET=""
  readonly BOLD=""
fi

section() {
  printf "\n%s%s%s\n" "$BOLD" "$BLUE" "$1"
  printf "%s%s%s\n" "$(printf '=%.0s' {1..60})" "$RESET"
}

info()  { printf "%s[INFO]%s %s\n"  "$GREEN" "$RESET" "$1"; }
warn()  { printf "%s[WARN]%s %s\n"  "$YELLOW" "$RESET" "$1"; }
error() { printf "%s[ERR ]%s %s\n" "$RED" "$RESET" "$1"; }

check_log_files() {
  local log_files=("$SYSLOG" "$KERNEL_LOG" "$AUTH_LOG")
  local missing_files=()
  for log_file in "${log_files[@]}"; do
    if [ ! -f "$log_file" ]; then
      missing_files+=("$log_file")
    elif [ ! -r "$log_file" ]; then
      warn "$log_file exists but is not readable. Run with sudo."
    fi
  done
  if [ ${#missing_files[@]} -gt 0 ]; then
    warn "Some log files are missing: ${missing_files[*]}"
  fi
}

parse_honeypot_logs() {
  section "HONEYPOT ATTACK DETECTION LOGS"
  local honeypot_count=0
  if [ -f "$KERNEL_LOG" ]; then
    while IFS= read -r line; do
      if echo "$line" | grep -q "HONEYPOT_ATTACK"; then
        honeypot_count=$((honeypot_count + 1))
        local timestamp=$(echo "$line" | grep -oP '^\w+\s+\d+\s+[\d:]+')
        local src_ip=$(echo "$line" | grep -oP 'SRC=[\d.]+' | cut -d= -f2)
        local dst_ip=$(echo "$line" | grep -oP 'DST=[\d.]+' | cut -d= -f2)
        local protocol=$(echo "$line" | grep -oP 'PROTO=\w+' | cut -d= -f2)
        local dport=$(echo "$line" | grep -oP 'DPT=\d+' | cut -d= -f2)
        local attack_type=$(echo "$line" | grep -oP 'HONEYPOT_ATTACK_\w+:' | cut -d: -f1 | cut -d_ -f3)
        printf "%s[%s]%s %sAttack from %s%s -> %s%s on port %s%s (%s%s)\n" \
          "$CYAN" "$timestamp" "$RESET" \
          "$RED" "$src_ip" "$RESET" \
          "$YELLOW" "$dst_ip" "$RESET" \
          "$BLUE" "$dport" "$RESET" \
          "$GREEN" "$protocol" "$RESET"
      elif echo "$line" | grep -qE "(FTP_HARD_BAN:|SSH_HARD_BAN:|TELNET_HARD_BAN:)"; then
        honeypot_count=$((honeypot_count + 1))
        local timestamp=$(echo "$line" | grep -oP '^\w+\s+\d+\s+[\d:]+' )
        local prefix=$(echo "$line" | grep -oE "FTP_HARD_BAN:|SSH_HARD_BAN:|TELNET_HARD_BAN:")
        local src_ip=$(echo "$line" | grep -oP 'SRC=[\d.]+' | cut -d= -f2)
        local dst_ip=$(echo "$line" | grep -oP 'DST=[\d.]+' | cut -d= -f2)
        local dport=$(echo "$line" | grep -oP 'DPT=\d+' | cut -d= -f2)
        printf "%s[%s]%s %s%s%s from %s%s -> %s%s on port %s%s\n" \
          "$CYAN" "$timestamp" "$RESET" \
          "$RED" "$prefix" "$RESET" \
          "$RED" "$src_ip" "$RESET" \
          "$YELLOW" "$dst_ip" "$RESET" \
          "$BLUE" "$dport" "$RESET"
      fi
    done < "$KERNEL_LOG"
  fi
  if [ $honeypot_count -eq 0 ]; then
    info "No honeypot attacks detected in recent logs."
  else
    printf "\n%sTotal honeypot attacks detected: %s%d%s\n" "$BOLD" "$RED" "$honeypot_count" "$RESET"
  fi
}

parse_syn_flood_logs() {
  section "SYN FLOOD ATTACK DETECTION"
  local flood_count=0
  if [ -f "$KERNEL_LOG" ]; then
    while IFS= read -r line; do
      if echo "$line" | grep -q "SYN_FLOOD_DROP"; then
        flood_count=$((flood_count + 1))
        local timestamp=$(echo "$line" | grep -oP '^\w+\s+\d+\s+[\d:]+')
        local src_ip=$(echo "$line" | grep -oP 'SRC=[\d.]+' | cut -d= -f2)
        local dst_ip=$(echo "$line" | grep -oP 'DST=[\d.]+' | cut -d= -f2)
        local dport=$(echo "$line" | grep -oP 'DPT=\d+' | cut -d= -f2)
        printf "%s[%s]%s %sSYN Flood from %s%s -> %s%s:%s%s\n" \
          "$CYAN" "$timestamp" "$RESET" \
          "$RED" "$src_ip" "$RESET" \
          "$YELLOW" "$dst_ip" "$RESET" \
          "$BLUE" "$dport" "$RESET"
      fi
    done < "$KERNEL_LOG"
  fi
  if [ $flood_count -eq 0 ]; then
    info "No SYN flood attacks detected in recent logs."
  else
    printf "\n%sTotal SYN flood attacks: %s%d%s\n" "$BOLD" "$RED" "$flood_count" "$RESET"
  fi
}

parse_dropped_packets() {
  section "DROPPED PACKETS SUMMARY"
  local drop_count=0
  if [ -f "$KERNEL_LOG" ]; then
    while IFS= read -r line; do
      if echo "$line" | grep -q "IPTABLES.*DROP"; then
        drop_count=$((drop_count + 1))
      fi
    done < "$KERNEL_LOG"
  fi
  printf "Total dropped packets logged: %s%d%s\n" "$YELLOW" "$drop_count" "$RESET"
  if [ $drop_count -gt 0 ]; then
    info "Showing recent dropped packets:"
    tail -20 "$KERNEL_LOG" | grep "IPTABLES.*DROP" | while IFS= read -r line; do
      local timestamp=$(echo "$line" | grep -oP '^\w+\s+\d+\s+[\d:]+')
      local src_ip=$(echo "$line" | grep -oP 'SRC=[\d.]+' | cut -d= -f2)
      local dst_ip=$(echo "$line" | grep -oP 'DST=[\d.]+' | cut -d= -f2)
      printf "  %s[%s]%s %s -> %s\n" "$CYAN" "$timestamp" "$RESET" "$src_ip" "$dst_ip"
    done
  fi
}

parse_ssh_attempts() {
  section "SSH CONNECTION ATTEMPTS"
  local ssh_count=0
  if [ -f "$AUTH_LOG" ]; then
    while IFS= read -r line; do
      if echo "$line" | grep -q "sshd.*Failed\|sshd.*Accepted"; then
        ssh_count=$((ssh_count + 1))
        local timestamp=$(echo "$line" | grep -oP '^\w+\s+\d+\s+[\d:]+')
        if echo "$line" | grep -q "Failed"; then
          local ip=$(echo "$line" | grep -oP 'from [\d.]+' | cut -d' ' -f2)
          printf "%s[%s]%s %sFailed SSH login from %s%s\n" \
            "$CYAN" "$timestamp" "$RESET" \
            "$RED" "$ip" "$RESET"
        elif echo "$line" | grep -q "Accepted"; then
          local ip=$(echo "$line" | grep -oP 'from [\d.]+' | cut -d' ' -f2)
          printf "%s[%s]%s %sSuccessful SSH login from %s%s\n" \
            "$CYAN" "$timestamp" "$RESET" \
            "$GREEN" "$ip" "$RESET"
        fi
      fi
    done < "$AUTH_LOG"
  fi
  if [ $ssh_count -eq 0 ]; then
    info "No SSH connection attempts in recent logs."
  fi
}

show_attack_statistics() {
  section "ATTACK STATISTICS SUMMARY"
  local total_attacks=0
  if [ -f "$KERNEL_LOG" ]; then
    local honeypot_attacks=$(grep -c "HONEYPOT_ATTACK" "$KERNEL_LOG" 2>/dev/null || echo "0")
    local syn_floods=$(grep -c "SYN_FLOOD_DROP" "$KERNEL_LOG" 2>/dev/null || echo "0")
    local dropped=$(grep -c "IPTABLES.*DROP" "$KERNEL_LOG" 2>/dev/null || echo "0")
    total_attacks=$((honeypot_attacks + syn_floods))
    printf "Honeypot attacks detected: %s%d%s\n" "$RED" "$honeypot_attacks" "$RESET"
    printf "SYN flood attacks: %s%d%s\n" "$RED" "$syn_floods" "$RESET"
    printf "Total dropped packets: %s%d%s\n" "$YELLOW" "$dropped" "$RESET"
  fi
  if [ $total_attacks -eq 0 ]; then
    info "No attacks detected. Firewall is protecting the system."
  else
    warn "Total security events: $total_attacks"
  fi
}

show_realtime_logs() {
  section "REAL-TIME LOG MONITORING"
  info "Press Ctrl+C to stop monitoring."
  if [ -f "$KERNEL_LOG" ]; then
    tail -f "$KERNEL_LOG" | grep --line-buffered -E "HONEYPOT_ATTACK|SYN_FLOOD|IPTABLES.*DROP|FTP_HARD_BAN:|SSH_HARD_BAN:|TELNET_HARD_BAN:" | while IFS= read -r line; do
      if echo "$line" | grep -q "HONEYPOT_ATTACK"; then
        printf "%s[HONEYPOT]%s %s\n" "$RED" "$RESET" "$line"
      elif echo "$line" | grep -q "SYN_FLOOD"; then
        printf "%s[SYN_FLOOD]%s %s\n" "$YELLOW" "$RESET" "$line"
      elif echo "$line" | grep -qE "(FTP_HARD_BAN:|SSH_HARD_BAN:|TELNET_HARD_BAN:)"; then
        printf "%s[HARD_BAN]%s %s\n" "$RED" "$RESET" "$line"
      else
        printf "%s[DROP]%s %s\n" "$CYAN" "$RESET" "$line"
      fi
    done
  else
    error "Kernel log file not found. Cannot monitor logs."
  fi
}

show_menu() {
  clear
  section "IPTABLES LOG VIEWER"
  printf "Select an option:\n"
  printf "  1) View Honeypot Attack Logs\n"
  printf "  2) View SYN Flood Logs\n"
  printf "  3) View Dropped Packets\n"
  printf "  4) View SSH Connection Attempts\n"
  printf "  5) Show Attack Statistics\n"
  printf "  6) Real-time Log Monitoring\n"
  printf "  7) View All Logs\n"
  printf "  8) Exit\n"
  printf "\nChoice: "
}

main() {
  check_log_files
  if [ $# -eq 0 ]; then
    while true; do
      show_menu
      read -r choice
      case "$choice" in
        1) parse_honeypot_logs; read -p "Press Enter to continue..."; ;;
        2) parse_syn_flood_logs; read -p "Press Enter to continue..."; ;;
        3) parse_dropped_packets; read -p "Press Enter to continue..."; ;;
        4) parse_ssh_attempts; read -p "Press Enter to continue..."; ;;
        5) show_attack_statistics; read -p "Press Enter to continue..."; ;;
        6) show_realtime_logs; ;;
        7) parse_honeypot_logs; parse_syn_flood_logs; parse_dropped_packets; parse_ssh_attempts; show_attack_statistics; read -p "Press Enter to continue..."; ;;
        8) info "Exiting log viewer."; exit 0; ;;
        *) warn "Invalid choice. Please select 1-8."; sleep 2; ;;
      esac
    done
  else
    case "$1" in
      honeypot) parse_honeypot_logs; ;;
      synflood) parse_syn_flood_logs; ;;
      dropped) parse_dropped_packets; ;;
      ssh) parse_ssh_attempts; ;;
      stats) show_attack_statistics; ;;
      all) parse_honeypot_logs; parse_syn_flood_logs; parse_dropped_packets; parse_ssh_attempts; show_attack_statistics; ;;
      *) error "Invalid argument. Use: honeypot, synflood, dropped, ssh, stats, or all"; exit 1; ;;
    esac
  fi
}

main "$@"
