#!/bin/bash # Use bash interpreter for script execution.

# log_viewer.sh – Interactive log viewer for iptables and system logs on LinuxServer firewall.
# This script presents firewall logs in a readable, organized format for security analysis.

set -euo pipefail # Exit on first error, undefined variable, or failed pipeline.
IFS=$'\n\t' # Limit word splitting to newline and tab for safer parsing.

# ------------------------- GLOBAL CONSTANTS -------------------------
readonly SYSLOG="/var/log/syslog" # System log file path.
readonly KERNEL_LOG="/var/log/kern.log" # Kernel log file path (iptables logs here).
readonly AUTH_LOG="/var/log/auth.log" # Authentication log file path.
readonly IPTABLES_LOG="/var/log/iptables.log" # Custom iptables log file (if configured).
readonly LOG_VIEWER_CACHE="/tmp/log_viewer_cache.txt" # Temporary cache file for log processing.

# ------------------------- COLOR & LOG HELPERS ----------------------
if command -v tput >/dev/null 2>&1 && [ -n "${TERM:-}" ]; then # Detect terminal color support.
  readonly GREEN="$(tput setaf 2)" # ANSI code for green text.
  readonly YELLOW="$(tput setaf 3)" # ANSI code for yellow text.
  readonly RED="$(tput setaf 1)" # ANSI code for red text.
  readonly BLUE="$(tput setaf 6)" # ANSI code for cyan/blue text.
  readonly CYAN="$(tput setaf 5)" # ANSI code for cyan text.
  readonly RESET="$(tput sgr0)" # ANSI reset sequence.
  readonly BOLD="$(tput bold)" # ANSI bold text.
else
  readonly GREEN="" # Fallback blank string when no color support.
  readonly YELLOW="" # Fallback blank string when no color support.
  readonly RED="" # Fallback blank string when no color support.
  readonly BLUE="" # Fallback blank string when no color support.
  readonly CYAN="" # Fallback blank string when no color support.
  readonly RESET="" # Fallback blank string when no color support.
  readonly BOLD="" # Fallback blank string when no color support.
fi

section() { # Print section headers with formatting.
  printf "\n%s%s%s\n" "$BOLD" "$BLUE" "$1" # Emit bold, colored header.
  printf "%s%s%s\n" "$(printf '=%.0s' {1..60})" "$RESET" # Print separator line.
}

info()  { printf "%s[INFO]%s %s\n"  "$GREEN" "$RESET" "$1"; } # Informational message helper.
warn()  { printf "%s[WARN]%s %s\n"  "$YELLOW" "$RESET" "$1"; } # Warning message helper.
error() { printf "%s[ERR ]%s %s\n" "$RED" "$RESET" "$1"; } # Error message helper.

check_log_files() { # Verify log files exist and are readable.
  local log_files=("$SYSLOG" "$KERNEL_LOG" "$AUTH_LOG") # Define log files to check.
  local missing_files=() # Initialize array for missing files.
  for log_file in "${log_files[@]}"; do # Iterate through log files.
    if [ ! -f "$log_file" ]; then # Check if log file exists.
      missing_files+=("$log_file") # Add to missing files array.
    elif [ ! -r "$log_file" ]; then # Check if log file is readable.
      warn "$log_file exists but is not readable. Run with sudo." # Warn about permissions.
    fi # End file existence check.
  done # End log file iteration.
  if [ ${#missing_files[@]} -gt 0 ]; then # Check if any files are missing.
    warn "Some log files are missing: ${missing_files[*]}" # List missing files.
  fi # End missing files check.
}

parse_honeypot_logs() { # Parse and display honeypot attack logs.
  section "HONEYPOT ATTACK DETECTION LOGS" # Print section header.
  local honeypot_count=0 # Initialize attack counter.
  # Search for honeypot log entries in kernel log.
  if [ -f "$KERNEL_LOG" ]; then # Check if kernel log exists.
    while IFS= read -r line; do # Read log file line by line.
      if echo "$line" | grep -q "HONEYPOT_ATTACK"; then # Check if line contains honeypot log.
        honeypot_count=$((honeypot_count + 1)) # Increment attack counter.
        local timestamp=$(echo "$line" | grep -oP '^\w+\s+\d+\s+[\d:]+') # Extract timestamp.
        local src_ip=$(echo "$line" | grep -oP 'SRC=[\d.]+' | cut -d= -f2) # Extract source IP.
        local dst_ip=$(echo "$line" | grep -oP 'DST=[\d.]+' | cut -d= -f2) # Extract destination IP.
        local protocol=$(echo "$line" | grep -oP 'PROTO=\w+' | cut -d= -f2) # Extract protocol.
        local dport=$(echo "$line" | grep -oP 'DPT=\d+' | cut -d= -f2) # Extract destination port.
        local attack_type=$(echo "$line" | grep -oP 'HONEYPOT_ATTACK_\w+:' | cut -d: -f1 | cut -d_ -f3) # Extract attack type.
        printf "%s[%s]%s %sAttack from %s%s -> %s%s on port %s%s (%s%s)\n" \
          "$CYAN" "$timestamp" "$RESET" \
          "$RED" "$src_ip" "$RESET" \
          "$YELLOW" "$dst_ip" "$RESET" \
          "$BLUE" "$dport" "$RESET" \
          "$GREEN" "$protocol" "$RESET" # Print formatted attack log.
      fi # End honeypot log check.
    done < "$KERNEL_LOG" # End file reading.
  fi # End kernel log check.
  if [ $honeypot_count -eq 0 ]; then # Check if no attacks detected.
    info "No honeypot attacks detected in recent logs." # Confirm no attacks.
  else
    printf "\n%sTotal honeypot attacks detected: %s%d%s\n" "$BOLD" "$RED" "$honeypot_count" "$RESET" # Print attack count.
  fi # End attack count check.
}

parse_syn_flood_logs() { # Parse and display SYN flood attack logs.
  section "SYN FLOOD ATTACK DETECTION" # Print section header.
  local flood_count=0 # Initialize flood counter.
  if [ -f "$KERNEL_LOG" ]; then # Check if kernel log exists.
    while IFS= read -r line; do # Read log file line by line.
      if echo "$line" | grep -q "SYN_FLOOD_DROP"; then # Check if line contains SYN flood log.
        flood_count=$((flood_count + 1)) # Increment flood counter.
        local timestamp=$(echo "$line" | grep -oP '^\w+\s+\d+\s+[\d:]+') # Extract timestamp.
        local src_ip=$(echo "$line" | grep -oP 'SRC=[\d.]+' | cut -d= -f2) # Extract source IP.
        local dst_ip=$(echo "$line" | grep -oP 'DST=[\d.]+' | cut -d= -f2) # Extract destination IP.
        local dport=$(echo "$line" | grep -oP 'DPT=\d+' | cut -d= -f2) # Extract destination port.
        printf "%s[%s]%s %sSYN Flood from %s%s -> %s%s:%s%s\n" \
          "$CYAN" "$timestamp" "$RESET" \
          "$RED" "$src_ip" "$RESET" \
          "$YELLOW" "$dst_ip" "$RESET" \
          "$BLUE" "$dport" "$RESET" # Print formatted flood log.
      fi # End SYN flood log check.
    done < "$KERNEL_LOG" # End file reading.
  fi # End kernel log check.
  if [ $flood_count -eq 0 ]; then # Check if no floods detected.
    info "No SYN flood attacks detected in recent logs." # Confirm no floods.
  else
    printf "\n%sTotal SYN flood attacks: %s%d%s\n" "$BOLD" "$RED" "$flood_count" "$RESET" # Print flood count.
  fi # End flood count check.
}

parse_dropped_packets() { # Parse and display dropped packet logs.
  section "DROPPED PACKETS SUMMARY" # Print section header.
  local drop_count=0 # Initialize drop counter.
  if [ -f "$KERNEL_LOG" ]; then # Check if kernel log exists.
    while IFS= read -r line; do # Read log file line by line.
      if echo "$line" | grep -q "IPTABLES.*DROP"; then # Check if line contains drop log.
        drop_count=$((drop_count + 1)) # Increment drop counter.
      fi # End drop log check.
    done < "$KERNEL_LOG" # End file reading.
  fi # End kernel log check.
  printf "Total dropped packets logged: %s%d%s\n" "$YELLOW" "$drop_count" "$RESET" # Print drop count.
  if [ $drop_count -gt 0 ]; then # Check if drops exist.
    info "Showing recent dropped packets:" # Announce recent drops.
    tail -20 "$KERNEL_LOG" | grep "IPTABLES.*DROP" | while IFS= read -r line; do # Process recent drops.
      local timestamp=$(echo "$line" | grep -oP '^\w+\s+\d+\s+[\d:]+') # Extract timestamp.
      local src_ip=$(echo "$line" | grep -oP 'SRC=[\d.]+' | cut -d= -f2) # Extract source IP.
      local dst_ip=$(echo "$line" | grep -oP 'DST=[\d.]+' | cut -d= -f2) # Extract destination IP.
      printf "  %s[%s]%s %s -> %s\n" "$CYAN" "$timestamp" "$RESET" "$src_ip" "$dst_ip" # Print formatted drop log.
    done # End drop processing.
  fi # End drop count check.
}

parse_ssh_attempts() { # Parse and display SSH connection attempts.
  section "SSH CONNECTION ATTEMPTS" # Print section header.
  local ssh_count=0 # Initialize SSH counter.
  if [ -f "$AUTH_LOG" ]; then # Check if auth log exists.
    while IFS= read -r line; do # Read log file line by line.
      if echo "$line" | grep -q "sshd.*Failed\|sshd.*Accepted"; then # Check if line contains SSH log.
        ssh_count=$((ssh_count + 1)) # Increment SSH counter.
        local timestamp=$(echo "$line" | grep -oP '^\w+\s+\d+\s+[\d:]+') # Extract timestamp.
        if echo "$line" | grep -q "Failed"; then # Check if login failed.
          local ip=$(echo "$line" | grep -oP 'from [\d.]+' | cut -d' ' -f2) # Extract IP address.
          printf "%s[%s]%s %sFailed SSH login from %s%s\n" \
            "$CYAN" "$timestamp" "$RESET" \
            "$RED" "$ip" "$RESET" # Print failed login.
        elif echo "$line" | grep -q "Accepted"; then # Check if login succeeded.
          local ip=$(echo "$line" | grep -oP 'from [\d.]+' | cut -d' ' -f2) # Extract IP address.
          printf "%s[%s]%s %sSuccessful SSH login from %s%s\n" \
            "$CYAN" "$timestamp" "$RESET" \
            "$GREEN" "$ip" "$RESET" # Print successful login.
        fi # End login type check.
      fi # End SSH log check.
    done < "$AUTH_LOG" # End file reading.
  fi # End auth log check.
  if [ $ssh_count -eq 0 ]; then # Check if no SSH attempts.
    info "No SSH connection attempts in recent logs." # Confirm no SSH attempts.
  fi # End SSH count check.
}

show_attack_statistics() { # Display attack statistics summary.
  section "ATTACK STATISTICS SUMMARY" # Print section header.
  local total_attacks=0 # Initialize total attack counter.
  # Count honeypot attacks.
  if [ -f "$KERNEL_LOG" ]; then # Check if kernel log exists.
    local honeypot_attacks=$(grep -c "HONEYPOT_ATTACK" "$KERNEL_LOG" 2>/dev/null || echo "0") # Count honeypot attacks.
    local syn_floods=$(grep -c "SYN_FLOOD_DROP" "$KERNEL_LOG" 2>/dev/null || echo "0") # Count SYN floods.
    local dropped=$(grep -c "IPTABLES.*DROP" "$KERNEL_LOG" 2>/dev/null || echo "0") # Count dropped packets.
    total_attacks=$((honeypot_attacks + syn_floods)) # Calculate total attacks.
    printf "Honeypot attacks detected: %s%d%s\n" "$RED" "$honeypot_attacks" "$RESET" # Print honeypot count.
    printf "SYN flood attacks: %s%d%s\n" "$RED" "$syn_floods" "$RESET" # Print SYN flood count.
    printf "Total dropped packets: %s%d%s\n" "$YELLOW" "$dropped" "$RESET" # Print drop count.
  fi # End kernel log check.
  if [ $total_attacks -eq 0 ]; then # Check if no attacks.
    info "No attacks detected. Firewall is protecting the system." # Confirm no attacks.
  else
    warn "Total security events: $total_attacks" # Warn about security events.
  fi # End total attacks check.
}

show_realtime_logs() { # Show real-time log monitoring (optional).
  section "REAL-TIME LOG MONITORING" # Print section header.
  info "Press Ctrl+C to stop monitoring." # Display instruction.
  if [ -f "$KERNEL_LOG" ]; then # Check if kernel log exists.
    tail -f "$KERNEL_LOG" | grep --line-buffered -E "HONEYPOT_ATTACK|SYN_FLOOD|IPTABLES.*DROP" | while IFS= read -r line; do # Monitor logs in real-time.
      if echo "$line" | grep -q "HONEYPOT_ATTACK"; then # Check if honeypot attack.
        printf "%s[HONEYPOT]%s %s\n" "$RED" "$RESET" "$line" # Print honeypot attack.
      elif echo "$line" | grep -q "SYN_FLOOD"; then # Check if SYN flood.
        printf "%s[SYN_FLOOD]%s %s\n" "$YELLOW" "$RESET" "$line" # Print SYN flood.
      else # Handle other drops.
        printf "%s[DROP]%s %s\n" "$CYAN" "$RESET" "$line" # Print drop.
      fi # End log type check.
    done # End log monitoring.
  else
    error "Kernel log file not found. Cannot monitor logs." # Report missing log file.
  fi # End kernel log check.
}

show_menu() { # Display interactive menu.
  clear # Clear screen.
  section "IPTABLES LOG VIEWER" # Print main header.
  printf "Select an option:\n" # Display menu prompt.
  printf "  1) View Honeypot Attack Logs\n" # List option 1.
  printf "  2) View SYN Flood Logs\n" # List option 2.
  printf "  3) View Dropped Packets\n" # List option 3.
  printf "  4) View SSH Connection Attempts\n" # List option 4.
  printf "  5) Show Attack Statistics\n" # List option 5.
  printf "  6) Real-time Log Monitoring\n" # List option 6.
  printf "  7) View All Logs\n" # List option 7.
  printf "  8) Exit\n" # List option 8.
  printf "\nChoice: " # Display choice prompt.
}

# ------------------------- MAIN ------------------------------------
main() { # Primary orchestration function.
  check_log_files # Verify log files exist and are readable.
  if [ $# -eq 0 ]; then # Check if no arguments provided (interactive mode).
    while true; do # Start interactive loop.
      show_menu # Display interactive menu.
      read -r choice # Read user choice.
      case "$choice" in # Process user choice.
        1) parse_honeypot_logs; read -p "Press Enter to continue..."; ;; # View honeypot logs.
        2) parse_syn_flood_logs; read -p "Press Enter to continue..."; ;; # View SYN flood logs.
        3) parse_dropped_packets; read -p "Press Enter to continue..."; ;; # View dropped packets.
        4) parse_ssh_attempts; read -p "Press Enter to continue..."; ;; # View SSH attempts.
        5) show_attack_statistics; read -p "Press Enter to continue..."; ;; # Show statistics.
        6) show_realtime_logs; ;; # Real-time monitoring.
        7) parse_honeypot_logs; parse_syn_flood_logs; parse_dropped_packets; parse_ssh_attempts; show_attack_statistics; read -p "Press Enter to continue..."; ;; # View all logs.
        8) info "Exiting log viewer."; exit 0; ;; # Exit program.
        *) warn "Invalid choice. Please select 1-8."; sleep 2; ;; # Handle invalid choice.
      esac # End case statement.
    done # End interactive loop.
  else # Handle command-line arguments.
    case "$1" in # Process command-line argument.
      honeypot) parse_honeypot_logs; ;; # View honeypot logs.
      synflood) parse_syn_flood_logs; ;; # View SYN flood logs.
      dropped) parse_dropped_packets; ;; # View dropped packets.
      ssh) parse_ssh_attempts; ;; # View SSH attempts.
      stats) show_attack_statistics; ;; # Show statistics.
      all) parse_honeypot_logs; parse_syn_flood_logs; parse_dropped_packets; parse_ssh_attempts; show_attack_statistics; ;; # View all logs.
      *) error "Invalid argument. Use: honeypot, synflood, dropped, ssh, stats, or all"; exit 1; ;; # Handle invalid argument.
    esac # End case statement.
  fi # End argument check.
}

main "$@" # Execute main function with provided CLI arguments.

