#!/bin/bash 
# Use bash interpreter for script execution.

# cleanup_iptables.sh – Complete iptables firewall reset and cleanup script.
# This script removes all iptables rules, chains, and restores firewall to default state (like fresh install).

set -euo pipefail # Exit on first error, undefined variable, or failed pipeline.
IFS=$'\n\t' # Limit word splitting to newline and tab for safer parsing.

# ------------------------- GLOBAL CONSTANTS -------------------------
readonly IPTABLES_BIN=$(command -v iptables) # Resolve absolute iptables binary path.
readonly IPTABLES_SAVE_BIN=$(command -v iptables-save) # Resolve iptables-save binary path.
readonly LOG_FILE="/var/log/iptables_cleanup.log" # Local cleanup log file.

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
  logger -t iptables_cleanup "$1" 2>/dev/null || true # Send section label to syslog if available.
}

info()  { printf "%s[INFO]%s %s\n"  "$GREEN" "$RESET" "$1"; } # Informational message helper.
warn()  { printf "%s[WARN]%s %s\n"  "$YELLOW" "$RESET" "$1"; } # Warning message helper.
error() { printf "%s[ERR ]%s %s\n" "$RED" "$RESET" "$1"; } # Error message helper.

require_root() { # Enforce root execution to manage firewall.
  if [ "$EUID" -ne 0 ]; then # Compare effective user ID against zero (root).
    error "This script must be run as root." # Display error message.
    exit 1 # Exit immediately without running cleanup.
  fi # End privilege check.
}

backup_current_rules() { # Backup current iptables rules before cleanup.
  section "Backing up current iptables rules" # Announce backup stage.
  local backup_file="/tmp/iptables_backup_$(date +%Y%m%d_%H%M%S).rules" # Create timestamped backup filename.
  if [ -f "$IPTABLES_SAVE_BIN" ]; then # Check if iptables-save exists.
    "$IPTABLES_SAVE_BIN" > "$backup_file" 2>/dev/null || true # Save current rules to backup file.
    if [ -s "$backup_file" ]; then # Check if backup file has content.
      info "Current rules backed up to: $backup_file" # Confirm backup creation.
    else
      warn "Backup file is empty (no rules to backup)." # Warn about empty backup.
    fi # End backup content check.
  else
    warn "iptables-save not found. Skipping backup." # Warn about missing tool.
  fi # End iptables-save check.
}

flush_all_tables() { # Flush all iptables tables and chains.
  section "Flushing all iptables tables" # Announce flushing stage.
  for table in filter nat mangle raw security; do # Iterate through all netfilter tables.
    if "$IPTABLES_BIN" -w -t "$table" -L >/dev/null 2>&1; then # Check if table exists.
      info "Flushing table: $table" # Announce table being flushed.
      "$IPTABLES_BIN" -w -t "$table" -F # Flush all rules in table.
      "$IPTABLES_BIN" -w -t "$table" -X # Delete all custom chains in table.
      "$IPTABLES_BIN" -w -t "$table" -Z # Zero packet and byte counters.
    fi # End table existence check.
  done # End table iteration.
  # Clear iptables 'recent' lists used by hard-ban logic if present
  for recent_list in ABUSE_COUNT ABUSE_BANNED; do
    local recent_path="/proc/net/xt_recent/${recent_list}"
    if [ -w "$recent_path" ]; then
      info "Clearing recent list: ${recent_list}"
      # Clear entries by writing 'clear' to the file (kernel xt_recent)
      echo clear > "$recent_path" 2>/dev/null || true
    fi
  done
  info "All tables flushed successfully." # Confirm flushing completion.
}

reset_default_policies() { # Reset default policies to ACCEPT (default Linux behavior).
  section "Resetting default policies" # Announce policy reset stage.
  "$IPTABLES_BIN" -w -P INPUT ACCEPT # Set INPUT policy to ACCEPT (default).
  "$IPTABLES_BIN" -w -P FORWARD ACCEPT # Set FORWARD policy to ACCEPT (default).
  "$IPTABLES_BIN" -w -P OUTPUT ACCEPT # Set OUTPUT policy to ACCEPT (default).
  info "Default policies reset to ACCEPT (default Linux behavior)." # Confirm policy reset.
}

remove_persistent_rules() { # Remove persistent iptables rules files.
  section "Removing persistent iptables rules" # Announce persistent rules removal.
  local rules_file="/etc/iptables/rules.v4" # Define persistent rules file path.
  if [ -f "$rules_file" ]; then # Check if persistent rules file exists.
    info "Backing up persistent rules file before removal." # Announce backup.
    cp "$rules_file" "${rules_file}.backup.$(date +%Y%m%d_%H%M%S)" # Backup persistent rules.
    rm -f "$rules_file" # Remove persistent rules file.
    info "Persistent rules file removed: $rules_file" # Confirm removal.
  else
    info "No persistent rules file found: $rules_file" # Note absence of rules file.
  fi # End rules file check.
  # Also check for IPv6 rules.
  local rules_file_v6="/etc/iptables/rules.v6" # Define IPv6 persistent rules file path.
  if [ -f "$rules_file_v6" ]; then # Check if IPv6 persistent rules file exists.
    cp "$rules_file_v6" "${rules_file_v6}.backup.$(date +%Y%m%d_%H%M%S)" # Backup IPv6 persistent rules.
    rm -f "$rules_file_v6" # Remove IPv6 persistent rules file.
    info "IPv6 persistent rules file removed: $rules_file_v6" # Confirm removal.
  fi # End IPv6 rules file check.
}

disable_persistent_service() { # Disable netfilter-persistent service.
  section "Disabling netfilter-persistent service" # Announce service disable stage.
  if systemctl list-unit-files | grep -q netfilter-persistent; then # Check if service exists.
    systemctl stop netfilter-persistent 2>/dev/null || true # Stop service if running.
    systemctl disable netfilter-persistent 2>/dev/null || true # Disable service from starting on boot.
    info "netfilter-persistent service disabled." # Confirm service disable.
  else
    info "netfilter-persistent service not found or already disabled." # Note service status.
  fi # End service check.
}

verify_cleanup() { # Verify that iptables is in default state.
  section "Verifying cleanup" # Announce verification stage.
  local rule_count=0 # Initialize rule counter.
  for table in filter nat mangle raw; do # Iterate through main tables.
    local table_rules=$("$IPTABLES_BIN" -w -t "$table" -L -n 2>/dev/null | grep -c '^[A-Z]' || echo "0") # Count rules in table.
    rule_count=$((rule_count + table_rules)) # Add to total rule count.
  done # End table iteration.
  if [ "$rule_count" -eq 0 ]; then # Check if no rules exist.
    info "Verification successful: No iptables rules found (clean state)." # Confirm clean state.
  else
    warn "Verification: $rule_count rules still exist. Manual review may be needed." # Warn about remaining rules.
  fi # End rule count check.
  # Check default policies.
  local input_policy=$("$IPTABLES_BIN" -w -P INPUT 2>/dev/null | awk '{print $3}') # Get INPUT policy.
  local forward_policy=$("$IPTABLES_BIN" -w -P FORWARD 2>/dev/null | awk '{print $3}') # Get FORWARD policy.
  local output_policy=$("$IPTABLES_BIN" -w -P OUTPUT 2>/dev/null | awk '{print $3}') # Get OUTPUT policy.
  if [[ "$input_policy" == "ACCEPT" ]] && [[ "$forward_policy" == "ACCEPT" ]] && [[ "$output_policy" == "ACCEPT" ]]; then # Check if all policies are ACCEPT.
    info "Default policies verified: INPUT=ACCEPT, FORWARD=ACCEPT, OUTPUT=ACCEPT" # Confirm default policies.
  else
    warn "Default policies: INPUT=$input_policy, FORWARD=$forward_policy, OUTPUT=$output_policy" # Warn about non-default policies.
  fi # End policy check.
}

print_summary() { # Print cleanup summary.
  section "Cleanup Summary" # Announce summary stage.
  info "iptables cleanup completed." # Confirm cleanup completion.
  printf "\n%sWhat was done:%s\n" "$BLUE" "$RESET" # Print summary header.
  printf "  ✓ All iptables rules flushed\n" # List completed action.
  printf "  ✓ All custom chains deleted\n" # List completed action.
  printf "  ✓ Default policies reset to ACCEPT\n" # List completed action.
  printf "  ✓ Persistent rules files removed\n" # List completed action.
  printf "  ✓ netfilter-persistent service disabled\n" # List completed action.
  printf "\n%sCurrent state:%s\n" "$BLUE" "$RESET" # Print state header.
  printf "  - iptables is now in default state (like fresh install)\n" # Describe current state.
  printf "  - All traffic is allowed (no firewall rules)\n" # Describe current state.
  printf "  - Rules will NOT persist after reboot\n" # Describe current state.
  warn "WARNING: System is now unprotected. Configure firewall rules as needed." # Warn about unprotected state.
}

# ------------------------- MAIN ------------------------------------
main() { # Primary orchestration function.
  require_root # Verify script is executed as root.
  section "IPTables Complete Cleanup" # Print main header.
  backup_current_rules # Backup current rules before cleanup.
  flush_all_tables # Flush all iptables tables and chains.
  reset_default_policies # Reset default policies to ACCEPT.
  remove_persistent_rules # Remove persistent rules files.
  disable_persistent_service # Disable netfilter-persistent service.
  verify_cleanup # Verify cleanup was successful.
  print_summary # Print cleanup summary.
  section "iptables cleanup completed successfully." # Print completion message.
}

main "$@" # Execute main function with provided CLI arguments.

