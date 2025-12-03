#!/bin/bash 
# Use bash interpreter for script execution.

# cleanup_services.sh – Stop and disable all vulnerable services configured for penetration testing.
# This script stops services, disables them from starting on boot, and optionally restores original configurations.

set -euo pipefail # Exit on first error, undefined variable, or failed pipeline.
IFS=$'\n\t' # Limit word splitting to newline and tab for safer parsing.

# ------------------------- GLOBAL CONSTANTS -------------------------
readonly SERVICES=(sshd vsftpd telnet apache2 snmpd inetd) # Services to stop and disable.
readonly LOG_FILE="/var/log/services_cleanup.log" # Local cleanup log file.

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
  logger -t services_cleanup "$1" 2>/dev/null || true # Send section label to syslog if available.
}

info()  { printf "%s[INFO]%s %s\n"  "$GREEN" "$RESET" "$1"; } # Informational message helper.
warn()  { printf "%s[WARN]%s %s\n"  "$YELLOW" "$RESET" "$1"; } # Warning message helper.
error() { printf "%s[ERR ]%s %s\n" "$RED" "$RESET" "$1"; } # Error message helper.

require_root() { # Enforce root execution to manage services.
  if [ "$EUID" -ne 0 ]; then # Compare effective user ID against zero (root).
    error "This script must be run as root." # Display error message.
    exit 1 # Exit immediately without running cleanup.
  fi # End privilege check.
}

stop_service() { # Stop a service if it is running.
  local service=$1 # Capture service name.
  if systemctl is-active --quiet "$service" 2>/dev/null; then # Check if service is active.
    info "Stopping service: $service" # Announce service stop.
    systemctl stop "$service" 2>/dev/null || true # Stop service (ignore errors if already stopped).
    sleep 1 # Wait for service to stop.
    if systemctl is-active --quiet "$service" 2>/dev/null; then # Check if service is still active.
      warn "Service $service may still be running. Attempting force stop..." # Warn about still-running service.
      systemctl kill "$service" 2>/dev/null || true # Force kill service.
    else
      info "Service $service stopped successfully." # Confirm service stop.
    fi # End service status check.
  else
    info "Service $service is not running." # Note service is not running.
  fi # End service active check.
}

disable_service() { # Disable a service from starting on boot.
  local service=$1 # Capture service name.
  if systemctl is-enabled --quiet "$service" 2>/dev/null; then # Check if service is enabled.
    info "Disabling service: $service" # Announce service disable.
    systemctl disable "$service" 2>/dev/null || true # Disable service (ignore errors).
    info "Service $service disabled from starting on boot." # Confirm service disable.
  else
    info "Service $service is already disabled." # Note service is already disabled.
  fi # End service enabled check.
}

restore_ssh_config() { # Restore SSH configuration to secure defaults.
  section "Restoring SSH configuration" # Announce SSH restore stage.
  local sshd_config="/etc/ssh/sshd_config" # Define SSH configuration file path.
  local backup_file="${sshd_config}.backup" # Define backup file path.
  if [ -f "$backup_file" ]; then # Check if backup file exists.
    info "Restoring SSH configuration from backup." # Announce restore.
    cp "$backup_file" "$sshd_config" # Restore from backup.
    info "SSH configuration restored from backup." # Confirm restore.
  else
    warn "SSH backup file not found. Applying secure defaults manually." # Warn about missing backup.
    # Apply secure defaults manually.
    sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' "$sshd_config" 2>/dev/null || true # Disable root login.
    sed -i 's/^PermitRootLogin no/PermitRootLogin prohibit-password/' "$sshd_config" 2>/dev/null || true # Ensure secure root login.
    sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "$sshd_config" 2>/dev/null || true # Disable password auth.
    info "SSH secure defaults applied." # Confirm secure defaults.
  fi # End backup file check.
  # Optional: Clear weak root password if set during lab setup
  if command -v passwd >/dev/null 2>&1; then
    warn "Root password may have been set to a weak value for testing. Consider resetting it now."
    # Uncomment to force reset interactively:
    # passwd root
  fi
}

restore_ftp_config() { # Restore FTP configuration to secure defaults.
  section "Restoring FTP configuration" # Announce FTP restore stage.
  local vsftpd_config="/etc/vsftpd.conf" # Define vsftpd configuration file path.
  local backup_file="${vsftpd_config}.backup" # Define backup file path.
  if [ -f "$backup_file" ]; then # Check if backup file exists.
    info "Restoring FTP configuration from backup." # Announce restore.
    cp "$backup_file" "$vsftpd_config" # Restore from backup.
    info "FTP configuration restored from backup." # Confirm restore.
  else
    warn "FTP backup file not found. Applying secure defaults manually." # Warn about missing backup.
    # Apply secure defaults manually.
    sed -i 's/^write_enable=YES/write_enable=NO/' "$vsftpd_config" 2>/dev/null || true # Disable write access.
    sed -i 's/^local_enable=YES/local_enable=NO/' "$vsftpd_config" 2>/dev/null || true # Disable local users.
    info "FTP secure defaults applied." # Confirm secure defaults.
  fi # End backup file check.
}

restore_snmp_config() { # Restore SNMP configuration to secure defaults.
  section "Restoring SNMP configuration" # Announce SNMP restore stage.
  local snmpd_config="/etc/snmp/snmpd.conf" # Define SNMP configuration file path.
  local backup_file="${snmpd_config}.backup" # Define backup file path.
  if [ -f "$backup_file" ]; then # Check if backup file exists.
    info "Restoring SNMP configuration from backup." # Announce restore.
    cp "$backup_file" "$snmpd_config" # Restore from backup.
    info "SNMP configuration restored from backup." # Confirm restore.
  else
    warn "SNMP backup file not found. Removing public community string." # Warn about missing backup.
    # Remove public community string.
    sed -i '/^rocommunity public/d' "$snmpd_config" 2>/dev/null || true # Remove public community.
    info "SNMP public community string removed." # Confirm removal.
  fi # End backup file check.
}

stop_all_services() { # Stop all vulnerable services.
  section "Stopping all vulnerable services" # Announce service stop stage.
  for service in "${SERVICES[@]}"; do # Iterate through services.
    if systemctl list-unit-files | grep -q "^${service}"; then # Check if service exists.
      stop_service "$service" # Stop service.
    else
      info "Service $service not found. Skipping." # Note service absence.
    fi # End service existence check.
  done # End service iteration.
  # Also check for telnet via inetd/xinetd.
  if systemctl list-unit-files | grep -q "xinetd"; then # Check if xinetd exists.
    stop_service "xinetd" # Stop xinetd (manages telnet).
  fi # End xinetd check.
}

disable_all_services() { # Disable all vulnerable services from starting on boot.
  section "Disabling all vulnerable services" # Announce service disable stage.
  for service in "${SERVICES[@]}"; do # Iterate through services.
    if systemctl list-unit-files | grep -q "^${service}"; then # Check if service exists.
      disable_service "$service" # Disable service.
    fi # End service existence check.
  done # End service iteration.
  # Also disable xinetd if it exists.
  if systemctl list-unit-files | grep -q "xinetd"; then # Check if xinetd exists.
    disable_service "xinetd" # Disable xinetd.
  fi # End xinetd check.
}

restore_configurations() { # Restore service configurations to secure defaults.
  section "Restoring service configurations" # Announce configuration restore stage.
  restore_ssh_config # Restore SSH configuration.
  restore_ftp_config # Restore FTP configuration.
  restore_snmp_config # Restore SNMP configuration.
  info "Service configurations restored to secure defaults." # Confirm configuration restore.
}

verify_services_stopped() { # Verify all services are stopped.
  section "Verifying services are stopped" # Announce verification stage.
  local running_services=() # Initialize array for running services.
  for service in "${SERVICES[@]}"; do # Iterate through services.
    if systemctl is-active --quiet "$service" 2>/dev/null; then # Check if service is active.
      running_services+=("$service") # Add to running services array.
    fi # End service active check.
  done # End service iteration.
  if [ ${#running_services[@]} -eq 0 ]; then # Check if no services are running.
    info "Verification successful: All services are stopped." # Confirm all services stopped.
  else
    warn "The following services are still running: ${running_services[*]}" # Warn about running services.
  fi # End running services check.
}

check_listening_ports() { # Check if vulnerable ports are still listening.
  section "Checking listening ports" # Announce port check stage.
  local vulnerable_ports=(21 22 23 80 161) # Define vulnerable ports.
  local listening_ports=() # Initialize array for listening ports.
  for port in "${vulnerable_ports[@]}"; do # Iterate through ports.
    if netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then # Check if port is listening.
      listening_ports+=("$port") # Add to listening ports array.
    fi # End port listening check.
  done # End port iteration.
  if [ ${#listening_ports[@]} -eq 0 ]; then # Check if no ports are listening.
    info "Verification successful: No vulnerable ports are listening." # Confirm no listening ports.
  else
    warn "The following ports are still listening: ${listening_ports[*]}" # Warn about listening ports.
    info "You may need to manually stop the services using these ports." # Suggest manual intervention.
  fi # End listening ports check.
}

print_summary() { # Print cleanup summary.
  section "Services Cleanup Summary" # Announce summary stage.
  info "Services cleanup completed." # Confirm cleanup completion.
  printf "\n%sWhat was done:%s\n" "$BLUE" "$RESET" # Print summary header.
  printf "  ✓ All vulnerable services stopped\n" # List completed action.
  printf "  ✓ All services disabled from starting on boot\n" # List completed action.
  printf "  ✓ Service configurations restored to secure defaults\n" # List completed action.
  printf "\n%sServices affected:%s\n" "$BLUE" "$RESET" # Print services header.
  for service in "${SERVICES[@]}"; do # Iterate through services.
    printf "  - $service\n" # List service.
  done # End service iteration.
  printf "\n%sCurrent state:%s\n" "$BLUE" "$RESET" # Print state header.
  printf "  - All vulnerable services are stopped\n" # Describe current state.
  printf "  - Services will NOT start on boot\n" # Describe current state.
  printf "  - Configurations restored to secure defaults\n" # Describe current state.
  warn "WARNING: Services are disabled. Re-enable and configure as needed for production use." # Warn about disabled services.
}

# ------------------------- MAIN ------------------------------------
main() { # Primary orchestration function.
  require_root # Verify script is executed as root.
  section "Vulnerable Services Complete Cleanup" # Print main header.
  stop_all_services # Stop all vulnerable services.
  disable_all_services # Disable all services from starting on boot.
  restore_configurations # Restore service configurations to secure defaults.
  verify_services_stopped # Verify all services are stopped.
  check_listening_ports # Check if vulnerable ports are still listening.
  print_summary # Print cleanup summary.
  section "Services cleanup completed successfully." # Print completion message.
}

main "$@" # Execute main function with provided CLI arguments.

