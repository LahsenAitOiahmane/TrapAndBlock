#!/bin/bash 
# Use bash interpreter for script execution.

# cleanup_all.sh – Master cleanup script that resets both iptables and services to default state.
# This script runs both cleanup_iptables.sh and cleanup_services.sh to completely reset the system.

set -euo pipefail # Exit on first error, undefined variable, or failed pipeline.
IFS=$'\n\t' # Limit word splitting to newline and tab for safer parsing.

# ------------------------- GLOBAL CONSTANTS -------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" # Get script directory.
readonly IPTABLES_CLEANUP="${SCRIPT_DIR}/cleanup_iptables.sh" # Path to iptables cleanup script.
readonly SERVICES_CLEANUP="${SCRIPT_DIR}/cleanup_services.sh" # Path to services cleanup script.

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
  printf "\n%s%s%s\n" "$BLUE" "$(printf '=%.0s' {1..60})" "$RESET" # Print separator line.
  printf "%s[%s]%s %s\n" "$BLUE" "$(date +'%H:%M:%S')" "$RESET" "$1" # Emit colored, timestamped header.
  printf "%s%s%s\n" "$BLUE" "$(printf '=%.0s' {1..60})" "$RESET" # Print separator line.
}

info()  { printf "%s[INFO]%s %s\n"  "$GREEN" "$RESET" "$1"; } # Informational message helper.
warn()  { printf "%s[WARN]%s %s\n"  "$YELLOW" "$RESET" "$1"; } # Warning message helper.
error() { printf "%s[ERR ]%s %s\n" "$RED" "$RESET" "$1"; } # Error message helper.

require_root() { # Enforce root execution.
  if [ "$EUID" -ne 0 ]; then # Compare effective user ID against zero (root).
    error "This script must be run as root." # Display error message.
    exit 1 # Exit immediately.
  fi # End privilege check.
}

check_scripts() { # Verify cleanup scripts exist and are executable.
  section "Checking cleanup scripts" # Announce script check stage.
  local missing_scripts=() # Initialize array for missing scripts.
  if [ ! -f "$IPTABLES_CLEANUP" ]; then # Check if iptables cleanup script exists.
    missing_scripts+=("$IPTABLES_CLEANUP") # Add to missing scripts array.
  elif [ ! -x "$IPTABLES_CLEANUP" ]; then # Check if script is executable.
    info "Making iptables cleanup script executable." # Announce making executable.
    chmod +x "$IPTABLES_CLEANUP" # Make script executable.
  fi # End iptables script check.
  if [ ! -f "$SERVICES_CLEANUP" ]; then # Check if services cleanup script exists.
    missing_scripts+=("$SERVICES_CLEANUP") # Add to missing scripts array.
  elif [ ! -x "$SERVICES_CLEANUP" ]; then # Check if script is executable.
    info "Making services cleanup script executable." # Announce making executable.
    chmod +x "$SERVICES_CLEANUP" # Make script executable.
  fi # End services script check.
  if [ ${#missing_scripts[@]} -gt 0 ]; then # Check if any scripts are missing.
    error "Missing cleanup scripts: ${missing_scripts[*]}" # Report missing scripts.
    exit 1 # Exit with error.
  fi # End missing scripts check.
  info "All cleanup scripts found and ready." # Confirm scripts are ready.
}

run_iptables_cleanup() { # Run iptables cleanup script.
  section "Running iptables cleanup" # Announce iptables cleanup stage.
  if bash "$IPTABLES_CLEANUP"; then # Execute iptables cleanup script.
    info "iptables cleanup completed successfully." # Confirm successful cleanup.
    return 0 # Return success.
  else
    error "iptables cleanup failed. Continuing with services cleanup..." # Report failure.
    return 1 # Return failure.
  fi # End iptables cleanup execution.
}

run_services_cleanup() { # Run services cleanup script.
  section "Running services cleanup" # Announce services cleanup stage.
  if bash "$SERVICES_CLEANUP"; then # Execute services cleanup script.
    info "Services cleanup completed successfully." # Confirm successful cleanup.
    return 0 # Return success.
  else
    error "Services cleanup failed." # Report failure.
    return 1 # Return failure.
  fi # End services cleanup execution.
}

print_final_summary() { # Print final cleanup summary.
  section "Complete Cleanup Summary" # Announce final summary stage.
  info "Complete system cleanup finished." # Confirm cleanup completion.
  printf "\n%sWhat was cleaned:%s\n" "$BLUE" "$RESET" # Print summary header.
  printf "  ✓ All iptables rules removed\n" # List completed action.
  printf "  ✓ All iptables chains deleted\n" # List completed action.
  printf "  ✓ Default firewall policies reset\n" # List completed action.
  printf "  ✓ Persistent firewall rules removed\n" # List completed action.
  printf "  ✓ Hard-ban recent lists cleared (ABUSE_COUNT, ABUSE_BANNED)\n" # Reflect xt_recent cleanup.
  printf "  ✓ All vulnerable services stopped\n" # List completed action.
  printf "  ✓ All services disabled from boot\n" # List completed action.
  printf "  ✓ Service configurations restored\n" # List completed action.
  printf "\n%sSystem state:%s\n" "$BLUE" "$RESET" # Print state header.
  printf "  - Firewall: Default state (all traffic allowed)\n" # Describe firewall state.
  printf "  - Services: All stopped and disabled\n" # Describe services state.
  printf "  - Configuration: Restored to secure defaults\n" # Describe configuration state.
  printf "\n%sNext steps:%s\n" "$BLUE" "$RESET" # Print next steps header.
  printf "  1. System is now in default state (like fresh install)\n" # List step 1.
  printf "  2. Configure firewall and services as needed for production\n" # List step 2.
  printf "  3. Review backup files in /tmp/ if you need to restore anything\n" # List step 3.
  warn "WARNING: System is now completely unprotected. Configure security as needed." # Warn about unprotected state.
}

# ------------------------- MAIN ------------------------------------
main() { # Primary orchestration function.
  require_root # Verify script is executed as root.
  section "Complete System Cleanup" # Print main header.
  check_scripts # Verify cleanup scripts exist.
  run_iptables_cleanup # Run iptables cleanup.
  run_services_cleanup # Run services cleanup.
  print_final_summary # Print final summary.
  section "Complete cleanup finished successfully." # Print completion message.
}

main "$@" # Execute main function with provided CLI arguments.

