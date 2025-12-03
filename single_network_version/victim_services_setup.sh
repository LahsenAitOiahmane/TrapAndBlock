#!/bin/bash # Use bash interpreter for script execution.

# victim_services_setup.sh – Service configuration script for LinuxServer victim machine.
# This script opens vulnerable services (FTP, SSH, Telnet, HTTP, SNMP) for penetration testing.

set -euo pipefail # Exit on first error, undefined variable, or failed pipeline.
IFS=$'\n\t' # Limit word splitting to newline and tab for safer parsing.

# ------------------------- GLOBAL CONSTANTS -------------------------
readonly REQUIRED_PACKAGES=(vsftpd openssh-server telnetd apache2 snmpd) # Required service packages.
readonly LOG_FILE="/var/log/victim_services_setup.log" # Local setup log file.

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
  logger -t victim_services "$1" # Send section label to syslog for auditing.
}

info()  { printf "%s[INFO]%s %s\n"  "$GREEN" "$RESET" "$1"; logger -t victim_services "INFO: $1"; } # Informational message helper.
warn()  { printf "%s[WARN]%s %s\n"  "$YELLOW" "$RESET" "$1"; logger -t victim_services "WARN: $1"; } # Warning message helper.
error() { printf "%s[ERR ]%s %s\n" "$RED" "$RESET" "$1"; logger -t victim_services "ERR : $1"; } # Error message helper.

run_cmd() { # Wrapper adding logging and exit-on-failure semantics.
  local desc=$1 # Capture human-readable description.
  shift # Remove description from argument list.
  info "$desc" # Report upcoming action.
  if ! "$@"; then # Execute command and test success.
    error "Failure while running: $*" # Log detailed failure context.
    return 1 # Return error status (don't exit, continue with other services).
  fi # End command success check.
}

require_root() { # Enforce root execution to manage services.
  if [ "$EUID" -ne 0 ]; then # Compare effective user ID against zero (root).
    error "This script must be run as root." # Display error message.
    exit 1 # Exit immediately without running configuration.
  fi # End privilege check.
}

install_packages() { # Install required service packages.
  section "Installing Service Packages" # Announce package installation stage.
  export DEBIAN_FRONTEND=noninteractive # Suppress interactive apt prompts.
  run_cmd "Updating package cache" apt-get update -qq # Refresh package metadata quietly.
  for package in "${REQUIRED_PACKAGES[@]}"; do # Iterate through required packages.
    if dpkg -l | grep -q "^ii.*$package"; then # Check if package is already installed.
      info "$package is already installed." # Confirm package presence.
    else
      run_cmd "Installing $package" apt-get install -y "$package" # Install package non-interactively.
    fi # End package installation check.
  done # End package iteration.
}

configure_ssh() { # Configure SSH service with vulnerable settings.
  section "Configuring SSH Service" # Announce SSH configuration stage.
  local sshd_config="/etc/ssh/sshd_config" # Define SSH configuration file path.
  # Backup original configuration.
  if [ ! -f "${sshd_config}.backup" ]; then # Check if backup doesn't exist.
    run_cmd "Backing up SSH configuration" cp "$sshd_config" "${sshd_config}.backup" # Create backup.
  fi # End backup check.
  # Enable root login and password authentication (vulnerable settings).
  sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' "$sshd_config" # Enable root login.
  sed -i 's/PermitRootLogin no/PermitRootLogin yes/' "$sshd_config" # Enable root login if set to no.
  sed -i 's/#PasswordAuthentication no/PasswordAuthentication yes/' "$sshd_config" # Enable password authentication.
  sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' "$sshd_config" # Enable password authentication if disabled.
  info "SSH configured: PermitRootLogin=yes, PasswordAuthentication=yes" # Confirm SSH configuration.
  run_cmd "Restarting SSH service" systemctl restart sshd # Restart SSH service to apply changes.
  run_cmd "Enabling SSH service" systemctl enable sshd # Ensure SSH starts on boot.
  # Set weak root password (for testing purposes only).
  warn "Setting weak root password for testing. Change this in production!" # Warn about weak password.
  echo "root:root" | chpasswd # Set root password to "root" (vulnerable).
}

configure_ftp() { # Configure FTP service with vulnerable settings.
  section "Configuring FTP Service" # Announce FTP configuration stage.
  local vsftpd_config="/etc/vsftpd.conf" # Define vsftpd configuration file path.
  if [ -f "$vsftpd_config" ]; then # Check if configuration file exists.
    # Backup original configuration.
    if [ ! -f "${vsftpd_config}.backup" ]; then # Check if backup doesn't exist.
      run_cmd "Backing up FTP configuration" cp "$vsftpd_config" "${vsftpd_config}.backup" # Create backup.
    fi # End backup check.
    # Enable local users and write access (vulnerable settings).
    sed -i 's/#write_enable=YES/write_enable=YES/' "$vsftpd_config" # Enable write access.
    sed -i 's/write_enable=NO/write_enable=YES/' "$vsftpd_config" # Enable write access if disabled.
    sed -i 's/#local_enable=YES/local_enable=YES/' "$vsftpd_config" # Enable local users.
    sed -i 's/local_enable=NO/local_enable=YES/' "$vsftpd_config" # Enable local users if disabled.
    info "FTP configured: write_enable=YES, local_enable=YES" # Confirm FTP configuration.
  else
    warn "FTP configuration file not found. Creating default configuration." # Warn about missing config.
    cat > "$vsftpd_config" <<EOF # Write default FTP configuration.
listen=YES
local_enable=YES
write_enable=YES
anonymous_enable=NO
EOF
  fi # End configuration file check.
  run_cmd "Restarting FTP service" systemctl restart vsftpd # Restart FTP service to apply changes.
  run_cmd "Enabling FTP service" systemctl enable vsftpd # Ensure FTP starts on boot.
}

configure_telnet() { # Configure Telnet service (insecure, for testing).
  section "Configuring Telnet Service" # Announce Telnet configuration stage.
  # Telnet service is typically managed by inetd or xinetd.
  if systemctl list-unit-files | grep -q telnet; then # Check if telnet service exists.
    run_cmd "Enabling Telnet service" systemctl enable telnet # Enable telnet service.
    run_cmd "Starting Telnet service" systemctl start telnet # Start telnet service.
    info "Telnet service enabled and started." # Confirm telnet activation.
  else
    warn "Telnet service not found. Installing telnetd..." # Warn about missing telnet.
    run_cmd "Installing telnetd" apt-get install -y telnetd # Install telnet daemon.
    run_cmd "Starting Telnet service" systemctl start inetd # Start inetd (manages telnet).
    run_cmd "Enabling Telnet service" systemctl enable inetd # Enable inetd service.
  fi # End telnet service check.
}

configure_http() { # Configure HTTP web server.
  section "Configuring HTTP Service" # Announce HTTP configuration stage.
  run_cmd "Starting Apache service" systemctl start apache2 # Start Apache web server.
  run_cmd "Enabling Apache service" systemctl enable apache2 # Ensure Apache starts on boot.
  # Create a simple test page.
  local web_root="/var/www/html" # Define web root directory.
  if [ -d "$web_root" ]; then # Check if web root exists.
    echo "<h1>Vulnerable Web Server</h1><p>This is a test server for penetration testing.</p>" > "${web_root}/index.html" # Create test page.
    info "HTTP service configured. Test page created at ${web_root}/index.html" # Confirm HTTP configuration.
  fi # End web root check.
}

configure_snmp() { # Configure SNMP service with public community string (vulnerable).
  section "Configuring SNMP Service" # Announce SNMP configuration stage.
  local snmpd_config="/etc/snmp/snmpd.conf" # Define SNMP configuration file path.
  if [ -f "$snmpd_config" ]; then # Check if configuration file exists.
    # Backup original configuration.
    if [ ! -f "${snmpd_config}.backup" ]; then # Check if backup doesn't exist.
      run_cmd "Backing up SNMP configuration" cp "$snmpd_config" "${snmpd_config}.backup" # Create backup.
    fi # End backup check.
  else
    mkdir -p /etc/snmp # Create SNMP configuration directory.
  fi # End configuration file check.
  # Configure SNMP with public community string (vulnerable).
  cat > "$snmpd_config" <<EOF # Write SNMP configuration.
rocommunity public
sysLocation "Test Lab"
sysContact "test@example.com"
EOF
  info "SNMP configured with public community string (vulnerable)." # Confirm SNMP configuration.
  run_cmd "Restarting SNMP service" systemctl restart snmpd # Restart SNMP service to apply changes.
  run_cmd "Enabling SNMP service" systemctl enable snmpd # Ensure SNMP starts on boot.
}

verify_services() { # Verify all services are running and listening.
  section "Verifying Services" # Announce service verification stage.
  local services=("sshd:22" "vsftpd:21" "apache2:80" "snmpd:161") # Define services and ports to check.
  for service_port in "${services[@]}"; do # Iterate through services.
    local service=$(echo "$service_port" | cut -d: -f1) # Extract service name.
    local port=$(echo "$service_port" | cut -d: -f2) # Extract port number.
    if systemctl is-active --quiet "$service" 2>/dev/null || netstat -tuln | grep -q ":$port "; then # Check if service is running or port is listening.
      info "$service is running and listening on port $port" # Confirm service status.
    else
      warn "$service may not be running or listening on port $port" # Warn about service status.
    fi # End service status check.
  done # End service iteration.
  # Check telnet separately (may use inetd).
  if netstat -tuln | grep -q ":23 "; then # Check if port 23 is listening.
    info "Telnet is listening on port 23" # Confirm telnet status.
  else
    warn "Telnet may not be listening on port 23" # Warn about telnet status.
  fi # End telnet check.
}

print_summary() { # Print service setup summary.
  section "Service Setup Summary" # Announce summary stage.
  info "Vulnerable services configured:" # List configured services.
  printf "  - SSH (port 22): Root login enabled, weak password\n" # List SSH configuration.
  printf "  - FTP (port 21): Local users enabled, write enabled\n" # List FTP configuration.
  printf "  - Telnet (port 23): Unencrypted remote access\n" # List Telnet configuration.
  printf "  - HTTP (port 80): Apache web server\n" # List HTTP configuration.
  printf "  - SNMP (port 161): Public community string\n" # List SNMP configuration.
  printf "\nHard-ban detection active (firewall):\n" # Inform about firewall behavior.
  printf "  - Repeated NEW connection attempts (>3 in 60s) to 21/22/23 are logged (FTP_HARD_BAN:, SSH_HARD_BAN:, TELNET_HARD_BAN:) and banned for ~60s.\n"
  warn "WARNING: These services are configured with vulnerable settings for testing purposes only!" # Warn about vulnerable settings.
  warn "Do NOT use these settings in production environments!" # Emphasize production warning.
}

# ------------------------- MAIN ------------------------------------
main() { # Primary orchestration function.
  require_root # Verify script is executed as root.
  section "Victim Machine Service Setup" # Print main header.
  install_packages # Install required service packages.
  configure_ssh # Configure SSH service with vulnerable settings.
  configure_ftp # Configure FTP service with vulnerable settings.
  configure_telnet # Configure Telnet service.
  configure_http # Configure HTTP web server.
  configure_snmp # Configure SNMP service with public community.
  verify_services # Verify all services are running.
  print_summary # Print service setup summary.
  section "Service setup completed." # Print completion message.
}

main "$@" # Execute main function with provided CLI arguments.


