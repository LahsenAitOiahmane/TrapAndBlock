# Cleanup Scripts - System Restoration

## Hard-Ban Cleanup

- Clears iptables `recent` lists used by unified hard ban:
  - `/proc/net/xt_recent/ABUSE_COUNT`
  - `/proc/net/xt_recent/ABUSE_BANNED`
- Use `cleanup_iptables.sh` to flush chains and clear recent lists
- Use `cleanup_all.sh` to perform full reset (iptables + services)

## Overview

This folder contains scripts to completely reset and clean up the penetration testing lab environment. These scripts restore the system to a default state, as if it were freshly installed, by removing all iptables firewall rules and stopping/disabling all vulnerable services.

## ⚠️ Important Warnings

- **These scripts will remove ALL firewall protection** - System will be completely unprotected
- **All vulnerable services will be stopped** - Services will not start on boot
- **Service configurations will be restored** - Vulnerable settings will be removed
- **Backups are created automatically** - Original configurations are saved before changes

## Scripts

### 1. `cleanup_iptables.sh` - Firewall Reset

**Purpose**: Completely removes all iptables rules and restores firewall to default state.

**What it does**:

- Backs up current iptables rules to `/tmp/iptables_backup_*.rules`
- Flushes all rules from all tables (filter, nat, mangle, raw, security)
- Deletes all custom chains
- Resets default policies to ACCEPT (default Linux behavior)
- Removes persistent rules files (`/etc/iptables/rules.v4` and `rules.v6`)
- Disables netfilter-persistent service
- Verifies cleanup was successful

**Usage**:

```bash
chmod +x cleanup_iptables.sh
sudo ./cleanup_iptables.sh
```

**Result**:

- Firewall in default state (all traffic allowed)
- No firewall rules active
- Rules will NOT persist after reboot

---

### 2. `cleanup_services.sh` - Services Reset

**Purpose**: Stops and disables all vulnerable services configured for penetration testing.

**What it does**:

- Stops all vulnerable services (SSH, FTP, Telnet, HTTP, SNMP)
- Disables services from starting on boot
- Restores service configurations to secure defaults:
  - **SSH**: Restores from backup or sets `PermitRootLogin prohibit-password`, disables password auth
  - **FTP**: Restores from backup or disables write access and local users
  - **SNMP**: Restores from backup or removes public community string
- Verifies all services are stopped
- Checks if vulnerable ports are still listening

**Services affected**:

- `sshd` (SSH - port 22)
- `vsftpd` (FTP - port 21)
- `telnet` / `inetd` / `xinetd` (Telnet - port 23)
- `apache2` (HTTP - port 80)
- `snmpd` (SNMP - port 161)

**Usage**:

```bash
chmod +x cleanup_services.sh
sudo ./cleanup_services.sh
```

**Result**:

- All vulnerable services stopped
- Services disabled from boot
- Configurations restored to secure defaults

---

### 3. `cleanup_all.sh` - Master Cleanup Script

**Purpose**: Runs both iptables and services cleanup scripts in sequence.

**What it does**:

- Verifies both cleanup scripts exist and are executable
- Runs `cleanup_iptables.sh` first
- Runs `cleanup_services.sh` second
- Provides comprehensive summary of all cleanup actions

**Usage**:

```bash
chmod +x cleanup_all.sh
sudo ./cleanup_all.sh
```

**Result**:

- Complete system reset to default state
- Firewall and services both cleaned
- System ready for fresh configuration

---

## When to Use

### Use `cleanup_iptables.sh` when

- You want to remove all firewall rules
- Testing different firewall configurations
- Resetting firewall to default state
- Troubleshooting firewall issues

### Use `cleanup_services.sh` when

- You want to stop all vulnerable services
- Removing penetration testing setup
- Restoring services to secure defaults
- Preparing system for production use

### Use `cleanup_all.sh` when

- You want complete system reset
- Starting fresh with lab setup
- Removing all penetration testing configurations
- Preparing system for reconfiguration

---

## Backup Files

All cleanup scripts create backups before making changes:

### iptables Backups

- Location: `/tmp/iptables_backup_YYYYMMDD_HHMMSS.rules`
- Contains: All iptables rules before cleanup
- Restore: `sudo iptables-restore < /tmp/iptables_backup_*.rules`

### Service Configuration Backups

- SSH: `/etc/ssh/sshd_config.backup`
- FTP: `/etc/vsftpd.conf.backup`
- SNMP: `/etc/snmp/snmpd.conf.backup`
- Restore: Copy backup file back to original location

---

## Verification

After running cleanup scripts, verify the cleanup:

### Verify iptables

```bash
```bash
# Check if any rules exist
sudo iptables -L -n -v

# Check default policies
sudo iptables -P INPUT
sudo iptables -P FORWARD
sudo iptables -P OUTPUT

# Should show: ACCEPT for all policies
```

### Verify services

```bash
```bash
# Check service status
sudo systemctl status sshd
sudo systemctl status vsftpd
sudo systemctl status apache2
sudo systemctl status snmpd

# Check listening ports
sudo netstat -tuln | grep -E ':(21|22|23|80|161) '
# Should show: No output (ports not listening)
```

---

## Restoring from Backups

### Restore iptables rules

```bash
```bash
# Find backup file
ls -la /tmp/iptables_backup_*.rules

# Restore rules
sudo iptables-restore < /tmp/iptables_backup_YYYYMMDD_HHMMSS.rules

# Save restored rules
sudo netfilter-persistent save
```

### Restore service configurations

```bash
```bash
# SSH
sudo cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
sudo systemctl restart sshd

# FTP
sudo cp /etc/vsftpd.conf.backup /etc/vsftpd.conf
sudo systemctl restart vsftpd

# SNMP
sudo cp /etc/snmp/snmpd.conf.backup /etc/snmp/snmpd.conf
sudo systemctl restart snmpd
```

---

## Examples

### Example 1: Reset firewall only

```bash
cd cleanup
sudo ./cleanup_iptables.sh
```

### Example 2: Stop all vulnerable services

```bash
cd cleanup
sudo ./cleanup_services.sh
```

### Example 3: Complete system reset

```bash
cd cleanup
sudo ./cleanup_all.sh
```

### Example 4: Cleanup and verify

```bash
cd cleanup
sudo ./cleanup_all.sh

# Verify firewall
sudo iptables -L -n

# Verify services
sudo systemctl list-units --type=service --state=running | grep -E 'ssh|ftp|apache|snmp'
```

---

## Troubleshooting

### Issue: Script fails with "permission denied"

**Solution**: Run with sudo:

```bash
sudo ./cleanup_iptables.sh
```

### Issue: Services still running after cleanup

**Solution**: Force stop services:

```bash
sudo systemctl stop sshd vsftpd apache2 snmpd
sudo systemctl kill sshd vsftpd apache2 snmpd
```

### Issue: Ports still listening

**Solution**: Check what's using the ports:

```bash
sudo lsof -i :22  # SSH
sudo lsof -i :21  # FTP
sudo lsof -i :80  # HTTP
```

### Issue: Can't restore from backup

**Solution**: Check backup file exists and has content:

```bash
ls -la /tmp/iptables_backup_*.rules
cat /tmp/iptables_backup_*.rules | head -20
```

---

## Safety Features

1. **Automatic Backups**: All scripts create backups before making changes
2. **Verification Steps**: Scripts verify cleanup was successful
3. **Error Handling**: Scripts continue even if individual steps fail
4. **Detailed Logging**: All actions are logged for review

---

## Notes

- These scripts work for **both single network and full version** setups
- Scripts are idempotent (safe to run multiple times)
- Backups are timestamped to prevent overwriting
- All changes are reversible using backup files

