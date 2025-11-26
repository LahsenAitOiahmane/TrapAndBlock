# IPTables Firewall Security Lab

## Introduction

This project demonstrates a comprehensive network security lab environment designed to test and validate firewall configurations using Linux iptables. The lab simulates a realistic network topology with an attacker machine (Kali Linux), a victim server (LinuxServer), and a centralized logging infrastructure. The primary goal is to implement a **honeypot/transparent shield** firewall that logs attacks before blocking them, enabling security analysis and verification of attack patterns.

### Key Features

- **Honeypot Security Model**: Firewall configured to log attacks first, then block them
- **Comprehensive Attack Detection**: Detects and logs SYN floods, brute force attempts, port scans, and spoofing attacks
- **Rate Limiting**: Implements connection rate limiting for SSH and other services
- **Centralized Logging**: All security events forwarded to a centralized LogServer
- **Automated Setup Scripts**: Pre-configured scripts for attacker, victim, and firewall setup

---

## Network Architecture & Design

### Network Topology

```
┌─────────────────────────────────────────────────────────────┐
│                    External Network                          │
│                    192.168.100.0/24                          │
│                                                               │
│  ┌──────────────┐              ┌──────────────┐             │
│  │  Cloud/R1    │              │ Kali Attacker│             │
│  │ 192.168.100.1│              │192.168.100.10│             │
│  └──────┬───────┘              └──────────────┘             │
└─────────┼───────────────────────────────────────────────────┘
          │
          │
┌─────────┼───────────────────────────────────────────────────┐
│         │          DMZ / Server Network                      │
│         │          10.10.0.0/24                              │
│         │                                                     │
│  ┌──────▼──────┐                                             │
│  │ Router R2   │                                             │
│  │ 10.10.0.1   │                                             │
│  └──────┬──────┘                                             │
│         │                                                     │
│  ┌──────┼──────┬──────────────┬──────────────┐             │
│  │      │      │              │              │             │
│  │ LinuxServer│  BSDServer   │  LogServer   │             │
│  │ 10.10.0.10 │  10.10.0.20  │  10.10.0.30  │             │
│  │ (Gateway)  │  (Gateway)   │  (Collector) │             │
│  └──────┬──────┘              │              │             │
│         │                     │              │             │
│  ┌──────▼──────┐      ┌───────▼──────┐     │             │
│  │    LAN1     │      │     LAN2     │     │             │
│  │10.10.10.0/24│      │10.10.20.0/24 │     │             │
│  │             │      │              │     │             │
│  │ PC1: .11    │      │ PC3: .11     │     │             │
│  │ PC2: .12    │      │ PC4: .12     │     │             │
│  └─────────────┘      └──────────────┘     │             │
└─────────────────────────────────────────────┘
```

### Network Addressing Plan

#### External Network (192.168.100.0/24)
- **Cloud/Router R1**: 192.168.100.1
- **Kali Attacker**: 192.168.100.10

#### DMZ / Server Network (10.10.0.0/24)
- **Router R2**: 10.10.0.1
- **LinuxServer** (Victim/Gateway): 10.10.0.10
  - Interface 1 (enp0s3): 10.10.0.10/24 (toward R2)
  - Interface 2 (enp0s8): 10.10.10.1/24 (toward LAN1)
- **BSDServer**: 10.10.0.20
- **LogServer**: 10.10.0.30

#### LAN1 (10.10.10.0/24) - Behind LinuxServer
- **Gateway**: LinuxServer (10.10.10.1)
- **PC1**: 10.10.10.11
- **PC2**: 10.10.10.12

#### LAN2 (10.10.20.0/24) - Behind BSDServer
- **Gateway**: BSDServer (10.10.20.1)
- **PC3**: 10.10.20.11
- **PC4**: 10.10.20.12

---

## Required Machines

### 1. Kali Linux (Attacker Machine)
- **OS**: Kali Linux (latest)
- **RAM**: 2GB minimum (4GB recommended)
- **Disk**: 20GB minimum
- **Network**: 1 NIC (NAT or Bridged)
- **IP**: 192.168.100.10/24
- **Purpose**: Penetration testing, attack simulation

### 2. LinuxServer (Victim/Firewall Machine)
- **OS**: Ubuntu Server 20.04/22.04 LTS
- **RAM**: 2GB minimum (4GB recommended)
- **Disk**: 20GB minimum
- **Network**: 2 NICs
  - NIC1 (enp0s3): 10.10.0.10/24 (toward R2)
  - NIC2 (enp0s8): 10.10.10.1/24 (toward LAN1)
- **Purpose**: Firewall gateway, victim server, iptables configuration

### 3. Router R2 (Optional - Can use Linux router)
- **OS**: Cisco IOS or Linux router
- **Network**: 2 NICs
  - NIC1: 192.168.100.1/24 (toward external)
  - NIC2: 10.10.0.1/24 (toward DMZ)
- **Purpose**: Network routing between external and DMZ

### 4. LogServer (Optional but Recommended)
- **OS**: Ubuntu Server
- **RAM**: 1GB minimum
- **Disk**: 10GB minimum
- **Network**: 1 NIC
- **IP**: 10.10.0.30/24
- **Purpose**: Centralized log collection (rsyslog)

### 5. BSDServer (Optional)
- **OS**: FreeBSD or OpenBSD
- **Network**: 2 NICs
  - NIC1: 10.10.0.20/24 (toward DMZ)
  - NIC2: 10.10.20.1/24 (toward LAN2)
- **Purpose**: Alternative gateway for LAN2

### 6. Client Machines (PC1-PC4) - Optional
- **OS**: Any Linux distribution
- **Purpose**: Test internal network connectivity

---

## VMware Implementation Guide

### Step 1: Create Virtual Network Adapters

1. **Open VMware Workstation/Player**
2. **Go to Edit → Virtual Network Editor**
3. **Create Custom Networks**:
   - **VMnet2** (External Network): 192.168.100.0/24, Subnet IP: 192.168.100.0
   - **VMnet3** (DMZ Network): 10.10.0.0/24, Subnet IP: 10.10.0.0
   - **VMnet4** (LAN1): 10.10.10.0/24, Subnet IP: 10.10.10.0

### Step 2: Configure Kali Linux (Attacker)

1. **Create New Virtual Machine**
   - Name: `Kali-Attacker`
   - OS: Linux → Debian 11.x 64-bit
   - RAM: 2048 MB
   - Disk: 20 GB
   - Network: VMnet2 (External Network)

2. **Install Kali Linux**
   - Use Kali Linux ISO image
   - Complete standard installation

3. **Configure Network**
   ```bash
   sudo ip addr add 192.168.100.10/24 dev eth0
   sudo ip link set eth0 up
   sudo ip route add default via 192.168.100.1
   ```

4. **Install Required Tools**
   ```bash
   sudo apt-get update
   sudo apt-get install -y nmap hping3 hydra snmpwalk nikto tcpdump
   ```

### Step 3: Configure LinuxServer (Victim/Firewall)

1. **Create New Virtual Machine**
   - Name: `LinuxServer-Victim`
   - OS: Linux → Ubuntu 64-bit
   - RAM: 2048 MB
   - Disk: 20 GB
   - **Network Adapters**: 2 adapters
     - Adapter 1: VMnet3 (DMZ Network)
     - Adapter 2: VMnet4 (LAN1)

2. **Install Ubuntu Server**
   - Use Ubuntu Server 22.04 LTS ISO
   - Complete standard installation

3. **Configure Network Interfaces**
   ```bash
   # Interface 1 (enp0s3) - DMZ
   sudo ip addr add 10.10.0.10/24 dev enp0s3
   sudo ip link set enp0s3 up
   
   # Interface 2 (enp0s8) - LAN1
   sudo ip addr add 10.10.10.1/24 dev enp0s8
   sudo ip link set enp0s8 up
   
   # Default route
   sudo ip route add default via 10.10.0.1 dev enp0s3
   ```

4. **Run Setup Scripts**
   ```bash
   # Make scripts executable
   chmod +x victim_services_setup.sh AutoTableV2.sh log_viewer.sh
   
   # Setup vulnerable services
   sudo ./victim_services_setup.sh
   
   # Configure firewall (after services are running)
   sudo ./AutoTableV2.sh
   ```

### Step 4: Configure Router R2 (Optional)

If using a Linux router:

1. **Create New Virtual Machine**
   - Name: `Router-R2`
   - OS: Linux → Ubuntu Server
   - RAM: 512 MB
   - Disk: 5 GB
   - **Network Adapters**: 2 adapters
     - Adapter 1: VMnet2 (External Network)
     - Adapter 2: VMnet3 (DMZ Network)

2. **Configure Routing**
   ```bash
   # Enable IP forwarding
   echo 1 > /proc/sys/net/ipv4/ip_forward
   
   # Configure interfaces
   sudo ip addr add 192.168.100.1/24 dev eth0
   sudo ip addr add 10.10.0.1/24 dev eth1
   sudo ip link set eth0 up
   sudo ip link set eth1 up
   
   # Add routes
   sudo ip route add 10.10.10.0/24 via 10.10.0.10
   sudo ip route add 10.10.20.0/24 via 10.10.0.20
   ```

### Step 5: Configure LogServer (Optional)

1. **Create New Virtual Machine**
   - Name: `LogServer`
   - OS: Linux → Ubuntu Server
   - RAM: 1024 MB
   - Disk: 10 GB
   - Network: VMnet3 (DMZ Network)

2. **Configure rsyslog**
   ```bash
   # Install rsyslog
   sudo apt-get update
   sudo apt-get install -y rsyslog
   
   # Configure to receive remote logs
   sudo nano /etc/rsyslog.conf
   # Uncomment:
   # module(load="imudp")
   # input(type="imudp" port="514")
   # module(load="imtcp")
   # input(type="imtcp" port="514")
   
   # Create log directory
   sudo mkdir -p /var/log/remote
   sudo chmod 755 /var/log/remote
   
   # Restart rsyslog
   sudo systemctl restart rsyslog
   ```

---

## Scripts Overview

### 1. `attacker_test.sh` - Attacker Machine Pre-Flight Check

**Purpose**: Verifies attacker machine (Kali Linux) is properly configured before launching attacks.

**Location**: Run on **Kali Attacker** machine (192.168.100.10)

**Features**:
- Checks OS version and compatibility
- Verifies installation of required tools (nmap, hping3, hydra, snmpwalk, nikto, tcpdump)
- Validates network interface configuration
- Checks IP address assignment
- Verifies routing table configuration
- Tests connectivity to target

**Usage**:
```bash
# Make executable
chmod +x attacker_test.sh

# Run as root (some checks require root)
sudo ./attacker_test.sh
```

**Output**: Displays colored status messages indicating:
- ✅ Installed tools and their paths
- ⚠️ Missing tools with installation suggestions
- ✅ Network interface status
- ✅ IP configuration
- ✅ Routing configuration
- ✅ Connectivity test results

---

### 2. `victim_services_setup.sh` - Victim Machine Service Configuration

**Purpose**: Configures vulnerable services on LinuxServer for penetration testing.

**Location**: Run on **LinuxServer** machine (10.10.0.10)

**Features**:
- Installs required service packages (vsftpd, openssh-server, telnetd, apache2, snmpd)
- Configures SSH with vulnerable settings (root login, weak password)
- Configures FTP with write access enabled
- Enables Telnet service (unencrypted)
- Configures Apache HTTP server
- Configures SNMP with public community string
- Verifies all services are running and listening

**Usage**:
```bash
# Make executable
chmod +x victim_services_setup.sh

# Run as root (required for service configuration)
sudo ./victim_services_setup.sh
```

**Services Configured**:
- **SSH (port 22)**: Root login enabled, password: "root"
- **FTP (port 21)**: Local users enabled, write enabled
- **Telnet (port 23)**: Unencrypted remote access
- **HTTP (port 80)**: Apache web server with test page
- **SNMP (port 161)**: Public community string

**⚠️ WARNING**: These are vulnerable configurations for testing only. Do NOT use in production!

---

### 3. `AutoTableV2.sh` - Firewall Configuration Script

**Purpose**: Configures iptables firewall with honeypot/transparent shield security model.

**Location**: Run on **LinuxServer** machine (10.10.0.10)

**Features**:
- Installs required packages (iptables, iptables-persistent, rsyslog, iproute2)
- Configures network interfaces and routing
- Sets up rsyslog remote forwarding to LogServer
- Creates honeypot chains for attack detection and logging
- Implements anti-spoofing rules
- Configures service-specific access rules
- Implements rate limiting for SSH brute force detection
- Configures SYN flood protection
- Enables comprehensive logging of all attacks
- Persists firewall rules across reboots

**Usage**:
```bash
# Make executable
chmod +x AutoTableV2.sh

# Run as root (required for firewall configuration)
sudo ./AutoTableV2.sh
```

**Security Model**:
- **Honeypot Effect**: Attacks are logged first, then blocked
- **Rate Limiting**: SSH connections limited to 3/minute from attacker IP
- **Attack Detection**: Logs SYN floods, brute force, port scans, spoofing
- **Transparent Shield**: Allows initial connections to establish before blocking

**Log Prefixes**:
- `HONEYPOT_ATTACK_INPUT:` - Attack detected on INPUT chain
- `HONEYPOT_ATTACK_FORWARD:` - Attack detected on FORWARD chain
- `SYN_FLOOD_DROP:` - SYN flood attack detected
- `IPTABLES_INPUT_DROP:` - General dropped packets on INPUT
- `IPTABLES_FORWARD_DROP:` - General dropped packets on FORWARD

---

### 4. `log_viewer.sh` - Interactive Log Viewer

**Purpose**: Presents firewall and system logs in a readable, organized format.

**Location**: Run on **LinuxServer** machine (10.10.0.10)

**Features**:
- Interactive menu-driven interface
- Parses honeypot attack logs
- Displays SYN flood detection logs
- Shows dropped packet summaries
- Displays SSH connection attempts
- Provides attack statistics
- Real-time log monitoring
- Color-coded output for easy reading

**Usage**:
```bash
# Make executable
chmod +x log_viewer.sh

# Interactive mode (menu-driven)
sudo ./log_viewer.sh

# Command-line mode
sudo ./log_viewer.sh honeypot    # View honeypot attacks
sudo ./log_viewer.sh synflood    # View SYN flood attacks
sudo ./log_viewer.sh dropped     # View dropped packets
sudo ./log_viewer.sh ssh         # View SSH attempts
sudo ./log_viewer.sh stats       # Show statistics
sudo ./log_viewer.sh all         # View all logs
```

**Menu Options**:
1. View Honeypot Attack Logs
2. View SYN Flood Logs
3. View Dropped Packets
4. View SSH Connection Attempts
5. Show Attack Statistics
6. Real-time Log Monitoring
7. View All Logs
8. Exit

---

## Step-by-Step Lab Setup

### Phase 1: Initial Setup

1. **Create Virtual Machines** (as described in VMware section)
2. **Configure Network Adapters** in VMware
3. **Install Operating Systems** on all VMs
4. **Configure Basic Networking** (IP addresses, routes)

### Phase 2: Attacker Machine Setup

1. **Run Pre-Flight Check**:
   ```bash
   cd /path/to/scripts
   chmod +x attacker_test.sh
   sudo ./attacker_test.sh
   ```

2. **Install Missing Tools** (if any):
   ```bash
   sudo apt-get update
   sudo apt-get install -y nmap hping3 hydra snmpwalk nikto tcpdump
   ```

3. **Verify Connectivity**:
   ```bash
   ping 192.168.100.1    # Router
   ping 10.10.0.10       # Target (may be blocked by firewall)
   ```

### Phase 3: Victim Machine Setup

1. **Setup Vulnerable Services**:
   ```bash
   cd /path/to/scripts
   chmod +x victim_services_setup.sh
   sudo ./victim_services_setup.sh
   ```

2. **Verify Services Are Running**:
   ```bash
   sudo netstat -tuln | grep -E ':(21|22|23|80|161) '
   ```

3. **Test Services** (from attacker):
   ```bash
   # From Kali machine
   nmap -sS 10.10.0.10    # Port scan
   ```

### Phase 4: Firewall Configuration

1. **Configure Firewall**:
   ```bash
   cd /path/to/scripts
   chmod +x AutoTableV2.sh
   sudo ./AutoTableV2.sh
   ```

2. **Verify Firewall Rules**:
   ```bash
   sudo iptables -L -v -n    # List rules
   sudo iptables -L -v -n -t filter | grep HONEYPOT    # Check honeypot chains
   ```

3. **Monitor Logs**:
   ```bash
   sudo ./log_viewer.sh
   ```

### Phase 5: Attack Simulation

1. **Reconnaissance** (from attacker):
   ```bash
   # Port scan
   nmap -sS 10.10.0.10
   
   # Service enumeration
   nmap -sV -sC 10.10.0.10
   ```

2. **Brute Force Attack** (from attacker):
   ```bash
   # SSH brute force
   hydra -l root -P /usr/share/wordlists/rockyou.txt 10.10.0.10 ssh
   ```

3. **DoS Attack** (from attacker):
   ```bash
   # SYN flood
   hping3 -S --flood -p 80 10.10.0.10
   ```

4. **Monitor Firewall Response** (on victim):
   ```bash
   sudo ./log_viewer.sh
   # Select option 6 for real-time monitoring
   ```

---

## Troubleshooting

### Issue: Cannot ping target from attacker

**Solution**:
- Verify network configuration on both machines
- Check if firewall is blocking ICMP (expected behavior)
- Verify routing table: `ip route show`

### Issue: Services not starting

**Solution**:
- Check service status: `sudo systemctl status <service>`
- Review service logs: `sudo journalctl -u <service>`
- Verify ports are not in use: `sudo netstat -tuln`

### Issue: Firewall rules not persisting after reboot

**Solution**:
- Verify netfilter-persistent is enabled: `sudo systemctl status netfilter-persistent`
- Manually save rules: `sudo netfilter-persistent save`
- Check rules file: `sudo cat /etc/iptables/rules.v4`

### Issue: Logs not appearing in log_viewer

**Solution**:
- Verify rsyslog is running: `sudo systemctl status rsyslog`
- Check kernel log: `sudo tail -f /var/log/kern.log`
- Verify iptables logging is enabled in firewall script

---

## Security Considerations

### ⚠️ Important Warnings

1. **Vulnerable Configurations**: This lab uses intentionally vulnerable service configurations for educational purposes only. **DO NOT** deploy these settings in production environments.

2. **Weak Passwords**: Services are configured with weak passwords (e.g., root:root). Change all passwords in production.

3. **Open Services**: Multiple services are exposed without proper hardening. In production, follow security best practices.

4. **Network Isolation**: This lab should be run in an isolated network environment. Do not connect to production networks.

5. **Legal Compliance**: Only use these scripts in authorized testing environments. Unauthorized access to computer systems is illegal.

---

## Additional Resources

- **iptables Documentation**: https://www.netfilter.org/documentation/
- **Kali Linux Tools**: https://www.kali.org/tools/
- **rsyslog Documentation**: https://www.rsyslog.com/doc/
- **VMware Networking**: https://docs.vmware.com/en/VMware-Workstation-Pro/



