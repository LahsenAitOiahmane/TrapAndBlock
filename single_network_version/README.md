# IPTables Firewall Security Lab - Single Network Version

## Introduction

This is a **simplified version** of the IPTables firewall security lab designed for easier setup and testing. In this version, the attacker machine (Kali Linux) and the victim/firewall machine (LinuxServer) are on the **same network segment** (192.168.100.0/24), eliminating the need for complex routing and multiple network interfaces.

### Key Differences from Full Version

- **Single Network**: Both attacker and victim on 192.168.100.0/24
- **No Routing Required**: Direct network communication
- **Single Interface**: Victim machine needs only one network interface
- **Simplified Setup**: Easier VMware configuration
- **Same Security Features**: Honeypot detection, rate limiting, attack logging

---

## Network Architecture

### Simplified Topology

```
┌─────────────────────────────────────────────┐
│         Single Network Segment              │
│           192.168.100.0/24                   │
│                                             │
│  ┌──────────────┐      ┌──────────────┐   │
│  │ Kali Attacker│      │ LinuxServer  │   │
│  │192.168.100.10│◄────►│192.168.100.20│   │
│  └──────────────┘      └──────────────┘   │
│                                             │
│  ┌──────────────┐                          │
│  │  Gateway     │                          │
│  │192.168.100.1 │ (Optional, for Internet) │
│  └──────────────┘                          │
└─────────────────────────────────────────────┘
```

### Network Addressing

- **Network**: 192.168.100.0/24
- **Kali Attacker**: 192.168.100.10/24
- **LinuxServer (Victim)**: 192.168.100.20/24
- **Gateway** (optional): 192.168.100.1/24

---

## Required Machines

### 1. Kali Linux (Attacker Machine)
- **OS**: Kali Linux (latest)
- **RAM**: 2GB minimum
- **Disk**: 20GB minimum
- **Network**: 1 NIC
- **IP**: 192.168.100.10/24
- **Purpose**: Penetration testing, attack simulation

### 2. LinuxServer (Victim/Firewall Machine)
- **OS**: Ubuntu Server 20.04/22.04 LTS
- **RAM**: 2GB minimum
- **Disk**: 20GB minimum
- **Network**: 1 NIC (simplified!)
- **IP**: 192.168.100.20/24
- **Purpose**: Firewall gateway, victim server, iptables configuration

---

## VMware Implementation Guide

### Step 1: Create Virtual Network

1. **Open VMware Workstation/Player**
2. **Go to Edit → Virtual Network Editor**
3. **Create Custom Network**:
   - **VMnet2**: 192.168.100.0/24, Subnet IP: 192.168.100.0
   - Enable "Connect a host virtual adapter to this network" (optional, for host access)

### Step 2: Configure Kali Linux (Attacker)

1. **Create New Virtual Machine**
   - Name: `Kali-Attacker-Single`
   - OS: Linux → Debian 11.x 64-bit
   - RAM: 2048 MB
   - Disk: 20 GB
   - Network: VMnet2 (Custom Network)

2. **Install Kali Linux**
   - Use Kali Linux ISO image
   - Complete standard installation

3. **Configure Network**
   ```bash
   sudo ip addr add 192.168.100.10/24 dev eth0
   sudo ip link set eth0 up
   # Optional: Add default gateway for Internet access
   # sudo ip route add default via 192.168.100.1
   ```

4. **Install Required Tools**
   ```bash
   sudo apt-get update
   sudo apt-get install -y nmap hping3 hydra snmpwalk nikto tcpdump
   ```

5. **Run Pre-Flight Check**
   ```bash
   cd /path/to/single_network_version
   chmod +x attacker_test_single.sh
   sudo ./attacker_test_single.sh
   ```

### Step 3: Configure LinuxServer (Victim/Firewall)

1. **Create New Virtual Machine**
   - Name: `LinuxServer-Victim-Single`
   - OS: Linux → Ubuntu 64-bit
   - RAM: 2048 MB
   - Disk: 20 GB
   - **Network**: VMnet2 (Custom Network) - **Only 1 adapter needed!**

2. **Install Ubuntu Server**
   - Use Ubuntu Server 22.04 LTS ISO
   - Complete standard installation

3. **Configure Network Interface**
   ```bash
   # Single interface configuration
   sudo ip addr add 192.168.100.20/24 dev eth0
   sudo ip link set eth0 up
   # Optional: Add default gateway for Internet access
   # sudo ip route add default via 192.168.100.1
   ```

4. **Run Setup Scripts**
   ```bash
   # Make scripts executable
   chmod +x victim_services_setup.sh AutoTableV2_single.sh log_viewer.sh
   
   # Setup vulnerable services
   sudo ./victim_services_setup.sh
   
   # Configure firewall (after services are running)
   sudo ./AutoTableV2_single.sh
   ```

---

## Scripts Overview

### 1. `attacker_test_single.sh` - Attacker Machine Pre-Flight Check

**Purpose**: Verifies attacker machine (Kali Linux) is properly configured.

**Location**: Run on **Kali Attacker** machine (192.168.100.10)

**Usage**:
```bash
chmod +x attacker_test_single.sh
sudo ./attacker_test_single.sh
```

**Features**:
- Checks OS version
- Verifies required tools installation
- Validates network interface
- Checks IP configuration (192.168.100.10)
- Tests connectivity to target (192.168.100.20)

---

### 2. `victim_services_setup.sh` - Victim Machine Service Configuration

**Purpose**: Configures vulnerable services on LinuxServer for penetration testing.

**Location**: Run on **LinuxServer** machine (192.168.100.20)

**Usage**:
```bash
chmod +x victim_services_setup.sh
sudo ./victim_services_setup.sh
```

**Services Configured**:
- **SSH (port 22)**: Root login enabled, password: "root"
- **FTP (port 21)**: Local users enabled, write enabled
- **Telnet (port 23)**: Unencrypted remote access
- **HTTP (port 80)**: Apache web server
- **SNMP (port 161)**: Public community string

**⚠️ WARNING**: Vulnerable configurations for testing only!

---

### 3. `AutoTableV2_single.sh` - Firewall Configuration Script

**Purpose**: Configures iptables firewall with honeypot/transparent shield security model.

**Location**: Run on **LinuxServer** machine (192.168.100.20)

**Usage**:
```bash
chmod +x AutoTableV2_single.sh
sudo ./AutoTableV2_single.sh
```

**Key Features**:
- **Single Interface**: Configured for eth0 (or enp0s3)
- **Honeypot Effect**: Attacks logged first, then blocked
- **Rate Limiting**: SSH connections limited to 3/minute from attacker IP
- **Attack Detection**: Logs SYN floods, brute force, port scans
- **No Forwarding**: Simplified rules (INPUT chain only)

**Network Configuration**:
- Interface: `eth0` (change to `enp0s3` if needed)
- IP: 192.168.100.20/24
- Attacker IP: 192.168.100.10

**To change interface name**, edit line 10 in the script:
```bash
readonly NET_IF="eth0"  # Change to "enp0s3" if needed
```

---

### 4. `log_viewer.sh` - Interactive Log Viewer

**Purpose**: Presents firewall and system logs in a readable format.

**Location**: Run on **LinuxServer** machine (192.168.100.20)

**Usage**:
```bash
chmod +x log_viewer.sh
sudo ./log_viewer.sh
```

**Features**:
- Interactive menu-driven interface
- Parses honeypot attack logs
- Displays SYN flood detection
- Shows dropped packet summaries
- Displays SSH connection attempts
- Real-time log monitoring

---

## Step-by-Step Lab Setup

### Phase 1: Initial Setup

1. **Create Virtual Machines** in VMware
2. **Configure Network Adapter** to VMnet2 (192.168.100.0/24)
3. **Install Operating Systems** (Kali Linux and Ubuntu Server)
4. **Configure Basic Networking** (IP addresses)

### Phase 2: Attacker Machine Setup

1. **Run Pre-Flight Check**:
   ```bash
   cd /path/to/single_network_version
   chmod +x attacker_test_single.sh
   sudo ./attacker_test_single.sh
   ```

2. **Install Missing Tools** (if any):
   ```bash
   sudo apt-get update
   sudo apt-get install -y nmap hping3 hydra snmpwalk nikto tcpdump
   ```

3. **Verify Connectivity**:
   ```bash
   ping 192.168.100.20  # Target (may be blocked by firewall)
   ```

### Phase 3: Victim Machine Setup

1. **Setup Vulnerable Services**:
   ```bash
   cd /path/to/single_network_version
   chmod +x victim_services_setup.sh
   sudo ./victim_services_setup.sh
   ```

2. **Verify Services Are Running**:
   ```bash
   sudo netstat -tuln | grep -E ':(21|22|23|80|161) '
   ```

3. **Configure Firewall**:
   ```bash
   chmod +x AutoTableV2_single.sh
   sudo ./AutoTableV2_single.sh
   ```

4. **Verify Firewall Rules**:
   ```bash
   sudo iptables -L -v -n
   sudo iptables -L -v -n | grep HONEYPOT
   ```

### Phase 4: Attack Simulation

1. **Reconnaissance** (from attacker):
   ```bash
   # Port scan
   nmap -sS 192.168.100.20
   
   # Service enumeration
   nmap -sV -sC 192.168.100.20
   ```

2. **Brute Force Attack** (from attacker):
   ```bash
   # SSH brute force
   hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.100.20 ssh
   ```

3. **DoS Attack** (from attacker):
   ```bash
   # SYN flood
   hping3 -S --flood -p 80 192.168.100.20
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
- Verify both machines are on VMnet2
- Check IP addresses: `ip addr show`
- Verify firewall allows ICMP (may be blocked intentionally)

### Issue: Interface name mismatch (eth0 vs enp0s3)

**Solution**:
- Check interface name: `ip link show`
- Edit `AutoTableV2_single.sh` line 10:
  ```bash
  readonly NET_IF="enp0s3"  # Change from eth0 if needed
  ```

### Issue: Services not starting

**Solution**:
- Check service status: `sudo systemctl status <service>`
- Review logs: `sudo journalctl -u <service>`
- Verify ports: `sudo netstat -tuln`

### Issue: Firewall rules not persisting

**Solution**:
- Verify netfilter-persistent: `sudo systemctl status netfilter-persistent`
- Manually save: `sudo netfilter-persistent save`
- Check rules file: `sudo cat /etc/iptables/rules.v4`

---

## Comparison: Single Network vs Full Version

| Feature | Single Network | Full Version |
|---------|---------------|--------------|
| Network Interfaces | 1 per machine | 2+ per machine |
| Network Segments | 1 (192.168.100.0/24) | 4+ segments |
| Routing Required | No | Yes |
| VMware Setup | Simple | Complex |
| Forwarding Rules | Not needed | Required |
| Use Case | Learning, testing | Advanced labs |

---

## Security Considerations

### ⚠️ Important Warnings

1. **Vulnerable Configurations**: This lab uses intentionally vulnerable service configurations for educational purposes only. **DO NOT** deploy these settings in production.

2. **Weak Passwords**: Services configured with weak passwords (e.g., root:root). Change all passwords in production.

3. **Network Isolation**: Run in an isolated network environment. Do not connect to production networks.

4. **Legal Compliance**: Only use in authorized testing environments. Unauthorized access is illegal.

---

## Additional Resources

- **iptables Documentation**: https://www.netfilter.org/documentation/
- **Kali Linux Tools**: https://www.kali.org/tools/
- **VMware Networking**: https://docs.vmware.com/en/VMware-Workstation-Pro/
