Key VPN Protection Features:
Automatic VPN Detection

Identifies VPN interfaces by name/description

Detects running VPN processes

Monitors active VPN connections

Checks VPN routing tables

Intelligent Interface Filtering

Skips TAP/TUN interfaces

Avoids OpenVPN/WireGuard adapters

Protects corporate VPN connections

Preserves tunnel interfaces

Non-Disruptive Operations

Staggered MAC changes to avoid network storms

Preserves active VPN sessions

Maintains internet connectivity

No VPN process termination

Supported VPN Clients:
OpenVPN, WireGuard, ZeroTier

NordVPN, ExpressVPN, ProtonVPN

Windows Built-in VPN

Corporate VPN solutions

Hamachi, SoftEther VPN

Windows-Specific Optimizations:
Registry-based MAC changes for persistence

PowerShell integration for system management

Windows event log cleaning (admin required)

Browser cache elimination for all major browsers

Sound notifications for operation status


# Comprehensive stealth with VPN protection (RECOMMENDED)
python windows_stealth_guardian.py --full

# Quick stealth mode (preserves VPN)
python windows_stealth_guardian.py --quick

# Check VPN protection status
python windows_stealth_guardian.py --vpn-status

# MAC rotation only (skips VPN interfaces)
python windows_stealth_guardian.py --mac-only --vendor dell

# Run as Administrator for full functionality
Right-click Command Prompt -> "Run as administrator"
cd to_script_directory
python windows_stealth_guardian.py --full
