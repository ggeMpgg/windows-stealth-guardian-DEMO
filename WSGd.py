import os
import sys
import random
import subprocess
import platform
import time
import re
import hashlib
import tempfile
import shutil
from datetime import datetime, timedelta
import json
import socket
import struct
import ctypes
from ctypes import wintypes
import winreg
import psutil
import logging
from pathlib import Path
import winsound

# Windows API imports
import win32api
import win32con
import win32security
import pywintypes

# === WINDOWS CONFIGURATION ===
class WindowsConfig:
    """Windows-specific footprint elimination configuration"""
    
    # VPN interface identifiers - these will be protected from modification
    VPN_IDENTIFIERS = [
        'tap', 'tun', 'openvpn', 'wireguard', 'nordvpn', 'expressvpn',
        'proton', 'windscribe', 'hidemyass', 'private', 'vpn', 'zerotier',
        'hamachi', 'softether', 'openvpn', 'utun', 'cloudflare'
    ]
    
    # Windows network interface types to avoid
    PROTECTED_INTERFACE_TYPES = [
        'tunnel', 'loopback', 'ppp', 'ipsec', 'l2tp'
    ]
    
    # MAC Vendor pools for Windows compatibility
    VENDOR_POOLS = {
        'microsoft': ['00:15:5D', '00:03:FF', '00:0D:3A'],
        'dell': ['00:14:22', '00:18:8B', '00:1C:23'],
        'hp': ['00:30:93', '00:1F:29', '00:25:B3'],
        'lenovo': ['00:27:0E', '00:21:5C', '00:1C:25'],
        'intel': ['00:02:B3', '00:11:11', '00:1B:21'],
        'realtek': ['00:13:20', '00:1C:25', '00:1D:72'],
        'broadcom': ['00:05:B5', '00:10:18', '00:1A:A0'],
        'random': ['02', '0A', '12', '1A', '2A']
    }
    
    # Windows artifact paths
    ARTIFACT_PATHS = [
        '%TEMP%', '%TMP%', '%USERPROFILE%\\AppData\\Local\\Temp',
        'C:\\Windows\\Temp', 'C:\\Windows\\Prefetch',
        '%USERPROFILE%\\Recent', '%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\History',
        '%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files',
        '%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache',
        '%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache',
        '%USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default-release\\cache2',
        '%USERPROFILE%\\AppData\\Local\\Discord\\Cache',
        '%USERPROFILE%\\AppData\\Local\\Spotify\\Browser\\Cache'
    ]
    
    # Browser history databases
    BROWSER_HISTORY_PATHS = [
        '%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History',
        '%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History',
        '%USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default-release\\places.sqlite',
        '%USERPROFILE%\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History'
    ]

class WindowsVPNProtector:
    """Advanced VPN Connection Detection and Protection"""
    
    def __init__(self):
        self.vpn_interfaces = []
        self.vpn_processes = []
        self.vpn_services = []
        self.detected_vpn_state = {}
        
    def detect_vpn_interfaces(self):
        """Detect and identify VPN network interfaces"""
        vpn_interfaces = []
        try:
            # Get all network interfaces
            interfaces = psutil.net_if_addrs()
            
            for interface_name, addresses in interfaces.items():
                interface_lower = interface_name.lower()
                
                # Check for VPN identifiers in interface name
                is_vpn = any(vpn_id in interface_lower for vpn_id in WindowsConfig.VPN_IDENTIFIERS)
                
                # Check interface description
                interface_stats = psutil.net_if_stats()
                if interface_name in interface_stats:
                    desc_lower = str(interface_stats[interface_name].description).lower()
                    is_vpn = is_vpn or any(vpn_id in desc_lower for vpn_id in WindowsConfig.VPN_IDENTIFIERS)
                
                if is_vpn:
                    vpn_interfaces.append(interface_name)
                    logging.info(f"Detected VPN interface: {interface_name}")
            
            self.vpn_interfaces = vpn_interfaces
            return vpn_interfaces
            
        except Exception as e:
            logging.error(f"VPN interface detection failed: {e}")
            return []
    
    def detect_vpn_processes(self):
        """Detect running VPN processes"""
        vpn_processes = []
        vpn_process_names = [
            'openvpn', 'wireguard', 'nordvpn', 'expressvpn', 'protonvpn',
            'windscribe', 'hotspot', 'pia', 'hidemyass', 'vpn', 'zerotier',
            'hamachi', 'softether', 'cloudflare'
        ]
        
        try:
            for process in psutil.process_iter(['name']):
                process_name = process.info['name'].lower()
                if any(vpn_name in process_name for vpn_name in vpn_process_names):
                    vpn_processes.append(process.info['name'])
                    logging.info(f"Detected VPN process: {process.info['name']}")
            
            self.vpn_processes = vpn_processes
            return vpn_processes
            
        except Exception as e:
            logging.error(f"VPN process detection failed: {e}")
            return []
    
    def check_vpn_connection_status(self):
        """Check if VPN is actively connected"""
        try:
            # Method 1: Check for VPN processes
            vpn_processes = self.detect_vpn_processes()
            
            # Method 2: Check for established VPN tunnels
            connections = psutil.net_connections()
            vpn_ports = [1194, 51820, 500, 4500, 1701, 1723]  # Common VPN ports
            
            vpn_connections = []
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.port in vpn_ports or any(vpn_id in str(conn.raddr).lower() for vpn_id in WindowsConfig.VPN_IDENTIFIERS):
                        vpn_connections.append(conn)
            
            # Method 3: Check routing table for VPN routes
            result = subprocess.run(['route', 'print'], capture_output=True, text=True)
            vpn_routes = []
            for line in result.stdout.split('\n'):
                if any(vpn_id in line.lower() for vpn_id in WindowsConfig.VPN_IDENTIFIERS):
                    vpn_routes.append(line.strip())
            
            vpn_active = len(vpn_processes) > 0 or len(vpn_connections) > 0 or len(vpn_routes) > 0
            
            self.detected_vpn_state = {
                'processes': vpn_processes,
                'connections': len(vpn_connections),
                'routes': len(vpn_routes),
                'active': vpn_active
            }
            
            logging.info(f"VPN Status - Active: {vpn_active}, Processes: {len(vpn_processes)}, Connections: {len(vpn_connections)}")
            return vpn_active
            
        except Exception as e:
            logging.error(f"VPN connection check failed: {e}")
            return False
    
    def protect_vpn_interfaces(self, interfaces):
        """Filter out VPN interfaces from modification list"""
        safe_interfaces = []
        vpn_interfaces = self.detect_vpn_interfaces()
        
        for interface in interfaces:
            interface_lower = interface.lower()
            is_vpn = any(vpn_interface.lower() in interface_lower for vpn_interface in vpn_interfaces)
            is_protected_type = any(ptype in interface_lower for ptype in WindowsConfig.PROTECTED_INTERFACE_TYPES)
            
            if not is_vpn and not is_protected_type:
                safe_interfaces.append(interface)
            else:
                logging.info(f"Protected VPN/System interface from modification: {interface}")
        
        return safe_interfaces
    
    def get_vpn_protection_status(self):
        """Get comprehensive VPN protection status"""
        return {
            'vpn_interfaces': self.vpn_interfaces,
            'vpn_processes': self.vpn_processes,
            'vpn_services': self.vpn_services,
            'connection_status': self.detected_vpn_state
        }

class WindowsMACManager:
    """Windows-optimized MAC address management with VPN protection"""
    
    def __init__(self):
        self.vpn_protector = WindowsVPNProtector()
        self.original_macs = {}
        self.network_adapters = {}
        
    def _run_powershell(self, command):
        """Execute PowerShell command and return result"""
        try:
            result = subprocess.run([
                'powershell', '-Command', command
            ], capture_output=True, text=True, timeout=30)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timeout", 1
        except Exception as e:
            return "", str(e), 1
    
    def detect_network_adapters(self):
        """Detect all network adapters with detailed information"""
        adapters = {}
        
        try:
            # PowerShell command to get network adapter details
            ps_command = """
            Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -or $_.Status -eq 'Disconnected'} | 
            Select-Object Name, InterfaceDescription, MacAddress, Status, InterfaceIndex, 
            @{Name='AdapterType';Expression={$_.InterfaceDescription.Split('#')[0].Trim()}} |
            ConvertTo-Json
            """
            
            output, error, code = self._run_powershell(ps_command)
            
            if code == 0 and output:
                adapter_list = json.loads(output) if output.startswith('[') else [json.loads(output)]
                
                for adapter in adapter_list:
                    adapter_name = adapter.get('Name', '')
                    if adapter_name:
                        adapters[adapter_name] = {
                            'description': adapter.get('InterfaceDescription', ''),
                            'mac': adapter.get('MacAddress', ''),
                            'status': adapter.get('Status', ''),
                            'index': adapter.get('InterfaceIndex', ''),
                            'type': adapter.get('AdapterType', '')
                        }
                        logging.info(f"Detected adapter: {adapter_name} - MAC: {adapter.get('MacAddress', 'Unknown')}")
            
            self.network_adapters = adapters
            return adapters
            
        except Exception as e:
            logging.error(f"Network adapter detection failed: {e}")
            return {}
    
    def get_safe_adapters(self):
        """Get adapters safe for MAC modification (excluding VPN interfaces)"""
        all_adapters = self.detect_network_adapters()
        safe_adapters = self.vpn_protector.protect_vpn_interfaces(list(all_adapters.keys()))
        
        logging.info(f"Safe adapters for MAC modification: {safe_adapters}")
        return {name: all_adapters[name] for name in safe_adapters if name in all_adapters}
    
    def _generate_windows_mac(self, vendor=None):
        """Generate Windows-compatible MAC address"""
        if vendor and vendor in WindowsConfig.VENDOR_POOLS:
            prefix = random.choice(WindowsConfig.VENDOR_POOLS[vendor])
        else:
            prefix = random.choice(WindowsConfig.VENDOR_POOLS['random'])
            
        # Generate remaining octets
        mac = prefix
        octets_needed = 6 - len(prefix.split(':'))
        for _ in range(octets_needed):
            mac += ':' + format(random.randint(0, 255), '02x')
            
        return mac.upper()  # Windows typically uses uppercase
    
    def change_mac_windows(self, adapter_name, new_mac=None, vendor=None):
        """Change MAC address for Windows adapter with proper error handling"""
        
        if not new_mac:
            new_mac = self._generate_windows_mac(vendor)
        
        # Store original MAC
        if adapter_name in self.network_adapters:
            original_mac = self.network_adapters[adapter_name].get('mac', '')
            if original_mac:
                self.original_macs[adapter_name] = original_mac
        
        logging.info(f"Changing {adapter_name} MAC to: {new_mac}")
        
        try:
            # Step 1: Disable the adapter
            disable_cmd = f"Disable-NetAdapter -Name \"{adapter_name}\" -Confirm:$false"
            output, error, code = self._run_powershell(disable_cmd)
            
            if code != 0:
                logging.error(f"Failed to disable adapter {adapter_name}: {error}")
                return False
            
            time.sleep(2)  # Allow time for disable to complete
            
            # Step 2: Change MAC address using registry
            reg_success = self._change_mac_registry(adapter_name, new_mac)
            
            if not reg_success:
                logging.error(f"Registry method failed for {adapter_name}, trying WMI")
                # Alternative method using WMI
                wmi_success = self._change_mac_wmi(adapter_name, new_mac)
                if not wmi_success:
                    return False
            
            # Step 3: Re-enable adapter
            enable_cmd = f"Enable-NetAdapter -Name \"{adapter_name}\" -Confirm:$false"
            output, error, code = self._run_powershell(enable_cmd)
            
            if code != 0:
                logging.error(f"Failed to enable adapter {adapter_name}: {error}")
                return False
            
            time.sleep(3)  # Allow time for network stack to reinitialize
            
            # Verify change
            verify_mac = self._get_adapter_mac(adapter_name)
            if verify_mac and verify_mac.replace('-', ':').upper() == new_mac.upper():
                logging.info(f"Successfully changed {adapter_name} MAC to {new_mac}")
                return True
            else:
                logging.warning(f"MAC change verification failed for {adapter_name}")
                return False
                
        except Exception as e:
            logging.error(f"MAC change failed for {adapter_name}: {e}")
            return False
    
    def _change_mac_registry(self, adapter_name, new_mac):
        """Change MAC address via Windows Registry"""
        try:
            # Format MAC for registry (without colons)
            registry_mac = new_mac.replace(':', '')
            
            # Find adapter in registry
            base_key = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
            
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey_path = f"{base_key}\\{subkey_name}"
                        
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path) as subkey:
                            try:
                                adapter_desc = winreg.QueryValueEx(subkey, "DriverDesc")[0]
                                if adapter_name in adapter_desc or adapter_desc in adapter_name:
                                    # Found our adapter, set new MAC
                                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_SET_VALUE) as write_key:
                                        winreg.SetValueEx(write_key, "NetworkAddress", 0, winreg.REG_SZ, registry_mac)
                                    logging.info(f"Registry MAC change successful for {adapter_name}")
                                    return True
                            except FileNotFoundError:
                                continue
                    except:
                        continue
                        
        except Exception as e:
            logging.error(f"Registry MAC change failed: {e}")
            
        return False
    
    def _change_mac_wmi(self, adapter_name, new_mac):
        """Alternative MAC change using WMI"""
        try:
            ps_command = f"""
            $adapter = Get-NetAdapter -Name \"{adapter_name}\"
            $adapter | Set-NetAdapter -MacAddress \"{new_mac}\"
            """
            
            output, error, code = self._run_powershell(ps_command)
            return code == 0
            
        except Exception as e:
            logging.error(f"WMI MAC change failed: {e}")
            return False
    
    def _get_adapter_mac(self, adapter_name):
        """Get current MAC address of adapter"""
        try:
            ps_command = f"Get-NetAdapter -Name \"{adapter_name}\" | Select-Object -ExpandProperty MacAddress"
            output, error, code = self._run_powershell(ps_command)
            return output if code == 0 else None
        except:
            return None
    
    def rotate_safe_adapters(self, vendor=None):
        """Rotate MAC addresses only for non-VPN adapters"""
        safe_adapters = self.get_safe_adapters()
        results = {}
        
        for adapter_name in safe_adapters.keys():
            success = self.change_mac_windows(adapter_name, vendor=vendor)
            results[adapter_name] = success
            time.sleep(2)  # Stagger changes to avoid network disruption
        
        return results

class WindowsForensicCleaner:
    """Windows-optimized forensic artifact elimination"""
    
    def __init__(self):
        self.cleaned_count = 0
        
    def _expand_windows_path(self, path):
        """Expand Windows environment variables in paths"""
        return os.path.expandvars(path)
    
    def _secure_delete_windows(self, path, passes=3):
        """Secure file deletion optimized for Windows"""
        try:
            if not os.path.exists(path):
                return True
            
            # Get file attributes and remove read-only if set
            if os.path.isfile(path):
                try:
                    os.chmod(path, 0o666)  # Ensure writable
                except:
                    pass
                
                file_size = os.path.getsize(path)
                
                # Multiple overwrite passes
                for pass_num in range(passes):
                    with open(path, 'wb') as f:
                        f.write(os.urandom(file_size))
                        f.flush()
                
                # Rename before deletion
                temp_name = path + '.tmp' + str(random.randint(1000, 9999))
                try:
                    os.rename(path, temp_name)
                    path = temp_name
                except:
                    pass
                
                # Final deletion
                os.unlink(path)
                self.cleaned_count += 1
                return True
                
            elif os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
                self.cleaned_count += 1
                return True
                
        except Exception as e:
            logging.warning(f"Secure delete failed for {path}: {e}")
            
        return False
    
    def clean_windows_artifacts(self):
        """Clean Windows-specific forensic artifacts"""
        artifact_paths = [self._expand_windows_path(path) for path in WindowsConfig.ARTIFACT_PATHS]
        
        for path_pattern in artifact_paths:
            try:
                # Handle glob patterns
                if '*' in path_pattern:
                    import glob
                    paths = glob.glob(path_pattern)
                else:
                    paths = [path_pattern]
                
                for path in paths:
                    if os.path.exists(path):
                        if os.path.isfile(path):
                            self._secure_delete_windows(path)
                        elif os.path.isdir(path):
                            # Clean directory contents
                            for root, dirs, files in os.walk(path):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    self._secure_delete_windows(file_path)
            except Exception as e:
                logging.warning(f"Could not clean {path_pattern}: {e}")
        
        logging.info(f"Cleaned {self.cleaned_count} Windows artifacts")
        return self.cleaned_count
    
    def clear_browser_history(self):
        """Clear browser history and cache"""
        browser_paths = [self._expand_windows_path(path) for path in WindowsConfig.BROWSER_HISTORY_PATHS]
        
        for path_pattern in browser_paths:
            try:
                if '*' in path_pattern:
                    import glob
                    paths = glob.glob(path_pattern)
                else:
                    paths = [path_pattern]
                
                for path in paths:
                    if os.path.exists(path):
                        self._secure_delete_windows(path)
                        logging.info(f"Cleared browser data: {path}")
            except Exception as e:
                logging.warning(f"Could not clear browser data {path_pattern}: {e}")
    
    def clear_windows_event_logs(self):
        """Clear Windows event logs (requires admin)"""
        try:
            ps_command = """
            Get-EventLog -LogName System, Application, Security | 
            ForEach-Object { Clear-EventLog -LogName $_.Log }
            """
            output, error, code = self._run_powershell(ps_command)
            
            if code == 0:
                logging.info("Windows event logs cleared")
                return True
            else:
                logging.warning("Failed to clear event logs (admin required)")
                return False
                
        except Exception as e:
            logging.warning(f"Event log clearing failed: {e}")
            return False
    
    def clear_dns_cache(self):
        """Clear Windows DNS cache"""
        try:
            subprocess.run(['ipconfig', '/flushdns'], capture_output=True, check=True)
            logging.info("DNS cache flushed")
            return True
        except Exception as e:
            logging.warning(f"DNS cache flush failed: {e}")
            return False
    
    def clear_arp_cache(self):
        """Clear ARP cache"""
        try:
            subprocess.run(['arp', '-d'], capture_output=True, check=True)
            logging.info("ARP cache cleared")
            return True
        except Exception as e:
            logging.warning(f"ARP cache clear failed: {e}")
            return False

class WindowsStealthOrchestrator:
    """Master controller for Windows footprint elimination with VPN protection"""
    
    def __init__(self):
        self.mac_manager = WindowsMACManager()
        self.forensic_cleaner = WindowsForensicCleaner()
        self.vpn_protector = WindowsVPNProtector()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('windows_stealth_guardian.log'),
                logging.StreamHandler()
            ]
        )
        
        # Check admin privileges
        self.is_admin = self._check_admin_privileges()
        
    def _check_admin_privileges(self):
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def _run_powershell(self, command):
        """Execute PowerShell command"""
        try:
            result = subprocess.run([
                'powershell', '-Command', command
            ], capture_output=True, text=True, timeout=30)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timeout", 1
    
    def execute_stealth_operation(self, vendor=None, protect_vpn=True):
        """Execute comprehensive Windows footprint elimination with VPN protection"""
        
        if not self.is_admin:
            logging.error("Administrator privileges required for full functionality")
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        
        start_time = datetime.now()
        logging.info("=== WINDOWS STEALTH GUARDIAN ACTIVATED ===")
        
        # Check VPN status
        vpn_active = self.vpn_protector.check_vpn_connection_status()
        if vpn_active and protect_vpn:
            logging.info("VPN connection detected - protecting VPN interfaces")
            winsound.MessageBeep(winsound.MB_ICONASTERISK)
        
        results = {
            'vpn_protected': vpn_active and protect_vpn,
            'mac_changes': {},
            'forensic_cleanup': 0,
            'network_cleaned': False,
            'admin_privileges': self.is_admin,
            'total_time': 0
        }
        
        try:
            # Phase 1: MAC Address Rotation (VPN-safe)
            logging.info("Phase 1: VPN-Safe MAC Address Rotation")
            results['mac_changes'] = self.mac_manager.rotate_safe_adapters(vendor)
            
            # Phase 2: Forensic Cleanup
            logging.info("Phase 2: Windows Forensic Artifact Elimination")
            results['forensic_cleanup'] = self.forensic_cleaner.clean_windows_artifacts()
            self.forensic_cleaner.clear_browser_history()
            
            # Phase 3: Network Cleanup
            logging.info("Phase 3: Network Cache Cleansing")
            self.forensic_cleaner.clear_dns_cache()
            self.forensic_cleaner.clear_arp_cache()
            results['network_cleaned'] = True
            
            # Phase 4: System Cleanup (if admin)
            if self.is_admin:
                logging.info("Phase 4: System-Level Cleansing")
                self.forensic_cleaner.clear_windows_event_logs()
            
            # Calculate execution time
            end_time = datetime.now()
            results['total_time'] = (end_time - start_time).total_seconds()
            
            logging.info(f"=== STEALTH OPERATION COMPLETED IN {results['total_time']:.2f}s ===")
            self._generate_report(results)
            
            # Success sound
            winsound.MessageBeep(winsound.MB_ICONINFORMATION)
            
            return results
            
        except Exception as e:
            logging.error(f"Stealth operation failed: {e}")
            winsound.MessageBeep(winsound.MB_ICONHAND)
            return results
    
    def quick_stealth_mode(self):
        """Rapid footprint reduction with maximum VPN protection"""
        logging.info("Activating Quick Stealth Mode with VPN Protection")
        
        # Fast MAC rotation (VPN-safe only)
        self.mac_manager.rotate_safe_adapters(vendor='random')
        
        # Essential forensic cleanup
        self.forensic_cleaner.clean_windows_artifacts()
        self.forensic_cleaner.clear_browser_history()
        
        # Network cleanup
        self.forensic_cleaner.clear_dns_cache()
        self.forensic_cleaner.clear_arp_cache()
        
        logging.info("Quick Stealth Mode activated")
        winsound.MessageBeep(winsound.MB_OK)
    
    def vpn_status_report(self):
        """Generate detailed VPN protection status report"""
        return self.vpn_protector.get_vpn_protection_status()
    
    def _generate_report(self, results):
        """Generate operation report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'system': platform.system(),
            'windows_version': platform.version(),
            'admin_privileges': self.is_admin,
            'vpn_status': self.vpn_status_report(),
            'operations': results
        }
        
        with open('windows_stealth_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        logging.info(f"Detailed report saved to: windows_stealth_report.json")

def main():
    """Windows-optimized command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Windows Stealth Guardian - Advanced Footprint Elimination with VPN Protection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python windows_stealth.py --full                    # Comprehensive stealth with VPN protection
  python windows_stealth.py --quick                   # Rapid stealth mode
  python windows_stealth.py --mac-only --vendor dell  # MAC change only (Dell compatible)
  python windows_stealth.py --forensic-only           # Forensic cleanup only
  python windows_stealth.py --vpn-status              # Check VPN protection status
        
Note: Administrator privileges required for full functionality.
        '''
    )
    
    parser.add_argument('--full', action='store_true', 
                       help='Comprehensive footprint elimination with VPN protection')
    parser.add_argument('--quick', action='store_true',
                       help='Rapid stealth mode with VPN protection')
    parser.add_argument('--mac-only', action='store_true',
                       help='Change MAC addresses only (VPN-safe)')
    parser.add_argument('--forensic-only', action='store_true',
                       help='Forensic cleanup only')
    parser.add_argument('--vpn-status', action='store_true',
                       help='Show VPN protection status')
    parser.add_argument('--vendor', choices=['microsoft', 'dell', 'hp', 'lenovo', 'intel', 'realtek', 'broadcom', 'random'],
                       default='random', help='Vendor for MAC address spoofing')
    parser.add_argument('--adapter', help='Specific network adapter to target')
    parser.add_argument('--no-vpn-protection', action='store_true',
                       help='Disable VPN protection (not recommended)')
    
    args = parser.parse_args()
    
    # Check if running on Windows
    if platform.system() != 'Windows':
        print("This script is optimized for Windows systems only.")
        sys.exit(1)
    
    orchestrator = WindowsStealthOrchestrator()
    
    try:
        if args.full:
            orchestrator.execute_stealth_operation(
                vendor=args.vendor,
                protect_vpn=not args.no_vpn_protection
            )
        elif args.quick:
            orchestrator.quick_stealth_mode()
        elif args.mac_only:
            if args.adapter:
                orchestrator.mac_manager.change_mac_windows(
                    adapter_name=args.adapter,
                    vendor=args.vendor
                )
            else:
                orchestrator.mac_manager.rotate_safe_adapters(vendor=args.vendor)
        elif args.forensic_only:
            orchestrator.forensic_cleaner.clean_windows_artifacts()
            orchestrator.forensic_cleaner.clear_browser_history()
        elif args.vpn_status:
            status = orchestrator.vpn_status_report()
            print("VPN Protection Status:")
            print(json.dumps(status, indent=2))
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        logging.info("Operation cancelled by user")
        winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
    except Exception as e:
        logging.error(f"Operation failed: {e}")
        winsound.MessageBeep(winsound.MB_ICONHAND)

if __name__ == '__main__':
    # Windows-specific initialization
    if platform.system() == 'Windows':
        # Add console colors for better visibility
        os.system('color')
        
        # Check for required modules
        try:
            import psutil
            import pywintypes
        except ImportError as e:
            print(f"Required module missing: {e}")
            print("Install required modules: pip install psutil pywin32")
            sys.exit(1)
        
        main()
    else:
        print("This tool is designed for Windows systems only.")
        sys.exit(1)
