"""
Script Name: TCPScan.py
Author: Justin Andrews
Version: 1.0
Date: 

Description:
    This script is a multithreaded TCP port scanner. It scans specified IP addresses
    for open ports within a given range. The scanner attempts to identify the service
    running on open ports and can retrieve responses from these services.

Features:
    - Multiple IP address scanning
    - Customizable port range
    - Multithreaded for improved performance
    - Service identification for open ports
    - Retrieves responses from open ports
    - Configurable timeout and retry attempts

Arguments:
    --ipaddr            IP address(es) separated by commas
    --start-port        Start of port range (default: 1)
    --end-port          End of port range (default: 65535)
    --timeout           Timeout in seconds for each connection attempt (default: 1)
    --max-attempts      Maximum number of attempts per port (default: 1)

Usage:
    python TCPScan.py --ipaddr IP_ADDRESSES [--start-port START_PORT] [--end-port END_PORT] [--timeout TIMEOUT] [--max-attempts MAX_ATTEMPTS]

Example:
    python TCPScan.py --ipaddr 192.168.1.1,192.168.1.2 --start-port 1 --end-port 1000 --timeout 2 --max-attempts 2

Note: Use this script responsibly and only on networks and systems you have permission to scan.
      Unauthorized scanning may be illegal and unethical.

GUI Parameters Start:
"ipaddr": ""
"start_port": 1
"end_port": 65535
"timeout": 1.0
"max_attempts": 1
"persistent": false
GUI Parameters End:
"""

import sys
import socket
import ipaddress
from typing import List, Dict, Optional, Union, Any
from Utils import LoggingPipeline, ArgumentHandler, Threading


class TCPScanner:
    """Main class for TCP port scanning operations."""

    # Max size of an uncompressed SSH packet
    MAX_PACKET = 32768

    def __init__(self, debug: bool = False, logging: bool = False):
        """
        Initialize TCP scanner with logging support.

        Args:
            debug (bool): Enable debug output
            logging (bool): Enable logging to file
        """
        self.logger = LoggingPipeline(debug=debug, logging=logging, log_name="tcp_scan")
        self.thread_manager = Threading(debug=debug, logging=logging)

    def validate_ip(self, ip: str) -> bool:
        """
        Validate an IP address.

        Args:
            ip (str): IP address to validate

        Returns:
            bool: True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip.strip())
            return True
        except ValueError:
            self.logger.append_log(f"Invalid IP address: {ip}", "ERROR")
            return False

    def scan_port(self, ip: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
        """
        Scan a single port on a given IP address.

        Args:
            ip (str): IP address to scan
            port (int): Port number to scan
            timeout (float): Connection timeout in seconds

        Returns:
            Optional[Dict[str, Any]]: Scan results if port is open, None otherwise
        """
        self.logger.append_log(f"Scanning {ip}:{port}", "DEBUG")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))

                if result == 0:
                    # Port is open, try to get service info and response
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except OSError:
                        service = "unknown"

                    try:
                        response = s.recv(self.MAX_PACKET)
                        response_data = f"Response: {response}"
                    except socket.error as e:
                        response_data = f"Error getting response: {e}"

                    self.logger.append_log(
                        f"Open port found: {ip}:{port} ({service})", "SUCCESS"
                    )

                    return {
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "response": response_data,
                        "status": "open",
                    }

                return None

        except socket.error as e:
            self.logger.append_log(f"Error scanning {ip}:{port}: {e}", "ERROR")
            return None

    def scan_range(
        self,
        ip_addresses: List[str],
        start_port: int,
        end_port: int,
        timeout: float,
        max_attempts: int,
        threads: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Scan a range of ports on multiple IP addresses using threading.

        Args:
            ip_addresses (List[str]): List of IP addresses to scan
            start_port (int): Starting port number
            end_port (int): Ending port number
            timeout (float): Connection timeout in seconds
            max_attempts (int): Maximum number of retry attempts
            threads (int): Number of threads to use

        Returns:
            List[Dict[str, Any]]: List of scan results for open ports
        """
        self.logger.start_section("TCP Port Scan")
        self.logger.append_log(
            f"Starting scan of {len(ip_addresses)} hosts, ports {start_port}-{end_port}",
            "INFO",
        )

        scan_tasks = []
        for ip in ip_addresses:
            for port in range(start_port, end_port + 1):
                scan_tasks.append((ip, port, timeout))

        # Use Threading utility for parallel scanning
        results = []
        for attempt in range(max_attempts):
            if attempt > 0:
                self.logger.append_log(f"Retry attempt {attempt + 1}", "INFO")

            # Map the scan_port function across all IP:port combinations
            attempt_results = self.thread_manager.map_threaded(
                lambda args: self.scan_port(*args), scan_tasks, threads=threads
            )

            # Filter out None results and extend the results list
            results.extend([r for r in attempt_results if r is not None])

        return results

    def print_results(self, results: List[Dict[str, Any]]) -> None:
        """
        Print formatted scan results.

        Args:
            results (List[Dict[str, Any]]): List of scan results
        """
        if not results:
            self.logger.append_log("No open ports found", "WARNING")
            return

        # Group results by IP address
        results_by_ip = {}
        for result in results:
            ip = result["ip"]
            if ip not in results_by_ip:
                results_by_ip[ip] = []
            results_by_ip[ip].append(result)

        # Print results for each IP
        for ip, ip_results in results_by_ip.items():
            self.logger.append_log(f"\nResults for {ip}:", "SUCCESS")
            self.logger.append_log("=" * 50, "INFO")

            for result in sorted(ip_results, key=lambda x: x["port"]):
                summary = (
                    f"Port: {result['port']} | "
                    f"Service: {result['service']}\n"
                    f"{result['response']}"
                )
                self.logger.append_log(summary, "SUCCESS")

        # Print summary statistics
        total_ips = len(results_by_ip)
        total_ports = len(results)
        summary = (
            f"\nScan Summary\n"
            f"{'=' * 50}\n"
            f"Total hosts with open ports: {total_ips}\n"
            f"Total open ports found: {total_ports}"
        )
        self.logger.append_log(summary, "SUCCESS")

    def cleanup(self) -> None:
        """Cleanup and finalize logging."""
        if self.logger.file_logging:
            self.logger.generate_log()


def main():
    # Define argument configuration
    arg_config = {
        "script": {
            "name": "TCPScan.py",
            "description": "TCP Port Scanner",
        },
        "args": {
            "ipaddr": {
                "flag": "--ipaddr",
                "help": "IP address(es) separated by commas",
                "required": True,
            },
            "start_port": {
                "flag": "--start-port",
                "type": int,
                "default": 1,
                "help": "Start of port range",
            },
            "end_port": {
                "flag": "--end-port",
                "type": int,
                "default": 65535,
                "help": "End of port range",
            },
            "timeout": {
                "flag": "--timeout",
                "type": float,
                "default": 1.0,
                "help": "Timeout in seconds",
            },
            "max_attempts": {
                "flag": "--max-attempts",
                "type": int,
                "default": 1,
                "help": "Maximum number of attempts per port",
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
        },
    }

    # Parse arguments
    arg_handler = ArgumentHandler(arg_config)
    args = arg_handler.parse_args()

    # Initialize scanner
    scanner = TCPScanner(debug=args.debug, logging=args.logging)

    try:
        # Validate IP addresses
        ip_addresses = [ip.strip() for ip in args.ipaddr.split(",")]
        valid_ips = [ip for ip in ip_addresses if scanner.validate_ip(ip)]

        if not valid_ips:
            scanner.logger.append_log("Error: No valid IP addresses provided", "ERROR")
            sys.exit(1)

        # Run the scan
        results = scanner.scan_range(
            valid_ips, args.start_port, args.end_port, args.timeout, args.max_attempts
        )

        # Print results
        scanner.print_results(results)

    except Exception as e:
        scanner.logger.append_log(f"Fatal error: {str(e)}", "ERROR")
        if args.debug:
            import traceback

            scanner.logger.append_log(traceback.format_exc(), "ERROR")
        sys.exit(1)

    finally:
        scanner.cleanup()


if __name__ == "__main__":
    main()
