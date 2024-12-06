"""
Script Name: PingScanPy.py
Author: Justin Andrews
Version: 2.0
Date: 2024-03-19

Description:
    This script performs a ping scan of a connected network using multithreading.
    It utilizes the utility classes from Utils.py for logging, argument handling,
    and network operations.

Arguments:
    network             Network to scan (e.g., 192.168.1.0/24)
    -t, --threads       Number of threads to use (default: 10)
    --timeout          Timeout for each ping in seconds (default: 1)
    -d, --debug        Enable debug output
    -l, --logging      Enable logging to file

Usage:
    Basic network scan:
        python PingScanPy.py <network>

    With custom thread count and timeout:
        python PingScanPy.py <network> -t 20 --timeout 2

    With debug output and logging:
        python PingScanPy.py <network> -d -l

Example:
    python PingScanPy.py 192.168.1.0/24 -t 10 -d -l

GUI Parameters Start:
"network": ""
"threads": 10
"timeout": 1
"debug": false
"logging": false
"persistent": false
GUI Parameters End:
"""

import sys
from typing import Dict, List, Union
from Utils import LoggingPipeline, ArgumentHandler, NetworkScanner


class PingScan:
    """Main class for network ping scanning operations."""

    def __init__(self, threads: int = 10, debug: bool = False, logging: bool = False):
        """
        Initialize ping scanner with logging support.

        Args:
            threads (int): Number of threads to use
            debug (bool): Enable debug output
            logging (bool): Enable logging to file
        """
        self.threads = threads
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="ping_scan"
        )
        self.scanner = NetworkScanner(debug=debug, logging=logging)

    def scan_network(self, network: str, timeout: int = 1) -> List[Dict[str, Union[str, bool]]]:
        """
        Perform ping scan on a network.

        Args:
            network (str): Network address in CIDR notation
            timeout (int): Timeout for each ping in seconds

        Returns:
            List[Dict[str, Union[str, bool]]]: List of scan results
        """
        self.logger.start_section(f"Network Scan: {network}")
        self.logger.append_log(
            f"Starting network scan with {self.threads} threads", "INFO"
        )

        try:
            # Use NetworkScanner to perform the scan
            results = self.scanner.scan_network(
                network=network,
                timeout=timeout,
                threads=self.threads
            )

            self.print_results(results)
            return results

        except ValueError as e:
            self.logger.append_log(f"Invalid network address: {str(e)}", "ERROR")
            return []
        except Exception as e:
            self.logger.append_log(f"Scan failed: {str(e)}", "ERROR")
            return []

    def print_results(self, results: List[Dict[str, Union[str, bool]]]) -> None:
        """
        Print formatted scan results.

        Args:
            results (List[Dict[str, Union[str, bool]]]): List of scan results
        """
        # Count successful and failed pings
        successful = sum(1 for r in results if r["success"])
        failed = len(results) - successful

        # Create summary
        summary = [
            f"\nScan Results Summary",
            f"{'=' * 50}",
            f"Total Hosts Scanned: {len(results)}",
            f"Hosts Up: {successful}",
            f"Hosts Down: {failed}",
        ]

        # Add details of responding hosts
        if successful > 0:
            summary.extend(["\nResponding Hosts:", f"{'-' * 20}"])
            for result in results:
                if result["success"]:
                    summary.append(f"  - {result['ip']}")
                    # Only show ping statistics in debug mode
                    if self.logger.debug and isinstance(result["output"], str) and result["output"].strip():
                        summary.append(f"    Response: {result['output'].strip()}")

        # Log results with appropriate status
        for line in summary:
            self.logger.append_log(
                line, "SUCCESS" if successful > 0 else "WARNING"
            )

    def cleanup(self) -> None:
        """Cleanup and finalize logging."""
        if self.logger.file_logging:
            self.logger.generate_log()


def main():
    # Define argument configuration
    arg_config = {
        "script": {
            "name": "PingScanPy.py",
            "description": "Network Ping Scanner",
        },
        "args": {
            "network": {
                "help": "Network to scan (e.g., 192.168.1.0/24)",
                "positional": True,
            },
            "threads": {
                "flag": "-t",
                "type": int,
                "default": 10,
                "help": "Number of threads to use",
            },
            "timeout": {
                "flag": "--timeout",
                "type": int,
                "default": 1,
                "help": "Timeout for each ping in seconds",
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
    scanner = PingScan(
        threads=args.threads,
        debug=args.debug,
        logging=args.logging
    )

    try:
        # Run the scan
        scanner.scan_network(args.network, args.timeout)

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