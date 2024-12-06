"""
Script Name: DNSZoneTransfer.py
Author: Justin Andrews 
Version: 2.4
Date:
Description:
    This script performs DNS Zone Transfer (AXFR) queries against specified DNS servers
    for a given domain using nslookup. It utilizes the utility classes from Utils.py
    for logging, argument handling, and system command execution.

Arguments:
    domain              The target domain to test for zone transfer
    dns_servers         One or more DNS servers to query for zone transfer
    -d, --debug        Enable debug output for more detailed information
    -l, --logging      Enable logging to file

Usage:
    Basic zone transfer:
        python DNSZoneTransfer.py <domain> <dns_server1> [dns_server2 ...]

    With debug output:
        python DNSZoneTransfer.py <domain> <dns_server> -d

    With logging:
        python DNSZoneTransfer.py <domain> <dns_server> -l

Example:
    python DNSZoneTransfer.py zonetransfer.me nsztm1.digi.ninja
    python DNSZoneTransfer.py zonetransfer.me nsztm1.digi.ninja -d -l

GUI Parameters Start:
"domain": ""
"dns_servers": []
"debug": false
"logging": false
"persistent": false
GUI Parameters End:
"""

import sys
from typing import List
from Utils import LoggingPipeline, SystemCommand, ArgumentHandler


class DNSZoneTransfer:
    """Class for performing DNS Zone Transfer operations with logging support."""

    def __init__(self, debug: bool = False, logging: bool = False):
        """
        Initialize DNS Zone Transfer utility with logging support.

        Args:
            debug (bool): Enable debug output
            logging (bool): Enable logging to file
        """
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="dns_zone_transfer"
        )
        self.system = SystemCommand(debug=debug, logging=logging)

    def run_zone_transfer(self, domain: str, dns_server: str) -> bool:
        """
        Perform DNS Zone Transfer for a specific domain and DNS server.

        Args:
            domain (str): Target domain
            dns_server (str): DNS server to query

        Returns:
            bool: True if successful, False otherwise
        """
        self.logger.start_section(f"Zone Transfer: {domain} from {dns_server}")

        # Construct nslookup commands
        nslookup_commands = [
            "server " + dns_server,
            "set q=AXFR",  # Explicitly set query type to AXFR
            "set type=any",
            "set class=any",
            "ls -d " + domain,  # Use ls -d for zone transfer
            "exit",
        ]

        command_input = "\n".join(nslookup_commands)
        self.logger.append_log(
            f"Executing nslookup commands:\n{command_input}", "DEBUG"
        )

        try:
            # Use enhanced SystemCommand with interactive mode
            result = self.system.execute(
                command=["nslookup", "-"],
                stdin_input=command_input,
                interactive=True,
                timeout=30,  # Add reasonable timeout
            )

            if isinstance(result, tuple):
                stdout, stderr = result

                # Process the output
                if stdout:
                    self.logger.append_log(stdout, "INFO")
                    if "Transfer failed" in stdout or "REFUSED" in stdout:
                        self.logger.append_log(
                            f"Zone transfer failed for {domain} from {dns_server}",
                            "WARNING",
                        )
                        return False

                    if "AXFR record" in stdout or "Transfer completed" in stdout:
                        self.logger.append_log(
                            f"Zone transfer successful for {domain} from {dns_server}",
                            "SUCCESS",
                        )
                        return True

                    # If we got output but can't determine success/failure
                    return True

                if stderr:
                    self.logger.append_log(stderr, "ERROR")
                    return False

            self.logger.append_log(f"Command execution failed or timed out", "ERROR")
            return False

        except Exception as e:
            self.logger.append_log(f"Error during zone transfer: {str(e)}", "ERROR")
            return False

    def process_servers(self, domain: str, dns_servers: List[str]) -> None:
        """
        Process multiple DNS servers for zone transfer attempts.

        Args:
            domain (str): Target domain
            dns_servers (List[str]): List of DNS servers to query
        """
        successful_transfers = 0
        failed_transfers = 0

        for server in dns_servers:
            success = self.run_zone_transfer(domain, server)
            if success:
                successful_transfers += 1
            else:
                failed_transfers += 1

        # Log summary
        summary = (
            f"\nZone Transfer Summary:\n"
            f"{'=' * 50}\n"
            f"Domain: {domain}\n"
            f"Total DNS Servers: {len(dns_servers)}\n"
            f"Successful Transfers: {successful_transfers}\n"
            f"Failed Transfers: {failed_transfers}\n"
        )

        self.logger.append_log(
            summary, "SUCCESS" if successful_transfers > 0 else "WARNING"
        )

    def cleanup(self) -> None:
        """Cleanup and finalize logging."""
        if self.logger.file_logging:
            self.logger.generate_log()


def main():
    # Define argument configuration
    arg_config = {
        "script": {
            "name": "DNSZoneTransfer.py",
            "description": "DNS Zone Transfer Utility",
        },
        "args": {
            "domain": {"help": "Target domain to query", "positional": True},
            "dns_servers": {
                "help": "One or more DNS servers to query",
                "nargs": "+",
                "positional": True,
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

    # Initialize DNS Zone Transfer utility
    zone_transfer = DNSZoneTransfer(debug=args.debug, logging=args.logging)

    try:
        zone_transfer.process_servers(args.domain, args.dns_servers)

    except Exception as e:
        zone_transfer.logger.append_log(f"Fatal error: {str(e)}", "ERROR")
        if args.debug:
            import traceback

            zone_transfer.logger.append_log(traceback.format_exc(), "ERROR")
        sys.exit(1)

    finally:
        zone_transfer.cleanup()


if __name__ == "__main__":
    main()
