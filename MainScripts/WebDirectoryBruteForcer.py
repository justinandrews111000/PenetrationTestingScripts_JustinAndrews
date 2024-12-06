"""
Script Name: DirectoryBruteForce.py
Author: Justin Andrews
Version: 1.0
Date: 


Description:
    This script performs a directory brute force scan on a specified URL using multithreading.
    It attempts to discover hidden directories and files by testing paths from a wordlist.
    The script utilizes rate limiting to avoid overwhelming target servers and provides
    detailed logging of all activities.

Arguments:
    url                 Target URL to scan (must include http:// or https://)
    -w, --wordlist     Path to wordlist file (default: WordLists/DirectoryWordList.txt)
    -t, --threads      Number of threads to use (default: 10)
    --timeout          Request timeout in seconds (default: 0.5)
    --max-retries      Maximum number of retries for failed requests (default: 3)
    --rate-limit       Maximum requests per second (default: 10)
    -d, --debug        Enable debug output
    -l, --logging      Enable logging to file
    -f, --follow       Follow redirects (default: False)
    --status-codes     Comma-separated list of status codes to report (default: 200,201,202,203,204,301,302,307,308,401,403)
    --user-agent       Custom User-Agent string
    --extensions       Comma-separated list of extensions to test (e.g., php,html,asp)

Usage:
    Basic scan:
        python WebDirectoryBruteForcer.py <url>

    Advanced scan:
        python WebDirectoryBruteForcer.py <url> -w custom_wordlist.txt -t 20 --timeout 1.0 --rate-limit 20

Example:
    python WebDirectoryBruteForcer.py https://example.com -w wordlist.txt -t 15 -d -l --extensions php,html,js

GUI Parameters Start:
"url": ""
"wordlist": "WordLists/DirectoryWordList.txt"
"threads": 10
"timeout": 0.5
"max_retries": 3
"rate_limit": 10
"debug": false
"logging": false
"follow": false
"status_codes": "200,201,202,203,204,301,302,307,308,401,403"
"user_agent": ""
"extensions": ""
"persistent": false
GUI Parameters End:
"""

import sys
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException
from Utils import ArgumentHandler, LoggingPipeline, Threading


class RateLimiter:
    """Rate limiting implementation using token bucket algorithm."""

    def __init__(self, rate: float):
        """
        Initialize rate limiter.

        Args:
            rate (float): Maximum requests per second
        """
        self.rate = rate
        self.tokens = rate
        self.last_update = time.time()
        self.min_interval = 1.0 / rate if rate > 0 else 0

    def acquire(self) -> float:
        """
        Acquire a token, blocking if necessary.

        Returns:
            float: Time to wait before proceeding
        """
        now = time.time()
        elapsed = now - self.last_update
        self.last_update = now

        # Add new tokens based on elapsed time
        self.tokens = min(self.rate, self.tokens + elapsed * self.rate)

        if self.tokens < 1:
            # Need to wait
            wait_time = (1 - self.tokens) / self.rate
            time.sleep(wait_time)
            self.tokens = 0
            return wait_time
        else:
            # Can proceed immediately
            self.tokens -= 1
            return 0


class DirectoryScanner:
    """Main class for directory brute force operations."""

    def __init__(
        self,
        url: str,
        wordlist: str,
        threads: int = 10,
        timeout: float = 0.5,
        max_retries: int = 3,
        rate_limit: int = 10,
        debug: bool = False,
        logging: bool = False,
        follow_redirects: bool = False,
        status_codes: Optional[List[int]] = None,
        user_agent: Optional[str] = None,
        extensions: Optional[List[str]] = None,
    ):
        """
        Initialize directory scanner with logging support.

        Args:
            url (str): Target URL to scan
            wordlist (str): Path to wordlist file
            threads (int): Number of threads to use
            timeout (float): Request timeout in seconds
            max_retries (int): Maximum number of retry attempts
            rate_limit (int): Maximum requests per second
            debug (bool): Enable debug output
            logging (bool): Enable logging to file
            follow_redirects (bool): Follow redirect responses
            status_codes (List[int], optional): Status codes to report
            user_agent (str, optional): Custom User-Agent string
            extensions (List[str], optional): File extensions to test
        """
        self.url = url.rstrip("/")
        self.wordlist = Path(wordlist)
        self.threads = threads
        self.timeout = timeout
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects
        self.status_codes = status_codes or [
            200,
            201,
            202,
            203,
            204,
            301,
            302,
            307,
            308,
            401,
            403,
        ]
        self.extensions = extensions or []

        # Initialize components
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="directory_scan"
        )
        self.thread_manager = Threading(debug=debug, logging=logging)
        self.rate_limiter = RateLimiter(rate_limit)

        # Set up requests session
        self.session = requests.Session()
        if user_agent:
            self.session.headers["User-Agent"] = user_agent

        # Results tracking
        self.results: Dict[str, Dict[str, Any]] = {}
        self.tested_paths: Set[str] = set()
        self.start_time = None
        
    def get_current_time(self):
        return time.time()

    def validate_url(self) -> bool:
        """Validate target URL format and accessibility."""
        try:
            parsed = urlparse(self.url)
            if not all([parsed.scheme, parsed.netloc]):
                raise ValueError(
                    "Invalid URL format. Must include scheme (http:// or https://)"
                )

            self.logger.append_log(f"Validating target URL: {self.url}", "DEBUG")
            response = self.session.head(
                self.url, timeout=self.timeout, allow_redirects=self.follow_redirects
            )
            response.raise_for_status()
            return True

        except (ValueError, RequestException) as e:
            self.logger.append_log(f"URL validation failed: {str(e)}", "ERROR")
            return False

    def load_wordlist(self) -> List[str]:
        """Load and process the wordlist file."""
        if not self.wordlist.exists():
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist}")

        paths = []
        try:
            with self.wordlist.open("r", encoding="utf-8") as f:
                base_paths = [line.strip() for line in f if line.strip()]

            # Process base paths and add extensions if specified
            for path in base_paths:
                paths.append(path)
                for ext in self.extensions:
                    if not ext.startswith("."):
                        ext = f".{ext}"
                    paths.append(f"{path}{ext}")

            self.logger.append_log(
                f"Loaded {len(paths)} paths from wordlist", "SUCCESS"
            )
            return paths

        except Exception as e:
            self.logger.append_log(f"Error loading wordlist: {str(e)}", "ERROR")
            raise

    def test_path(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Test a single path on the target URL.

        Args:
            path (str): Path to test

        Returns:
            Optional[Dict[str, Any]]: Test results if path is accessible
        """
        if path in self.tested_paths:
            return None

        self.tested_paths.add(path)
        target_url = urljoin(self.url, path.lstrip("/"))

        for attempt in range(self.max_retries):
            try:
                # Apply rate limiting
                wait_time = self.rate_limiter.acquire()
                if wait_time > 0:
                    self.logger.append_log(
                        f"Rate limit applied, waiting {wait_time:.2f}s", "DEBUG"
                    )

                # Make request
                start_time = time.time()
                response = self.session.get(
                    target_url,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                )
                elapsed = time.time() - start_time

                status_code = response.status_code
                if status_code in self.status_codes:
                    result = {
                        "url": target_url,
                        "status_code": status_code,
                        "content_length": len(response.content),
                        "response_time": elapsed,
                        "redirect_url": (
                            response.url
                            if self.follow_redirects and response.history
                            else None
                        ),
                    }

                    self.logger.append_log(
                        f"Found: {target_url} [{status_code}] ({result['content_length']} bytes)",
                        "SUCCESS",
                    )
                    return result

                return None

            except RequestException as e:
                if attempt < self.max_retries - 1:
                    self.logger.append_log(
                        f"Retry {attempt + 1}/{self.max_retries} for {target_url}: {str(e)}",
                        "WARNING",
                    )
                    time.sleep(1)  # Brief delay before retry
                else:
                    self.logger.append_log(
                        f"Failed to test {target_url}: {str(e)}", "ERROR"
                    )

        return None

    def scan(self) -> Dict[str, Dict[str, Any]]:
        """
        Perform the directory scan using multiple threads.

        Returns:
            Dict[str, Dict[str, Any]]: Scan results
        """
        self.logger.start_section("Directory Scan")
        self.start_time = time.time()

        try:
            # Validate URL before proceeding
            if not self.validate_url():
                raise ValueError("Target URL validation failed")

            # Load and prepare paths
            paths = self.load_wordlist()
            self.logger.append_log(
                f"Starting scan of {len(paths)} paths using {self.threads} threads",
                "INFO",
            )

            # Perform threaded scanning
            results = self.thread_manager.map_threaded(
                self.test_path, paths, threads=self.threads
            )

            # Process results
            self.results = {
                result["url"]: result for result in results if result is not None
            }

            return self.results

        except Exception as e:
            self.logger.append_log(f"Scan failed: {str(e)}", "ERROR")
            raise

    def print_results(self) -> None:
        """Print formatted scan results and statistics."""
        if not self.results:
            self.logger.append_log("No directories or files found", "WARNING")
            return

        scan_duration = self.get_current_time() - self.start_time
        paths_per_second = len(self.tested_paths) / scan_duration

        # Group results by status code
        results_by_status = {}
        for result in self.results.values():
            status = result["status_code"]
            if status not in results_by_status:
                results_by_status[status] = []
            results_by_status[status].append(result)

        # Print summary header
        summary = [
            f"\nScan Results for {self.url}",
            f"{'=' * 80}",
            f"Total Paths Tested: {len(self.tested_paths)}",
            f"Paths Found: {len(self.results)}",
            f"Scan Duration: {scan_duration:.2f} seconds",
            f"Paths/Second: {paths_per_second:.2f}",
            f"\nFindings by Status Code:",
            f"{'-' * 30}",
        ]

        # Print findings grouped by status code
        for status_code in sorted(results_by_status.keys()):
            findings = results_by_status[status_code]
            summary.extend(
                [f"\nStatus Code {status_code} ({len(findings)} found):", f"{'-' * 50}"]
            )

            for result in sorted(findings, key=lambda x: x["url"]):
                url = result["url"]
                size = result["content_length"]
                time = result["response_time"]
                redirect = (
                    f" -> {result['redirect_url']}"
                    if result.get("redirect_url")
                    else ""
                )

                summary.append(
                    f"{url}{redirect}\n"
                    f"  Size: {size} bytes | Response Time: {time:.3f}s"
                )

        # Log the complete summary
        for line in summary:
            self.logger.append_log(line, "SUCCESS" if self.results else "WARNING")

    def cleanup(self) -> None:
        """Cleanup and finalize logging."""
        self.session.close()
        if self.logger.file_logging:
            self.logger.generate_log()


def main():
    # Define argument configuration
    arg_config = {
        "script": {
            "name": "WebDirectoryBruteForcer.py",
            "description": "Web Directory Brute Force Scanner",
        },
        "args": {
            "url": {"help": "Target URL to scan", "positional": True},
            "wordlist": {
                "flag": "-w",
                "default": "WordLists/DirectoryWordList.txt",
                "help": "Path to wordlist file",
            },
            "threads": {
                "flag": "-t",
                "type": int,
                "default": 10,
                "help": "Number of threads to use",
            },
            "timeout": {
                "flag": "--timeout",
                "type": float,
                "default": 0.5,
                "help": "Request timeout in seconds",
            },
            "max_retries": {
                "flag": "--max-retries",
                "type": int,
                "default": 3,
                "help": "Maximum number of retries",
            },
            "rate_limit": {
                "flag": "--rate-limit",
                "type": int,
                "default": 10,
                "help": "Maximum requests per second",
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
            "follow": {
                "flag": "-f",
                "action": "store_true",
                "help": "Follow redirects",
            },
            "status_codes": {
                "flag": "--status-codes",
                "default": "200,201,202,203,204,301,302,307,308,401,403",
                "help": "Comma-separated list of status codes to report",
            },
            "user_agent": {"flag": "--user-agent", "help": "Custom User-Agent string"},
            "extensions": {
                "flag": "--extensions",
                "help": "Comma-separated list of extensions to test (e.g., php,html,asp)",
            },
        },
    }

    # Parse arguments
    arg_handler = ArgumentHandler(arg_config)
    args = arg_handler.parse_args()

    # Initialize scanner
    scanner = None
    try:
        # Process status codes
        status_codes = [int(code.strip()) for code in args.status_codes.split(",")]

        # Process extensions
        extensions = []
        if args.extensions:
            extensions = [ext.strip() for ext in args.extensions.split(",")]

        # Initialize scanner with parsed arguments
        scanner = DirectoryScanner(
            url=args.url,
            wordlist=args.wordlist,
            threads=args.threads,
            timeout=args.timeout,
            max_retries=args.max_retries,
            rate_limit=args.rate_limit,
            debug=args.debug,
            logging=args.logging,
            follow_redirects=args.follow,
            status_codes=status_codes,
            user_agent=args.user_agent,
            extensions=extensions,
        )

        # Run the scan
        scanner.scan()

        # Print results
        scanner.print_results()

    except Exception as e:
        if scanner and scanner.logger:
            scanner.logger.append_log(f"Fatal error: {str(e)}", "ERROR")
            if args.debug:
                import traceback

                scanner.logger.append_log(traceback.format_exc(), "ERROR")
        sys.exit(1)

    finally:
        if scanner:
            scanner.cleanup()


if __name__ == "__main__":
    main()
