"""
Script Name: SubdomainEnumerator.py
Author: Justin Andrews
Version: 1.0
Date: 2024-03-19

Description:
    This script performs subdomain enumeration for a given domain using multithreading.
    It attempts to discover valid subdomains by testing HTTP/HTTPS connectivity and 
    provides detailed logging of all findings.

Arguments:
    domain               Base domain to enumerate (e.g., example.com)
    -w, --wordlist      Path to wordlist file (default: WordLists/subdomains-top1million-5000.txt)
    -t, --threads       Number of threads to use (default: 10)
    --timeout           Request timeout in seconds (default: 3)
    --max-retries       Maximum number of retries for failed requests (default: 2)
    --rate-limit        Maximum requests per second (default: 10)
    -d, --debug         Enable debug output
    -l, --logging       Enable logging to file
    --user-agent        Custom User-Agent string
    --schemes           Comma-separated list of schemes to test (default: http,https)

Usage:
    Basic scan:
        python SubdomainEnumerator.py example.com
    
    Advanced scan:
        python SubdomainEnumerator.py example.com -w custom_wordlist.txt -t 20 --timeout 5 --rate-limit 20

Example:
    python SubdomainEnumerator.py example.com -t 15 -d -l --schemes https

GUI Parameters Start:
"domain": ""
"wordlist": "WordLists/subdomains-top1million-5000.txt"
"threads": 10
"timeout": 3
"max_retries": 2
"rate_limit": 10
"debug": false
"logging": false
"user_agent": ""
"schemes": "http,https"
"persistent": false
GUI Parameters End:
"""

import re
import sys
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set, Any

# Third-party imports 
import requests
import urllib3
from requests.exceptions import ConnectionError, Timeout
from urllib3.exceptions import InsecureRequestWarning

# Local imports
from Utils import LoggingPipeline, Threading, ArgumentHandler

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RateLimiter:
    """Thread-safe rate limiting implementation using token bucket algorithm."""

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
        self.lock = threading.Lock()

    def acquire(self) -> float:
        """
        Acquire a token, blocking if necessary.
        Returns:
            float: Time to wait before proceeding
        """
        with self.lock:
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


class SubdomainEnumerator:
    """Main class for subdomain enumeration operations."""

    def __init__(
        self,
        domain: str,
        wordlist: str,
        threads: int = 10,
        timeout: float = 3,
        max_retries: int = 2,
        rate_limit: int = 10,
        debug: bool = False,
        logging: bool = False,
        user_agent: Optional[str] = None,
        schemes: Optional[List[str]] = None,
    ):
        """
        Initialize subdomain enumerator with logging support.
        Args:
            domain (str): Base domain to enumerate
            wordlist (str): Path to wordlist file
            threads (int): Number of threads to use
            timeout (float): Request timeout in seconds
            max_retries (int): Maximum number of retry attempts
            rate_limit (int): Maximum requests per second
            debug (bool): Enable debug output
            logging (bool): Enable logging to file
            user_agent (str, optional): Custom User-Agent string
            schemes (List[str], optional): List of schemes to test (http/https)
        """
        if not domain:
            raise ValueError("Domain cannot be empty")

        self.domain = domain.lower().strip()
        self.wordlist = Path(wordlist)
        self.threads = max(1, min(threads, 50))  # Limit threads between 1 and 50
        self.timeout = max(1, timeout)  # Minimum 1 second timeout
        self.max_retries = max(0, max_retries)
        self.schemes = schemes or ["http", "https"]

        # Initialize components
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="subdomain_enum"
        )
        self.thread_manager = Threading(debug=debug, logging=logging)
        self.rate_limiter = RateLimiter(rate_limit)

        # Set up requests session
        self.session = requests.Session()
        if user_agent:
            self.session.headers["User-Agent"] = user_agent
        else:
            self.session.headers["User-Agent"] = "SubdomainEnumerator/1.0"
        self.session.verify = False  # Disable SSL verification
        
        # Suppress SSL warnings
        urllib3.disable_warnings(category=InsecureRequestWarning)

        # Results tracking
        self.results: Dict[str, Dict[str, Any]] = {}
        self.tested_subdomains: Set[str] = set()
        self.start_time = None
        self._lock = threading.Lock()

    def load_wordlist(self) -> List[str]:
        """Load and process the wordlist file."""
        if not self.wordlist.exists():
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist}")

        try:
            with self.wordlist.open("r", encoding="utf-8", errors="ignore") as f:
                subdomains = [line.strip().lower() for line in f if line.strip()]

            if not subdomains:
                raise ValueError("Wordlist is empty")

            self.logger.append_log(
                f"Loaded {len(subdomains)} subdomains from wordlist",
                "SUCCESS"
            )
            return subdomains

        except Exception as e:
            self.logger.append_log(f"Error loading wordlist: {str(e)}", "ERROR")
            raise

    def test_subdomain(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """
        Test a single subdomain for HTTP/HTTPS accessibility.
        Args:
            subdomain (str): Subdomain to test
        Returns:
            Optional[Dict[str, Any]]: Test results if subdomain is accessible
        """
        with self._lock:
            if subdomain in self.tested_subdomains:
                return None
            self.tested_subdomains.add(subdomain)

        full_domain = f"{subdomain}.{self.domain}"

        for scheme in self.schemes:
            target_url = f"{scheme}://{full_domain}"
            
            for attempt in range(self.max_retries + 1):
                try:
                    # Apply rate limiting
                    wait_time = self.rate_limiter.acquire()
                    if wait_time > 0 and self.logger.debug:
                        self.logger.append_log(
                            f"Rate limit applied, waiting {wait_time:.2f}s",
                            "DEBUG"
                        )

                    # Make request
                    start = time.time()
                    response = self.session.get(
                        target_url,
                        timeout=self.timeout,
                        allow_redirects=True,
                    )
                    elapsed = time.time() - start

                    # Process successful response
                    result = {
                        "subdomain": full_domain,
                        "url": target_url,
                        "scheme": scheme,
                        "status_code": response.status_code,
                        "response_time": elapsed,
                        "title": self._extract_title(response.text),
                        "redirect_url": response.url if response.history else None,
                        "server": response.headers.get("server", "Unknown"),
                        "content_type": response.headers.get("content-type", "Unknown"),
                    }

                    self.logger.append_log(
                        f"Found: {target_url} [{response.status_code}]",
                        "SUCCESS"
                    )
                    return result

                except (ConnectionError, Timeout) as e:
                    if attempt == self.max_retries:
                        if self.logger.debug:
                            self.logger.append_log(
                                f"Failed to connect to {target_url}: {str(e)}",
                                "DEBUG"
                            )
                    else:
                        time.sleep(0.5 * (attempt + 1))  # Exponential backoff
                except Exception as e:
                    if self.logger.debug:
                        self.logger.append_log(
                            f"Error testing {target_url}: {str(e)}",
                            "DEBUG"
                        )
                    break

        return None

    def _extract_title(self, html: str) -> str:
        """Extract title from HTML content."""
        try:
            pattern = r"<title>(.*?)</title>"
            title_match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
            return title_match.group(1).strip() if title_match else "No Title"
        except Exception:
            return "No Title"

    def enumerate(self) -> Dict[str, Dict[str, Any]]:
        """
        Perform subdomain enumeration using multiple threads.
        Returns:
            Dict[str, Dict[str, Any]]: Enumeration results
        """
        self.logger.start_section("Subdomain Enumeration")
        self.start_time = time.time()

        try:
            # Load subdomains
            subdomains = self.load_wordlist()
            self.logger.append_log(
                f"Starting enumeration of {len(subdomains)} subdomains using {self.threads} threads",
                "INFO"
            )

            # Perform threaded enumeration
            results = self.thread_manager.map_threaded(
                self.test_subdomain,
                subdomains,
                threads=self.threads
            )

            # Process results
            self.results = {
                result["subdomain"]: result
                for result in results
                if result is not None
            }

            return self.results

        except KeyboardInterrupt:
            self.logger.append_log("Enumeration interrupted by user", "WARNING")
            return self.results
        except Exception as e:
            self.logger.append_log(f"Enumeration failed: {str(e)}", "ERROR")
            raise

    def print_results(self) -> None:
        """Print formatted enumeration results and statistics."""
        if not hasattr(self, 'start_time') or self.start_time is None:
            self.logger.append_log("No scan has been performed yet", "WARNING")
            return

        scan_duration = time.time() - self.start_time
        tested_count = len(self.tested_subdomains)
        rate = tested_count / scan_duration if scan_duration > 0 else 0

        if not self.results:
            msg = f"No subdomains discovered. Tested {tested_count} subdomains in {scan_duration:.2f}s"
            self.logger.append_log(msg, "WARNING")
            return

        # Group results by status code
        results_by_status = {}
        for result in self.results.values():
            status = result["status_code"]
            if status not in results_by_status:
                results_by_status[status] = []
            results_by_status[status].append(result)

        # Print summary header
        summary = [
            f"\nSubdomain Enumeration Results for {self.domain}",
            "=" * 80,
            f"Total Subdomains Tested: {tested_count}",
            f"Subdomains Found: {len(self.results)}",
            f"Scan Duration: {scan_duration:.2f} seconds",
            f"Subdomains/Second: {rate:.2f}",
            "\nFindings by Status Code:",
            "-" * 30,
        ]

        # Print findings grouped by status code
        for status_code in sorted(results_by_status.keys()):
            findings = results_by_status[status_code]
            summary.extend([
                f"\nStatus Code {status_code} ({len(findings)} found):",
                "-" * 50
            ])

            for result in sorted(findings, key=lambda x: x["subdomain"]):
                url = result["url"]
                redirect = (
                    f" -> {result['redirect_url']}"
                    if result.get("redirect_url") and result["redirect_url"] != url
                    else ""
                )
                server = result["server"]
                resp_time = result["response_time"]
                title = result["title"]
                content_type = result["content_type"]

                summary.append(
                    f"{url}{redirect}\n"
                    f"  Title: {title}\n"
                    f"  Server: {server} | Content-Type: {content_type} | Response Time: {resp_time:.3f}s"
                )

        # Log the complete summary
        for line in summary:
            self.logger.append_log(line, "SUCCESS" if self.results else "WARNING")

    def cleanup(self) -> None:
        """Clean up resources."""
        try:
            self.session.close()
        except Exception as e:
            self.logger.append_log(f"Error during cleanup: {str(e)}", "ERROR")
        finally:
            if self.logger.file_logging:
                self.logger.generate_log()


def main():
    # Define argument configuration
    arg_config = {
        "script": {
            "name": "SubdomainEnumerator.py",
            "description": "Subdomain Enumeration Tool",
        },
        "args": {
            "domain": {
                "help": "Base domain to enumerate",
                "positional": True
            },
            "wordlist": {
                "flag": "-w",
                "default": "WordLists/subdomains-top1million-5000.txt",
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
                "default": 3,
                "help": "Request timeout in seconds",
            },
            "max_retries": {
                "flag": "--max-retries",
                "type": int,
                "default": 2,
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
            "user_agent": {
                "flag": "--user-agent",
                "help": "Custom User-Agent string",
            },
            "schemes": {
                "flag": "--schemes",
                "default": "http,https",
                "help": "Comma-separated list of schemes to test",
            },
        },
    }

    # Parse arguments
    arg_handler = ArgumentHandler(arg_config)
    args = arg_handler.parse_args()

    # Initialize enumerator
    enumerator = None
    try:
        # Process schemes
        schemes = [s.strip().lower() for s in args.schemes.split(",")]

        # Initialize enumerator with parsed arguments
        enumerator = SubdomainEnumerator(
            domain=args.domain,
            wordlist=args.wordlist,
            threads=args.threads,
            timeout=args.timeout,
            max_retries=args.max_retries,
            rate_limit=args.rate_limit,
            debug=args.debug,
            logging=args.logging,
            user_agent=args.user_agent,
            schemes=schemes,
        )

        # Run the enumeration
        enumerator.enumerate()

        # Print results
        enumerator.print_results()

    except KeyboardInterrupt:
        if enumerator and enumerator.logger:
            enumerator.logger.append_log("\nEnumeration interrupted by user", "WARNING")
    except Exception as e:
        if enumerator and enumerator.logger:
            enumerator.logger.append_log(f"Fatal error: {str(e)}", "ERROR")
            if args.debug:
                import traceback
                enumerator.logger.append_log(traceback.format_exc(), "ERROR")
        sys.exit(1)
    finally:
        if enumerator:
            enumerator.cleanup()


if __name__ == "__main__":
    main()
