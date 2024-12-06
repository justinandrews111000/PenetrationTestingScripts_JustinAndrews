"""
Common utility functions and classes for network, web, logging, threading, and system operations.
"""

import argparse
import concurrent.futures
import datetime
import hashlib
import ipaddress
import json
import os
import platform
import subprocess
import threading
from pathlib import Path
from socket import gethostname
from time import gmtime, mktime, sleep, time
from typing import Any, Dict, List, Optional, Tuple, Union

import colorama
from colorama import Fore, Style
from OpenSSL import SSL, crypto
from selenium import webdriver
from selenium.common.exceptions import (NoAlertPresentException,
                                        NoSuchElementException,
                                        StaleElementReferenceException,
                                        TimeoutException, WebDriverException)
from selenium.webdriver.chrome.options import Options  # Added this import
from selenium.webdriver.chrome.service import \
    Service  # You might need this too
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# Initialize colorama
colorama.init(autoreset=True)


class LoggingPipeline:
    """Enhanced pipeline for collecting and managing logs with support for both console and file output."""

    def __init__(
        self, debug: bool = False, logging: bool = False, log_name: Optional[str] = None
    ):
        """
        Initialize logging pipeline.
        Args:
            debug (bool): Enable debug output
            logging (bool): Enable file logging
            log_name (str, optional): Custom name for log file. If None, generates timestamp-based name
        """
        self.debug = debug
        self.file_logging = logging
        self.log_list: List[str] = []
        self._write_lock = threading.Lock()

        if self.file_logging:
            self.log_name = log_name or datetime.datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )
            self.log_dir = Path("./Logs")
            self.log_dir.mkdir(exist_ok=True)
            self.log_path = self.log_dir / f"{self.log_name}.log"

    def _should_display(self, level: str) -> bool:
        """Determine if a message should be displayed based on debug setting and level."""
        if level == "DEBUG" and not self.debug:
            return False
        if (
            level == "SYSTEM" and not self.debug
        ):  # For system messages like WebDriver initialization
            return False
        return True

    def _atomic_write(self, message: str, level: str = "INFO") -> None:
        """
        Ensure atomic writing of messages.
        Args:
            message (str): Message to write
            level (str): Message level (affects color)
        """
        if not self._should_display(level):
            return

        color_code = {
            "ERROR": Fore.RED,
            "WARNING": Fore.YELLOW,
            "DEBUG": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "INFO": Fore.WHITE,
            "SYSTEM": Fore.BLUE,
        }.get(level.upper(), Fore.WHITE)

        with self._write_lock:
            formatted_msg = f"{color_code}{message}{Style.RESET_ALL}"
            print(f"{formatted_msg}\n", end="", flush=True)

    def append_log(
        self, entry: Union[str, List[str], Dict[str, Any]], level: str = "INFO"
    ) -> None:
        """
        Add entries to the log with level-appropriate formatting.
        Args:
            entry: Log entry content
            level: Log level (ERROR, WARNING, DEBUG, SUCCESS, INFO, SYSTEM)
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        def process_entry(item: Union[str, Dict[str, Any]]) -> str:
            """Process a single entry and return formatted string."""
            if isinstance(item, dict):
                content = json.dumps(item)
            else:
                content = str(item)
            return f"[{level}] [{timestamp}] {content}"

        if isinstance(entry, list):
            for item in entry:
                formatted_msg = process_entry(item)
                if self.file_logging:
                    self.log_list.append(formatted_msg)
                self._atomic_write(formatted_msg, level)
        else:
            formatted_msg = process_entry(entry)
            if self.file_logging:
                self.log_list.append(formatted_msg)
            self._atomic_write(formatted_msg, level)

    def start_section(self, name: str) -> None:
        """
        Start a new logical section in the logs.
        Args:
            name (str): Section name
        """
        divider = "═" * 80
        if self.file_logging:
            self.log_list.extend([divider, f"Starting {name}", "─" * 80])

        self._atomic_write(divider, "SYSTEM")
        self._atomic_write(f"Starting {name}", "INFO")
        self._atomic_write("─" * 80, "SYSTEM")

    def end_section(self, summary: Optional[str] = None) -> None:
        """
        End the current logical section.
        Args:
            summary (str, optional): Section summary
        """
        if summary:
            self.append_log(summary)

        divider = "═" * 80
        if self.file_logging:
            self.log_list.append(divider)
        self._atomic_write(divider, "SYSTEM")

    def print_final_summary(self, summary: str, color_formatted: bool = False) -> None:
        """
        Print a final summary, optionally with color formatting.
        Args:
            summary (str): Summary text
            color_formatted (bool): Whether the summary already contains color codes
        """
        if self.file_logging:
            # Strip color codes for file logging if present
            clean_summary = summary
            if color_formatted:
                # Add logic to strip ANSI color codes for file logging
                import re

                clean_summary = re.compile(r"\x1b[^m]*m").sub("", summary)
            self.log_list.append(clean_summary)
            self.generate_log()

        # Print to console
        print(summary)

    def generate_log(self) -> None:
        """Write collected logs to file if file logging is enabled."""
        if not self.file_logging or not self.log_list:
            return

        with self.log_path.open(mode="a", encoding="utf-8") as log_file:
            log_file.write(f"\nLog started on {datetime.datetime.now()}\n")
            for entry in self.log_list:
                log_file.write(f"{entry}\n")

        self.log_list.clear()

    def clear(self) -> None:
        """Clear the current log buffer."""
        self.log_list.clear()


class Threading:
    """Utility class for managing threaded operations."""

    def __init__(self, debug: bool = False, logging: bool = False):
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="threading"
        )

    def start_threads(self, job_func, job_args=None, threads: int = 10):
        """Start multiple threads for a given job function."""
        self.logger.append_log(
            f"Starting {threads} threads for {job_func.__name__}", "INFO"
        )

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            if job_args:
                futures = [
                    (
                        executor.submit(job_func, *args)
                        if isinstance(args, tuple)
                        else executor.submit(job_func, args)
                    )
                    for args in job_args
                ]
            else:
                futures = [executor.submit(job_func) for _ in range(threads)]

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    self.logger.append_log(
                        f"Thread completed with result: {result}", "SUCCESS"
                    )
                except Exception as e:
                    self.logger.append_log(
                        f"Thread failed with error: {str(e)}", "ERROR"
                    )
                    results.append(None)

        return results

    def map_threaded(self, func, items, threads: int = 10):
        """Map a function across items using multiple threads."""
        self.logger.append_log(
            f"Starting threaded map of {func.__name__} across {len(items)} items",
            "INFO",
        )

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_item = {executor.submit(func, item): item for item in items}

            for future in concurrent.futures.as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.logger.append_log(
                        f"Processed item {item} with result: {result}", "SUCCESS"
                    )
                except Exception as e:
                    self.logger.append_log(
                        f"Failed to process item {item}: {str(e)}", "ERROR"
                    )
                    results.append(None)

        return results


class NetworkScanner:
    """Utility for network scanning operations."""

    def __init__(self, debug: bool = False, logging: bool = False):
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="network_scanner"
        )
        self.system = SystemCommand(debug=debug, logging=logging)

    def ping(self, ip: str, timeout: int) -> Dict[str, Union[str, bool]]:
        """Ping a single IP address."""
        self.logger.append_log(f"Pinging {ip} with timeout {timeout}s", "DEBUG")

        command = (
            ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
            if platform.system().lower() == "windows"
            else ["ping", "-c", "1", "-W", str(timeout), ip]
        )

        try:
            result = subprocess.run(
                command, text=True, capture_output=True, check=False
            )
            success = result.returncode == 0

            if success:
                self.logger.append_log(f"Ping to {ip} successful", "SUCCESS")
            else:
                self.logger.append_log(f"Ping to {ip} failed", "WARNING")

            return {
                "ip": ip,
                "success": success,
                "output": result.stdout if success else result.stderr,
            }
        except subprocess.SubprocessError as e:
            self.logger.append_log(f"Ping error for {ip}: {str(e)}", "ERROR")
            return {"ip": ip, "success": False, "output": str(e)}

    def scan_network(
        self, network: str, timeout: int = 1, threads: int = 10
    ) -> List[Dict[str, Union[str, bool]]]:
        """Perform a threaded network scan."""
        self.logger.append_log(f"Starting network scan of {network}", "INFO")

        try:
            net = ipaddress.ip_network(network)
        except ValueError as e:
            self.logger.append_log(f"Invalid network address: {e}", "ERROR")
            raise ValueError(f"Invalid network address: {e}")

        self.logger.append_log(
            f"Scanning {len(list(net.hosts()))} hosts with {threads} threads", "DEBUG"
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self.ping, str(ip), timeout): str(ip)
                for ip in net.hosts()
            }

            results = []
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
                if result["success"]:
                    self.logger.append_log(f"Host {result['ip']} is up", "SUCCESS")
                else:
                    self.logger.append_log(f"Host {result['ip']} is down", "WARNING")

        successful_pings = sum(1 for r in results if r["success"])
        self.logger.append_log(
            f"Scan complete. {successful_pings}/{len(results)} hosts responded", "INFO"
        )

        return results


class SystemCommand:
    """Utility for executing system commands with enhanced interactive support."""

    def __init__(self, debug: bool = False, logging: bool = False):
        self.os_type = platform.system().lower()
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="system_command"
        )

    def execute(
        self,
        command: List[str],
        stdin_input: Optional[str] = None,
        interactive: bool = False,
        timeout: Optional[int] = None,
    ) -> Union[str, Tuple[str, str], int]:
        """
        Execute a system command and return the output.

        Args:
            command (List[str]): Command and arguments as list
            stdin_input (Optional[str]): Input to be sent to command's stdin
            interactive (bool): Whether to use interactive mode (Popen with pipes)
            timeout (Optional[int]): Command timeout in seconds

        Returns:
            Union[str, Tuple[str, str], int]:
                - For non-interactive: command output string or error code
                - For interactive: tuple of (stdout, stderr) or error code
        """
        self.logger.append_log(f"Executing command: {' '.join(command)}", "DEBUG")
        if stdin_input:
            self.logger.append_log(f"With stdin input:\n{stdin_input}", "DEBUG")

        try:
            if interactive:
                # Interactive mode with stdin/stdout pipes
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                try:
                    stdout, stderr = process.communicate(
                        input=stdin_input, timeout=timeout
                    )

                    if stdout:
                        self.logger.append_log("Command stdout:", "DEBUG")
                        self.logger.append_log(stdout, "DEBUG")
                    if stderr:
                        self.logger.append_log("Command stderr:", "DEBUG")
                        self.logger.append_log(stderr, "DEBUG")

                    if process.returncode == 0:
                        self.logger.append_log(
                            "Interactive command executed successfully", "SUCCESS"
                        )
                    else:
                        self.logger.append_log(
                            f"Interactive command failed with code: {process.returncode}",
                            "WARNING",
                        )

                    return stdout, stderr

                except subprocess.TimeoutExpired:
                    process.kill()
                    self.logger.append_log(
                        f"Command timed out after {timeout} seconds", "ERROR"
                    )
                    return -1

            else:
                # Non-interactive mode using check_output
                result = subprocess.run(
                    command, text=True, capture_output=True, timeout=timeout, check=True
                )
                self.logger.append_log("Command executed successfully", "SUCCESS")
                return result.stdout

        except subprocess.SubprocessError as e:
            self.logger.append_log(f"Command failed: {str(e)}", "ERROR")
            return -1

        except Exception as e:
            self.logger.append_log(f"Unexpected error: {str(e)}", "ERROR")
            return -1


class ArgumentHandler:
    """Utility for handling command-line arguments based on a configuration dictionary."""

    def __init__(self, config: dict, debug: bool = False, logging: bool = False):
        self.config = config
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="argument_handler"
        )
        self._validate_config()
        self.parser = self._create_parser()

    def _validate_config(self) -> None:
        """Validate the configuration dictionary."""
        required_keys = {"script", "args"}
        script_keys = {"name", "description"}

        if not all(key in self.config for key in required_keys):
            raise ValueError(f"Config must contain keys: {required_keys}")

        if not all(key in self.config["script"] for key in script_keys):
            raise ValueError(f"Script config must contain keys: {script_keys}")

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser based on configuration."""
        self.logger.append_log("Creating argument parser", "DEBUG")

        parser = argparse.ArgumentParser(
            prog=self.config["script"]["name"],
            description=self.config["script"]["description"],
        )

        for arg_name, arg_config in self.config["args"].items():
            positional = arg_config.pop("positional", False)
            flag = arg_config.pop("flag", None)

            if positional:
                parser.add_argument(arg_name, **arg_config)
            else:
                flags = []
                if flag:
                    flags.append(flag)
                flags.append(f"--{arg_name}")
                parser.add_argument(*flags, **arg_config)

        return parser

    def parse_args(self) -> argparse.Namespace:
        """Parse command line arguments."""
        self.logger.append_log("Parsing command line arguments", "DEBUG")
        args = self.parser.parse_args()
        self.logger.append_log(f"Parsed arguments: {vars(args)}", "DEBUG")
        return args


class WebDriver:
    """Enhanced WebDriver class for web automation, testing, and form interaction."""

    def __init__(
        self,
        url: str,
        headless: bool = True,
        debug: bool = False,
        logging: bool = False,
        scan_forms: bool = False,
        page_load_timeout: int = 30,
        implicit_wait: int = 10,
    ):
        """
        Initialize WebDriver with enhanced configuration options.

        Args:
            url (str): Starting URL to load
            headless (bool): Run browser in headless mode
            debug (bool): Enable debug output
            logging (bool): Enable logging to file
            scan_forms (bool): Automatically scan for forms on page load
            page_load_timeout (int): Timeout for page loads in seconds
            implicit_wait (int): Implicit wait time in seconds
        """
        self.url = url
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="webdriver"
        )
        self.forms = {}
        self.driver = None
        self.form_responses = {}  # Dictionary to store form responses

        try:
            self._setup_driver(
                headless=headless,
                page_load_timeout=page_load_timeout,
                implicit_wait=implicit_wait,
            )
            self._initial_page_load(scan_forms)
            self.logger.append_log("WebDriver initialized successfully", "SUCCESS")
        except Exception as e:
            self.logger.append_log(
                f"WebDriver initialization failed: {str(e)}", "ERROR"
            )
            self.cleanup()
            raise

    def _setup_driver(
        self, headless: bool, page_load_timeout: int, implicit_wait: int
    ) -> None:
        """Set up Chrome WebDriver with specified options."""
        options = Options()
        if headless:
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")

        # Basic security and stability options
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-notifications")
        options.add_argument("--ignore-certificate-errors")

        self.driver = webdriver.Chrome(options=options)
        self.driver.set_page_load_timeout(page_load_timeout)
        self.driver.implicitly_wait(implicit_wait)
        self.driver.set_script_timeout(page_load_timeout)

    def _initial_page_load(self, scan_forms: bool) -> None:
        """Handle initial page load and optional form scanning."""
        if not self._load_page(self.url):
            raise WebDriverException(f"Failed to load initial URL: {self.url}")

        if scan_forms:
            self.forms = self._get_form_details()

    def _load_page(self, url: str, max_retries: int = 3) -> bool:
        """
        Load a page with retry mechanism.

        Args:
            url (str): URL to load
            max_retries (int): Maximum number of retry attempts

        Returns:
            bool: True if successful, False otherwise
        """
        for attempt in range(max_retries):
            try:
                self.driver.get(url)
                return True
            except Exception as e:
                self.logger.append_log(
                    f"Attempt {attempt + 1}/{max_retries} failed to load {url}: {str(e)}",
                    "WARNING" if attempt < max_retries - 1 else "ERROR",
                )
                if attempt < max_retries - 1:
                    sleep(2)  # Wait before retry
        return False

    def _get_form_details(self) -> Dict[str, Dict[str, Any]]:
        """Get detailed information about all forms on the page."""
        try:
            # First get all forms
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            form_details = {}

            self.logger.append_log(f"Found {len(forms)} forms to analyze", "DEBUG")

            for index, form in enumerate(forms):
                try:
                    # Try multiple ways to identify the form
                    form_id = form.get_attribute("id")
                    form_name = form.get_attribute("name")
                    form_action = form.get_attribute("action")

                    # Use the first available identifier or generate one
                    form_identifier = form_id or form_name or f"form_{index}"

                    self.logger.append_log(
                        f"Processing form {form_identifier} "
                        f"(id: {form_id}, name: {form_name}, action: {form_action})",
                        "DEBUG",
                    )

                    form_details[form_identifier] = self._get_single_form_details(form)

                except StaleElementReferenceException:
                    continue

        except Exception as e:
            self.logger.append_log(
                f"Error processing form {index}: {str(e)}", "WARNING"
            )

        return form_details

    def _get_single_form_details(self, form) -> Dict[str, Any]:
        """
        Extract details from a single form element.

        Args:
            form: WebElement representing the form

        Returns:
            Dict[str, Any]: Form details including inputs and attributes
        """
        details = {
            "action": form.get_attribute("action") or "",
            "method": form.get_attribute("method") or "get",
            "inputs": [],
        }

        # Process standard input fields
        for input_tag in form.find_elements(By.TAG_NAME, "input"):
            input_details = {
                "type": input_tag.get_attribute("type") or "text",
                "name": input_tag.get_attribute("name"),
                "id": input_tag.get_attribute("id"),
                "value": input_tag.get_attribute("value") or "",
                "class": input_tag.get_attribute("class"),
            }
            details["inputs"].append(input_details)

        # Process select fields
        for select in form.find_elements(By.TAG_NAME, "select"):
            select_details = {
                "type": "select",
                "name": select.get_attribute("name"),
                "id": select.get_attribute("id"),
                "options": [],
            }

            for option in select.find_elements(By.TAG_NAME, "option"):
                select_details["options"].append(
                    {
                        "value": option.get_attribute("value"),
                        "text": option.text,
                        "selected": option.is_selected(),
                    }
                )

            details["inputs"].append(select_details)

        return details

    def test_form_submission(self, form_name: str, payload: str) -> Dict[str, Any]:
        """
        Test a specific form with a payload and return the response.

        Args:
            form_name (str): Name/ID of the form to test
            payload (str): Payload to submit to the form
        """
        if form_name not in self.forms:
            self.logger.append_log(f"Form {form_name} not found", "ERROR")
            return None

        form_details = self.forms[form_name]

        # Log current URL before starting
        current_url = self.get_current_url()
        self.logger.append_log(f"Current URL before test: {current_url}", "DEBUG")

        # Navigate back to original URL if needed
        if current_url != self.url:
            self.logger.append_log(f"Navigating back to: {self.url}", "DEBUG")
            self._load_page(self.url)
            # Wait for page load
            sleep(2)
            self.logger.append_log(
                f"New URL after navigation: {self.get_current_url()}", "DEBUG"
            )

        try:
            # Get form method and log URL before form interaction
            form_method = form_details.get("method", "get").lower()
            self.logger.append_log(
                f"URL before finding form: {self.get_current_url()}", "DEBUG"
            )
            self.logger.append_log(
                f"Attempting to find form: {form_name} with method: {form_method}",
                "DEBUG",
            )

            # Find the form
            form = None
            try:
                form = self.driver.find_element(By.ID, form_name)
                self.logger.append_log(f"Found form by ID: {form_name}", "DEBUG")
            except:
                try:
                    form = self.driver.find_element(By.NAME, form_name)
                    self.logger.append_log(f"Found form by NAME: {form_name}", "DEBUG")
                except:
                    self.logger.append_log(
                        f"Failed to find form by ID or NAME", "ERROR"
                    )
                    self.logger.append_log(
                        f"Current page content: {self.get_page_source()[:500]}...",
                        "DEBUG",
                    )
                    raise

            if not form:
                self.logger.append_log(f"Could not locate form {form_name}", "ERROR")
                return None

            self.logger.append_log(
                f"URL after finding form: {self.get_current_url()}", "DEBUG"
            )

            # Fill all text-like inputs with the payload
            for input_info in form_details["inputs"]:
                if input_info.get("type") in [
                    "text",
                    "password",
                    "username",
                    "email",
                    "search",
                ]:
                    try:
                        input_element = None
                        if input_info.get("id"):
                            input_element = form.find_element(By.ID, input_info["id"])
                            self.logger.append_log(
                                f"Found input by ID: {input_info['id']}", "DEBUG"
                            )
                        elif input_info.get("name"):
                            input_element = form.find_element(
                                By.NAME, input_info["name"]
                            )
                            self.logger.append_log(
                                f"Found input by NAME: {input_info['name']}", "DEBUG"
                            )

                        if input_element:
                            input_element.clear()
                            input_element.send_keys(payload)
                            self.logger.append_log(
                                f"Filled input {input_info.get('name', input_info.get('id'))} with payload",
                                "DEBUG",
                            )
                    except Exception as e:
                        self.logger.append_log(
                            f"Error filling input {input_info}: {str(e)}", "DEBUG"
                        )

            self.logger.append_log(
                f"URL before submission: {self.get_current_url()}", "DEBUG"
            )

            # Submit based on method
            response = {
                "method": form_method,
                "payload": payload,
                "timestamp": datetime.datetime.now().isoformat(),
            }

            # Find and click submit button
            submit_button = None
            try:
                submit_button = form.find_element(
                    By.CSS_SELECTOR, 'input[type="submit"], button[type="submit"]'
                )
                self.logger.append_log("Found submit button", "DEBUG")
            except:
                # If no submit button found, try submitting the form directly
                self.logger.append_log(
                    "No submit button found, attempting direct form submission", "DEBUG"
                )

            if submit_button:
                submit_button.click()
                self.logger.append_log(
                    "Form submitted via submit button click", "DEBUG"
                )
            else:
                form.submit()
                self.logger.append_log("Form submitted directly", "DEBUG")

            # Wait for potential page load
            sleep(2)

            # Capture final state
            final_url = self.get_current_url()
            self.logger.append_log(f"URL after submission: {final_url}", "DEBUG")

            # Capture response data
            response.update(
                {
                    "url_changed": final_url != current_url,
                    "new_url": final_url,
                    "response_content": self.get_page_source(),
                    "status_code": 200,  # Default to 200 if we got here
                }
            )

            return response

        except Exception as e:
            self.logger.append_log(f"Error testing form {form_name}: {str(e)}", "ERROR")
            self.logger.append_log(
                f"URL when error occurred: {self.get_current_url()}", "DEBUG"
            )
            self.logger.append_log(
                f"Page content when error occurred: {self.get_page_source()[:500]}...",
                "DEBUG",
            )
            return None

    def capture_form_baseline(
        self, form_name: str, baseline_value: str = "test123"
    ) -> Dict[str, Any]:
        """
        Capture a baseline response for a form using a neutral value.

        Args:
            form_name (str): Name/ID of the form to test
            baseline_value (str): Neutral value to use for baseline

        Returns:
            Dict[str, Any]: Baseline response data
        """
        self.logger.append_log(f"Capturing baseline for form {form_name}", "DEBUG")
        return self.test_form_submission(form_name, baseline_value)

    def get_detailed_form_info(self, form_name: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific form.

        Args:
            form_name (str): Name/ID of the form to analyze

        Returns:
            Dict[str, Any]: Detailed form information
        """
        if form_name not in self.forms:
            return None

        form_details = self.forms[form_name]

        # Find the actual form element
        try:
            form = self.driver.find_element(By.ID, form_name)
            if not form:
                form = self.driver.find_element(By.NAME, form_name)
        except:
            return form_details

        # Enhance the existing form details
        enhanced_details = form_details.copy()
        enhanced_details.update(
            {
                "html": form.get_attribute("outerHTML"),
                "action": form.get_attribute("action") or "",
                "method": form.get_attribute("method") or "get",
                "enctype": form.get_attribute("enctype") or "",
                "submit_button": None,
            }
        )

        # Find submit button details
        try:
            submit_button = form.find_element(
                By.CSS_SELECTOR, 'input[type="submit"], button[type="submit"]'
            )
            if submit_button:
                enhanced_details["submit_button"] = {
                    "id": submit_button.get_attribute("id"),
                    "name": submit_button.get_attribute("name"),
                    "value": submit_button.get_attribute("value"),
                    "type": submit_button.get_attribute("type"),
                }
        except:
            pass

        return enhanced_details

    def wait_for_element(
        self, by: By, value: str, timeout: int = 10, condition: str = "presence"
    ) -> Optional[Any]:
        """
        Wait for an element with specified conditions.

        Args:
            by (By): Selenium By locator strategy
            value (str): Value to locate element
            timeout (int): Maximum wait time in seconds
            condition (str): Wait condition ('presence' or 'clickable')

        Returns:
            Optional[Any]: WebElement if found, None otherwise
        """
        try:
            wait = WebDriverWait(self.driver, timeout)
            if condition == "clickable":
                element = wait.until(EC.element_to_be_clickable((by, value)))
            else:
                element = wait.until(EC.presence_of_element_located((by, value)))
            return element
        except TimeoutException:
            self.logger.append_log(f"Timeout waiting for element: {value}", "WARNING")
            return None
        except Exception as e:
            self.logger.append_log(f"Error waiting for element: {str(e)}", "ERROR")
            return None

    def execute_script(self, script: str, *args) -> Optional[Any]:
        """
        Execute JavaScript in the current window/frame.

        Args:
            script (str): JavaScript to execute
            *args: Arguments to pass to the script

        Returns:
            Optional[Any]: Result of script execution if any
        """
        try:
            return self.driver.execute_script(script, *args)
        except Exception as e:
            self.logger.append_log(f"Script execution error: {str(e)}", "ERROR")
            return None

    def get_current_url(self) -> str:
        """Get the current URL of the browser."""
        return self.driver.current_url if self.driver else ""

    def get_page_source(self) -> str:
        """Get the current page source."""
        return self.driver.page_source if self.driver else ""

    def navigate(self, url: str) -> bool:
        """
        Navigate to a specific URL.

        Args:
            url (str): URL to navigate to

        Returns:
            bool: True if successful, False otherwise
        """
        return self._load_page(url)

    def cleanup(self) -> None:
        """Clean up resources and close the browser."""
        if self.driver:
            try:
                self.driver.quit()
            except Exception as e:
                self.logger.append_log(f"Error during cleanup: {str(e)}", "ERROR")
            finally:
                self.driver = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()

    def close(self) -> None:
        """Alias for cleanup() for compatibility."""
        self.cleanup()


class Cryptography:
    """Utility class for cryptographic operations including hashing, encryption, and key management."""

    def __init__(self, debug: bool = False, logging: bool = False):
        """Initialize cryptography utilities with logging support."""
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="cryptography"
        )
        self._available_hash_algorithms = sorted(hashlib.algorithms_available)
        self.logger.append_log(
            f"Initialized cryptography utilities with {len(self._available_hash_algorithms)} available hash algorithms",
            "INFO",
        )

    def get_available_algorithms(self) -> List[str]:
        """Return list of available hashing algorithms."""
        return self._available_hash_algorithms

    def hash_file(
        self, filename: str, algorithm: str = "sha256", chunk_size: int = 4096
    ) -> Optional[str]:
        """
        Calculate the hash of a file using the specified algorithm.

        Args:
            filename (str): Path to the file to be hashed
            algorithm (str): Name of the hashing algorithm (default: sha256)
            chunk_size (int): Size of chunks to read (default: 4096)

        Returns:
            Optional[str]: Hexadecimal digest of the file hash, or None if error occurs
        """
        self.logger.append_log(
            f"Attempting to hash file '{filename}' using {algorithm}", "DEBUG"
        )

        if algorithm not in self._available_hash_algorithms:
            self.logger.append_log(f"Invalid algorithm '{algorithm}'", "ERROR")
            raise ValueError(
                f"Invalid algorithm. Available algorithms: {', '.join(self._available_hash_algorithms)}"
            )

        try:
            hash_obj = hashlib.new(algorithm)

            with open(filename, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    hash_obj.update(chunk)

            file_hash = hash_obj.hexdigest()
            self.logger.append_log(f"Successfully hashed file '{filename}'", "SUCCESS")
            return file_hash

        except IOError as e:
            self.logger.append_log(
                f"Error reading file '{filename}': {str(e)}", "ERROR"
            )
            return None
        except Exception as e:
            self.logger.append_log(
                f"Unexpected error while hashing file: {str(e)}", "ERROR"
            )
            return None

    def hash_string(
        self, text: str, algorithm: str = "sha256", encoding: str = "utf-8"
    ) -> Optional[str]:
        """
        Calculate the hash of a string using the specified algorithm.

        Args:
            text (str): Text to hash
            algorithm (str): Name of the hashing algorithm (default: sha256)
            encoding (str): Text encoding to use (default: utf-8)

        Returns:
            Optional[str]: Hexadecimal digest of the string hash, or None if error occurs
        """
        self.logger.append_log(f"Hashing string using {algorithm}", "DEBUG")

        if algorithm not in self._available_hash_algorithms:
            self.logger.append_log(f"Invalid algorithm '{algorithm}'", "ERROR")
            raise ValueError(
                f"Invalid algorithm. Available algorithms: {', '.join(self._available_hash_algorithms)}"
            )

        try:
            hash_obj = hashlib.new(algorithm)
            hash_obj.update(text.encode(encoding))
            return hash_obj.hexdigest()

        except Exception as e:
            self.logger.append_log(f"Error hashing string: {str(e)}", "ERROR")
            return None

    def verify_file_hash(
        self, filename: str, expected_hash: str, algorithm: str = "sha256"
    ) -> bool:
        """
        Verify if a file matches an expected hash value.

        Args:
            filename (str): Path to the file to verify
            expected_hash (str): Expected hash value
            algorithm (str): Name of the hashing algorithm (default: sha256)

        Returns:
            bool: True if the file hash matches the expected hash, False otherwise
        """
        self.logger.append_log(f"Verifying hash of file '{filename}'", "DEBUG")

        actual_hash = self.hash_file(filename, algorithm)
        if not actual_hash:
            return False

        matches = actual_hash.lower() == expected_hash.lower()
        if matches:
            self.logger.append_log(
                f"Hash verification successful for '{filename}'", "SUCCESS"
            )
        else:
            self.logger.append_log(
                f"Hash verification failed for '{filename}'\n"
                f"Expected: {expected_hash}\n"
                f"Actual: {actual_hash}",
                "WARNING",
            )
        return matches

    def hash_directory(
        self, directory: str, algorithm: str = "sha256"
    ) -> Dict[str, str]:
        """
        Calculate hashes for all files in a directory.

        Args:
            directory (str): Path to the directory
            algorithm (str): Name of the hashing algorithm (default: sha256)

        Returns:
            Dict[str, str]: Dictionary mapping filenames to their hashes
        """
        self.logger.append_log(f"Hashing directory '{directory}'", "DEBUG")
        results = {}

        try:
            for root, _, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    file_hash = self.hash_file(filepath, algorithm)
                    if file_hash:
                        results[filepath] = file_hash

            self.logger.append_log(
                f"Successfully hashed {len(results)} files in directory '{directory}'",
                "SUCCESS",
            )
            return results

        except Exception as e:
            self.logger.append_log(f"Error hashing directory: {str(e)}", "ERROR")
            return results

    def compare_files(self, file1: str, file2: str, algorithm: str = "sha256") -> bool:
        """
        Compare two files by their hash values.

        Args:
            file1 (str): Path to first file
            file2 (str): Path to second file
            algorithm (str): Name of the hashing algorithm (default: sha256)

        Returns:
            bool: True if files have matching hashes, False otherwise
        """
        self.logger.append_log(f"Comparing files '{file1}' and '{file2}'", "DEBUG")

        hash1 = self.hash_file(file1, algorithm)
        hash2 = self.hash_file(file2, algorithm)

        if hash1 is None or hash2 is None:
            return False

        matches = hash1 == hash2
        if matches:
            self.logger.append_log("Files match", "SUCCESS")
        else:
            self.logger.append_log("Files do not match", "WARNING")
        return matches

    def generate_file_manifest(
        self, directory: str, output_file: str, algorithm: str = "sha256"
    ) -> bool:
        """
        Generate a manifest file containing hashes of all files in a directory.

        Args:
            directory (str): Path to the directory
            output_file (str): Path to write the manifest file
            algorithm (str): Name of the hashing algorithm (default: sha256)

        Returns:
            bool: True if manifest was generated successfully, False otherwise
        """
        self.logger.append_log(
            f"Generating manifest for directory '{directory}'", "DEBUG"
        )

        try:
            hashes = self.hash_directory(directory, algorithm)

            with open(output_file, "w") as f:
                json.dump(
                    {
                        "algorithm": algorithm,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "files": hashes,
                    },
                    f,
                    indent=4,
                )

            self.logger.append_log(
                f"Successfully generated manifest for {len(hashes)} files", "SUCCESS"
            )
            return True

        except Exception as e:
            self.logger.append_log(f"Error generating manifest: {str(e)}", "ERROR")
            return False

    def verify_against_manifest(
        self, directory: str, manifest_file: str
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        Verify files in a directory against a manifest file.

        Args:
            directory (str): Path to the directory to verify
            manifest_file (str): Path to the manifest file

        Returns:
            Tuple[List[str], List[str], List[str]]: Lists of matched, modified, and missing files
        """
        self.logger.append_log(
            f"Verifying directory '{directory}' against manifest", "DEBUG"
        )

        try:
            with open(manifest_file, "r") as f:
                manifest = json.load(f)

            algorithm = manifest.get("algorithm", "sha256")
            expected_hashes = manifest["files"]

            matched_files = []
            modified_files = []
            missing_files = []

            # Check each file in the manifest
            for filepath, expected_hash in expected_hashes.items():
                full_path = os.path.join(
                    directory, os.path.relpath(filepath, directory)
                )

                if not os.path.exists(full_path):
                    missing_files.append(filepath)
                    continue

                actual_hash = self.hash_file(full_path, algorithm)
                if actual_hash == expected_hash:
                    matched_files.append(filepath)
                else:
                    modified_files.append(filepath)

            self.logger.append_log(
                f"Verification complete:\n"
                f"Matched: {len(matched_files)}\n"
                f"Modified: {len(modified_files)}\n"
                f"Missing: {len(missing_files)}",
                "SUCCESS" if not (modified_files or missing_files) else "WARNING",
            )

            return matched_files, modified_files, missing_files

        except Exception as e:
            self.logger.append_log(
                f"Error verifying against manifest: {str(e)}", "ERROR"
            )
            return [], [], []

    def gen_self_signed_cert(
        self,
        emailAddress="emailAddress",
        commonName="commonName",
        countryName="NT",
        localityName="localityName",
        stateOrProvinceName="stateOrProvinceName",
        organizationName="organizationName",
        organizationUnitName="organizationUnitName",
        serialNumber=0,
        validityStartInSeconds=0,
        validityEndInSeconds=10 * 365 * 24 * 60 * 60,
        KEY_FILE=r"C:/Users/justi/PenetrationTestingScripts_JustinAndrews/RSA/private.key",
        CERT_FILE=r"C:/Users/justi/PenetrationTestingScripts_JustinAndrews/RSA/selfsigned.crt",
    ):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

        cert = crypto.X509()
        cert.get_subject().C = countryName
        cert.get_subject().ST = stateOrProvinceName
        cert.get_subject().L = localityName
        cert.get_subject().O = organizationName
        cert.get_subject().OU = organizationUnitName
        cert.get_subject().CN = commonName
        cert.get_subject().emailAddress = emailAddress
        cert.set_serial_number(serialNumber)
        cert.gmtime_adj_notBefore(validityStartInSeconds)
        cert.gmtime_adj_notAfter(validityEndInSeconds)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, "sha512")
        with open(CERT_FILE, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        with open(KEY_FILE, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))
        return [CERT_FILE, KEY_FILE]
