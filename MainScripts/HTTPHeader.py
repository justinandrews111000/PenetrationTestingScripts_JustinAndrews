"""
Script Name: HTTPHeader.py
Author: Justin Andrews
Version: 1.0
Date:

Description:
    This script analyzes HTTP headers of specified URLs using WebDriver. It sends requests
    to each URL, retrieves and displays all HTTP headers, and performs additional analysis 
    on specific headers such as Server, Content-Type, Content-Length, and Set-Cookie.

Arguments:
    urls                One or more URLs to analyze (include http:// or https://)
    -d, --debug        Enable debug output for more detailed information
    -l, --logging      Enable logging to file
    --headless         Run in headless mode (default: True)

Usage:
    Basic header analysis:
        python HTTPHeader.py <url1> [url2 ...]

    With debug output:
        python HTTPHeader.py <url> -d

    With logging:
        python HTTPHeader.py <url> -l

Example:
    python HTTPHeader.py https://www.example.com http://test.com -d -l

Note: This script uses browser automation to analyze headers. Ensure you have permission
      to access these URLs and be aware of any potential security implications.

GUI Parameters Start:
"urls": []
"debug": false
"logging": false
"headless": true
"persistent": false
GUI Parameters End:
"""

import sys
from typing import Dict, Any, List
from Utils import LoggingPipeline, ArgumentHandler, WebDriver


class HTTPHeaderAnalyzer:
    """Class for analyzing HTTP headers using WebDriver with integrated logging support."""

    def __init__(self, debug: bool = False, logging: bool = False):
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="http_headers"
        )

    def analyze_headers(self, url: str, headless: bool = True) -> Dict[str, Any]:
        """Analyze HTTP headers for a specific URL using WebDriver."""
        self.logger.start_section(f"Analyzing Headers: {url}")

        try:
            driver = WebDriver(
                url=url,
                headless=headless,
                debug=self.logger.debug,
                logging=self.logger.file_logging,
            )

            # Execute JavaScript to get response headers
            script = """
            var req = new XMLHttpRequest();
            req.open('GET', document.location, false);
            req.send(null);
            var headers = {};
            var headerString = req.getAllResponseHeaders();
            var headerArray = headerString.split('\\r\\n');
            for (var i = 0; i < headerArray.length; i++) {
                var header = headerArray[i].split(': ', 2);
                if (header.length === 2) {
                    headers[header[0].toLowerCase()] = header[1];
                }
            }
            return {
                status: req.status,
                headers: headers
            };
            """
            response = driver.driver.execute_script(script)

            headers = response["headers"]
            status_code = response["status"]

            # Log status and headers
            status_level = "SUCCESS" if status_code == 200 else "WARNING"
            self.logger.append_log(f"Status Code: {status_code}", status_level)

            if headers:
                header_block = "HTTP Headers:\n" + "\n".join(
                    f"  {header}: {value}" for header, value in headers.items()
                )
                self.logger.append_log(header_block)

            # Analyze and log headers
            self.logger.append_log("\n" + self._analyze_security_headers(headers))
            self.logger.append_log(self._analyze_content_headers(headers))
            self.logger.append_log(self._analyze_server_info(headers))

            # Cleanup
            driver.close()

            return {
                "url": url,
                "status_code": status_code,
                "headers": headers,
            }

        except Exception as e:
            self.logger.append_log(f"Error analyzing {url}: {str(e)}", "ERROR")
            return {"url": url, "status_code": None, "headers": {}, "error": str(e)}

    def _analyze_security_headers(self, headers: Dict[str, str]) -> str:
        """Analyze security-related headers."""
        security_headers = {
            "strict-transport-security": "HSTS is enabled",
            "content-security-policy": "CSP is configured",
            "x-frame-options": "Frame protection is enabled",
            "x-xss-protection": "XSS protection is enabled",
            "x-content-type-options": "MIME-type sniffing protection is enabled",
        }

        output = ["Security Headers Analysis:"]
        for header, message in security_headers.items():
            if header in headers:
                output.append(f"  ✓ {message}")
            else:
                output.append(f"  ✗ {header} is missing")

        return "\n".join(output)

    def _analyze_content_headers(self, headers: Dict[str, str]) -> str:
        """Analyze content-related headers."""
        output = ["Content Headers Analysis:"]
        
        if "content-type" in headers:
            output.append(f"  Content-Type: {headers['content-type']}")
        
        if "content-length" in headers:
            size = int(headers["content-length"])
            readable_size = self._format_size(size)
            output.append(f"  Content-Length: {readable_size}")

        if "content-encoding" in headers:
            output.append(f"  Content-Encoding: {headers['content-encoding']}")

        return "\n".join(output)

    def _analyze_server_info(self, headers: Dict[str, str]) -> str:
        """Analyze server information headers."""
        output = ["Server Information:"]
        
        if "server" in headers:
            output.append(f"  Server: {headers['server']}")
        
        if "x-powered-by" in headers:
            output.append(f"  Powered By: {headers['x-powered-by']}")

        return "\n".join(output)

    def _format_size(self, size: int) -> str:
        """Format size in bytes to human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    def _generate_summary(self, url_security_stats, total_urls, successful, failed, 
                         avg_headers, server_types, content_types, color_enabled=False) -> str:
        """Generate the analysis summary."""
        from colorama import Fore

        summary = "\nURL Analysis Results:\n"
        for url, stats in url_security_stats.items():
            security_score = sum(1 for k, v in stats.items() 
                               if k in ["hsts", "csp", "xframe", "xss", "nosniff"] and v) / 5 * 100
            
            def format_security_item(name, is_enabled):
                if color_enabled:
                    return f"{Fore.GREEN if is_enabled else Fore.YELLOW}{'Yes' if is_enabled else 'No'}{Fore.RESET}"
                return 'Yes' if is_enabled else 'No'

            summary += (
                f"\n{'=' * 50}\n"
                f"URL: {url}\n"
                f"{'=' * 50}\n"
                f"Status: Success\n"
                f"Total Headers: {stats['header_count']}\n"
                f"Server: {stats['server']}\n"
                f"Content-Type: {stats['content_type']}\n\n"
                f"Security Analysis:\n"
                f"  Security Score: {security_score:.1f}%\n"
                f"  Security Headers:\n"
                f"    ✓ HSTS Enabled: {format_security_item('HSTS', stats['hsts'])}\n"
                f"    ✓ CSP Configured: {format_security_item('CSP', stats['csp'])}\n"
                f"    ✓ X-Frame-Options: {format_security_item('X-Frame-Options', stats['xframe'])}\n"
                f"    ✓ XSS Protection: {format_security_item('XSS Protection', stats['xss'])}\n"
                f"    ✓ MIME Sniffing Protection: {format_security_item('MIME Sniffing', stats['nosniff'])}\n"
            )

        summary += (
            f"\n{'=' * 50}\n"
            f"Overall Analytics:\n"
            f"{'=' * 50}\n"
            f"General Statistics:\n"
            f"  Total URLs Analyzed: {total_urls}\n"
            f"  Successful Requests: {successful}\n"
            f"  Failed Requests: {failed}\n"
            f"  Average Headers per URL: {avg_headers:.1f}\n"
        )

        if server_types:
            summary += "\nServer Distribution:\n"
            for server, count in server_types.items():
                percentage = count/successful*100 if successful > 0 else 0
                summary += f"  {server}: {count} ({percentage:.1f}%)\n"

        if content_types:
            summary += "\nContent Type Distribution:\n"
            for ctype, count in content_types.items():
                percentage = count/successful*100 if successful > 0 else 0
                summary += f"  {ctype}: {count} ({percentage:.1f}%)\n"

        return summary

    def process_urls(self, urls: List[str], headless: bool = True) -> bool:
        """Process multiple URLs for header analysis."""
        results = []
        successful = 0
        failed = 0
        total_headers = 0
        url_security_stats = {}
        server_types = {}
        content_types = {}

        # Analyze each URL
        for url in urls:
            result = self.analyze_headers(url, headless)
            results.append(result)
            
            if result.get("status_code") == 200:
                successful += 1
                headers = result.get("headers", {})
                total_headers += len(headers)

                # Store security stats for this URL
                url_security_stats[url] = {
                    "hsts": "strict-transport-security" in headers,
                    "csp": "content-security-policy" in headers,
                    "xframe": "x-frame-options" in headers,
                    "xss": "x-xss-protection" in headers,
                    "nosniff": "x-content-type-options" in headers,
                    "server": headers.get("server", "Unknown"),
                    "content_type": headers.get("content-type", "Not specified").split(";")[0],
                    "header_count": len(headers)
                }

                # Track server types
                if "server" in headers:
                    server = headers["server"]
                    server_types[server] = server_types.get(server, 0) + 1

                # Track content types
                if "content-type" in headers:
                    content_type = headers["content-type"].split(";")[0]
                    content_types[content_type] = content_types.get(content_type, 0) + 1
            else:
                failed += 1

        # Calculate averages
        total_urls = len(urls)
        avg_headers = total_headers / total_urls if total_urls > 0 else 0

        # Generate and print final summary
        colored_summary = self._generate_summary(
            url_security_stats, total_urls, successful, failed,
            avg_headers, server_types, content_types, color_enabled=True
        )
        self.logger.print_final_summary(colored_summary, color_formatted=True)
        
        return successful == total_urls

    def cleanup(self) -> None:
        """Cleanup and finalize logging."""
        if self.logger.file_logging:
            self.logger.generate_log()


def main():
    # Define argument configuration
    arg_config = {
        "script": {
            "name": "HTTPHeader.py",
            "description": "HTTP Header Analysis Utility",
        },
        "args": {
            "urls": {"help": "URLs to analyze", "nargs": "+", "positional": True},
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
            "headless": {
                "action": "store_true",
                "default": True,
                "help": "Run in headless mode",
            },
        },
    }

    # Parse arguments
    arg_handler = ArgumentHandler(arg_config)
    args = arg_handler.parse_args()

    # Initialize analyzer
    analyzer = HTTPHeaderAnalyzer(debug=args.debug, logging=args.logging)

    try:
        analyzer.process_urls(args.urls, args.headless)

    except Exception as e:
        analyzer.logger.append_log(f"Fatal error: {str(e)}", "ERROR")
        if args.debug:
            import traceback

            analyzer.logger.append_log(traceback.format_exc(), "ERROR")
        sys.exit(1)

    finally:
        analyzer.cleanup()


if __name__ == "__main__":
    main()
