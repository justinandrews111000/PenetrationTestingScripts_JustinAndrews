"""
Script Name: PasswordBruteforcer.py
Author: Justin Andrews
Version: 1.1
Date: 2024-03-19

Description:
    This script checks a given hash against a dictionary of password hashes to find 
    the corresponding cleartext password. It utilizes the Utils.py classes for logging,
    argument handling, cryptographic operations, and multithreading.

Usage:
    python PasswordBruteforcer.py <hash_to_check> [options]

Arguments:
    hash             The hash to check against the password list
    -p, --passlist   Path to the password list file (default: WordLists/10-million-password-list-top-100000-and-hashes.txt)
    -t, --threads    Number of threads to use (default: 10)
    -d, --debug      Enable debug output
    -l, --logging    Enable logging to file

Example:
    python PasswordBruteforcer.py 4e1f35b85bf27fee01b2f369028d10903b73ba26b38d912e70c1a4633bb5fc8a -t 8 -d -l

GUI Parameters Start:
"hash": ""
"passlist": "WordLists/10-million-password-list-top-100000-and-hashes.txt"
"threads": 10
"debug": false
"logging": false
"persistent": false
GUI Parameters End:
"""

import sys
import json
from typing import Dict, Optional, Tuple, List
from Utils import LoggingPipeline, ArgumentHandler, Cryptography, Threading
import time


class PasswordBruteforcer:
    """Main class for checking password hashes against a dictionary."""

    def __init__(self, threads: int = 4, debug: bool = False, logging: bool = False):
        """
        Initialize hash checker with logging and threading support.

        Args:
            threads (int): Number of threads to use
            debug (bool): Enable debug output
            logging (bool): Enable logging to file
        """
        self.threads = threads
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="hash_checker"
        )
        self.crypto = Cryptography(debug=debug, logging=logging)
        self.thread_manager = Threading(debug=debug, logging=logging)
        self._found_match = None
        self._start_time = None

    def load_password_list(self, password_file: str) -> Optional[Dict[str, str]]:
        """
        Load password dictionary from JSON file.

        Args:
            password_file (str): Path to the password list file

        Returns:
            Optional[Dict[str, str]]: Dictionary of passwords and their hashes, or None if error
        """
        self.logger.append_log(f"Loading password list from {password_file}", "DEBUG")

        try:
            with open(password_file, "r", encoding="utf-8") as f:
                password_dict = json.load(f)

            self.logger.append_log(
                f"Successfully loaded {len(password_dict)} password hashes", "SUCCESS"
            )
            return password_dict

        except FileNotFoundError:
            self.logger.append_log(
                f"Password list file not found: {password_file}", "ERROR"
            )
            return None

        except json.JSONDecodeError as e:
            self.logger.append_log(
                f"Error parsing password list file: {str(e)}", "ERROR"
            )
            return None

        except Exception as e:
            self.logger.append_log(
                f"Unexpected error loading password list: {str(e)}", "ERROR"
            )
            return None

    def _split_dict_for_threading(
        self, password_dict: Dict[str, str], num_threads: int
    ) -> List[Dict[str, str]]:
        """
        Split the password dictionary into chunks for parallel processing.

        Args:
            password_dict (Dict[str, str]): Full password dictionary
            num_threads (int): Number of threads to split for

        Returns:
            List[Dict[str, str]]: List of dictionary chunks
        """
        items = list(password_dict.items())
        chunk_size = len(items) // num_threads + (1 if len(items) % num_threads else 0)

        return [
            dict(items[i : i + chunk_size]) for i in range(0, len(items), chunk_size)
        ]

    def _check_hash_chunk(
        self, chunk: Dict[str, str], target_hash: str
    ) -> Optional[Tuple[str, str]]:
        """
        Check a hash against a chunk of the password dictionary.

        Args:
            chunk (Dict[str, str]): Dictionary chunk to check
            target_hash (str): Hash to look for

        Returns:
            Optional[Tuple[str, str]]: Tuple of (cleartext, hash) if found, None if not found
        """
        target_hash = target_hash.lower().strip()

        for password, hash_value in chunk.items():
            # If we already found a match in another thread, stop processing
            if self._found_match is not None:
                return None

            if hash_value.lower() == target_hash:
                self._found_match = (password, hash_value)
                return password, hash_value

        return None

    def check_hash(
        self, password_dict: Dict[str, str], target_hash: str
    ) -> Optional[Tuple[str, str]]:
        """
        Check a hash against the password dictionary using multiple threads.

        Args:
            password_dict (Dict[str, str]): Dictionary of passwords and their hashes
            target_hash (str): Hash to look for

        Returns:
            Optional[Tuple[str, str]]: Tuple of (cleartext, hash) if found, None if not found
        """
        self.logger.append_log(
            f"Starting multithreaded hash check with {self.threads} threads", "DEBUG"
        )

        self._start_time = time.time()
        self._found_match = None

        try:
            # Split dictionary into chunks
            chunks = self._split_dict_for_threading(password_dict, self.threads)

            # Prepare arguments for each thread
            thread_args = [(chunk, target_hash) for chunk in chunks]

            # Run hash checking in parallel
            results = self.thread_manager.map_threaded(
                lambda args: self._check_hash_chunk(*args),
                thread_args,
                threads=self.threads,
            )

            # Return the first successful match (if any)
            for result in results:
                if result is not None:
                    return result

            self.logger.append_log(
                f"No matching password found for hash {target_hash}", "WARNING"
            )
            return None

        except Exception as e:
            self.logger.append_log(f"Error while checking hash: {str(e)}", "ERROR")
            return None

    def print_results(
        self, result: Optional[Tuple[str, str]], target_hash: str
    ) -> None:
        """
        Print formatted results of the hash check.

        Args:
            result (Optional[Tuple[str, str]]): Result tuple (cleartext, hash) or None
            target_hash (str): Original hash that was checked
        """
        self.logger.start_section("Hash Check Results")

        elapsed_time = time.time() - self._start_time

        if result:
            cleartext, hash_value = result
            summary = [
                f"Target Hash: {target_hash}",
                f"Found Password: {cleartext}",
                f"Stored Hash: {hash_value}",
                f"Time Elapsed: {elapsed_time:.2f} seconds",
                f"Threads Used: {self.threads}",
                "Status: MATCH FOUND",
            ]
        else:
            summary = [
                f"Target Hash: {target_hash}",
                f"Time Elapsed: {elapsed_time:.2f} seconds",
                f"Threads Used: {self.threads}",
                "Status: NO MATCH FOUND",
            ]

        for line in summary:
            self.logger.append_log(line, "SUCCESS" if result else "WARNING")

        self.logger.end_section()

    def cleanup(self) -> None:
        """Cleanup and finalize logging."""
        if self.logger.file_logging:
            self.logger.generate_log()


def main():
    # Define argument configuration
    arg_config = {
        "script": {
            "name": "PasswordBruteforcer.py",
            "description": "Multithreaded Password Hash Checker Utility",
        },
        "args": {
            "hash": {
                "help": "Hash to check against the password list",
                "positional": True,
            },
            "passlist": {
                "flag": "-p",
                "default": "WordLists/10-million-password-list-top-100000/10-million-password-list-top-100000-and-hashes.txt",
                "help": "Path to the password list file",
            },
            "threads": {
                "flag": "-t",
                "type": int,
                "default": 10,
                "help": "Number of threads to use",
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

    # Initialize hash checker
    checker = PasswordBruteforcer(
        threads=args.threads, debug=args.debug, logging=args.logging
    )

    try:
        # Load password list
        password_dict = checker.load_password_list(args.passlist)
        if not password_dict:
            sys.exit(1)

        # Check hash
        result = checker.check_hash(password_dict, args.hash)

        # Print results
        checker.print_results(result, args.hash)

    except Exception as e:
        checker.logger.append_log(f"Fatal error: {str(e)}", "ERROR")
        if args.debug:
            import traceback

            checker.logger.append_log(traceback.format_exc(), "ERROR")
        sys.exit(1)

    finally:
        checker.cleanup()


if __name__ == "__main__":
    main()
