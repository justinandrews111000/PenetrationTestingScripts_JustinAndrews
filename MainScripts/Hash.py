"""
Script Name: Hash.py
Author: Justin Andrews
Version: 2.0
Date: 2024-03-17

Description:
    This script calculates the hash of files or directories using various hashing algorithms.
    It provides a command-line interface for easy use and supports generating and verifying
    hash manifests.

Arguments:
    path                The path to the file or directory to be hashed
    -a, --algorithm     The hashing algorithm to use (default: sha256)
    -o, --output       Output file for manifest generation (optional)
    -v, --verify       Verify against a manifest file (optional)
    -d, --debug        Enable debug output
    -l, --logging      Enable logging to file
    -r, --recursive    Process directories recursively

Usage:
    Basic file hashing:
        python hash.py <filename> [-a <algorithm>]
    
    Directory hashing:
        python hash.py <directory> -r [-a <algorithm>]
    
    Generate manifest:
        python hash.py <directory> -r -o manifest.json
    
    Verify against manifest:
        python hash.py <directory> -v manifest.json
        
    Enable logging:
        python hash.py <filename> -l  # logging only
        python hash.py <filename> -d  # debug only
        python hash.py <filename> -d -l  # both debug and logging

Example:
    python hash.py myfile.txt -a md5
    python hash.py ./mydirectory -r -o manifest.json -d -l
    python hash.py ./mydirectory -v manifest.json -l

GUI Parameters Start:
"path": ""
"algorithm": "sha256"
"output": ""
"verify": ""
"recursive": false
"debug": false
"logging": false
"persistent": false
GUI Parameters End:
"""

import sys
from pathlib import Path
from Utils import Cryptography, ArgumentHandler, LoggingPipeline


def format_size(size: int) -> str:
    """Format file size in human-readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


class HashUtility:
    """Main class for hash operations with integrated logging."""

    def __init__(self, debug: bool = False, logging: bool = False):
        """
        Initialize hash utility with logging support.

        Args:
            debug (bool): Enable debug output
            logging (bool): Enable logging to file
        """
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="hash_operations"
        )
        self.crypto = Cryptography(debug=debug, logging=logging)

    def process_verification(self, path: Path, manifest_path: Path) -> bool:
        """Process verification against a manifest file."""
        if not manifest_path.exists():
            self.logger.append_log(
                f"Error: Manifest file '{manifest_path}' not found", "ERROR"
            )
            return False

        matched, modified, missing = self.crypto.verify_against_manifest(
            str(path), str(manifest_path)
        )

        result_summary = [
            "Verification Results:",
            f"{'=' * 50}",
            f"Matched Files:  {len(matched)}",
            f"Modified Files: {len(modified)}",
            f"Missing Files:  {len(missing)}",
        ]

        if modified:
            result_summary.extend(
                ["\nModified Files:"] + [f"  - {f}" for f in modified]
            )
        if missing:
            result_summary.extend(["\nMissing Files:"] + [f"  - {f}" for f in missing])

        self.logger.append_log(
            "\n".join(result_summary),
            "SUCCESS" if not (modified or missing) else "WARNING",
        )
        return True

    def process_directory(
        self, path: Path, algorithm: str, output_file: str = None
    ) -> bool:
        """Process a directory for hashing or manifest generation."""
        if output_file:
            success = self.crypto.generate_file_manifest(
                str(path), output_file, algorithm
            )
            self.logger.append_log(
                f"{'Successfully generated' if success else 'Failed to generate'} manifest: {output_file}",
                "SUCCESS" if success else "ERROR",
            )
            return success

        results = self.crypto.hash_directory(str(path), algorithm)

        result_lines = [f"Directory Hash Results ({algorithm}):"]
        for filepath, file_hash in results.items():
            file_size = format_size(Path(filepath).stat().st_size)
            result_lines.extend(
                [f"\nFile: {filepath}", f"Size: {file_size}", f"Hash: {file_hash}"]
            )

        self.logger.append_log("\n".join(result_lines), "SUCCESS")
        return True

    def process_file(self, path: Path, algorithm: str) -> bool:
        """Process a single file for hashing."""
        self.logger.append_log(f"Processing file: {path}", "DEBUG")

        file_hash = self.crypto.hash_file(str(path), algorithm)
        if file_hash:
            file_size = format_size(path.stat().st_size)
            self.logger.append_log(
                "\n".join(
                    [
                        f"File Hash Results ({algorithm})",
                        "=" * 50,
                        f"File: {path}",
                        f"Size: {file_size}",
                        f"Hash: {file_hash}\n",
                    ]
                ),
                "SUCCESS",
            )
            return True

        self.logger.append_log(f"Failed to hash file: {path}", "ERROR")
        return False

    def cleanup(self):
        """Cleanup and finalize logging."""
        if self.logger.file_logging:
            self.logger.append_log("Operation completed")
            self.logger.generate_log()


def main():
    # Define argument configuration
    arg_config = {
        "script": {
            "name": "Hash.py",
            "description": "File and Directory Hashing Utility",
        },
        "args": {
            "path": {
                "help": "Path to file or directory to process",
                "positional": True,
            },
            "algorithm": {
                "flag": "-a",
                "default": "sha256",
                "help": "Hashing algorithm to use",
            },
            "output": {"flag": "-o", "help": "Output file for manifest generation"},
            "verify": {"flag": "-v", "help": "Verify against manifest file"},
            "recursive": {
                "flag": "-r",
                "action": "store_true",
                "help": "Process directories recursively",
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

    # Initialize hash utility with debug/logging settings from arguments
    hash_util = HashUtility(debug=args.debug, logging=args.logging)

    try:
        path = Path(args.path)

        if not path.exists():
            hash_util.logger.append_log(
                f"Error: Path '{path}' does not exist.", "ERROR"
            )
            sys.exit(1)

        success = False
        if args.verify:
            success = hash_util.process_verification(path, Path(args.verify))
        elif args.recursive or (path.is_dir() and args.output):
            success = hash_util.process_directory(path, args.algorithm, args.output)
        else:
            success = hash_util.process_file(path, args.algorithm)

        if not success:
            sys.exit(1)

    except Exception as e:
        hash_util.logger.append_log(f"Fatal error: {str(e)}", "ERROR")
        if args.debug:
            import traceback

            hash_util.logger.append_log(traceback.format_exc(), "ERROR")
        sys.exit(1)
    finally:
        hash_util.cleanup()


if __name__ == "__main__":
    main()
