"""
Script Name: SecureFileTransfer.py
Author: Justin Andrews
Version: 1.0
Date: 2024-03-30

Description:
    This script implements a secure file transfer system using SSL/TLS with support for
    multiple simultaneous clients, file integrity verification, progress monitoring,
    and comprehensive logging.

Features:
    - SSL/TLS encryption using self-signed certificates
    - Multi-threaded client handling
    - File integrity verification using hashing
    - Directory transfers with permission preservation
    - Transfer progress monitoring
    - Rate limiting
    - File compression
    - Comprehensive logging
    - Protocol version checking
    - Metadata preservation

Arguments:
    --host              Host address to bind/connect to (default: localhost)
    --port              Port number (default: 8009)
    --cert-dir          Directory for certificates (default: ./certs)
    --max-clients       Maximum number of simultaneous clients (default: 5)
    --buffer-size       Transfer buffer size in bytes (default: 8192)
    --rate-limit        Transfer speed limit in MB/s (default: 0 for unlimited)
    -d, --debug         Enable debug output
    -l, --logging       Enable logging to file
    --mode              Server or client mode (required)

Example:
    Server mode:
        python SecureFileTransfer.py --mode server --port 8009 -d -l
    
    Client mode:
        python SecureFileTransfer.py --mode client --port 8009 -d -l

GUI Parameters Start:
"host": "localhost"
"port": 8009
"cert_dir": "./certs"
"max_clients": 5
"buffer_size": 8192
"rate_limit": 0
"debug": false
"logging": true
"mode": ""
"persistent": false
GUI Parameters End:
"""

import os
import ssl
import json
import socket
import sys
import threading
import time
import enum
from pathlib import Path
from dataclasses import dataclass
from contextlib import contextmanager
from typing import Optional

from Utils import LoggingPipeline, Threading, Cryptography, ArgumentHandler

# Protocol version and constants
PROTOCOL_VERSION = "1.0"
ENCODING = "utf-8"


class TransferType(enum.Enum):
    """Enumeration of supported transfer types.

    Values:
        FILE: Single file transfer
        DIRECTORY: Directory and its contents transfer
        MESSAGE: Text message transfer
        EXIT: Signal to terminate connection
    """

    FILE = "FILE"
    DIRECTORY = "DIR"
    MESSAGE = "MSG"
    EXIT = "EXIT"


class TransferStatus(enum.Enum):
    """Enumeration of transfer status codes.

    Values:
        SUCCESS: Transfer completed successfully
        FAILURE: General transfer failure
        VERSION_MISMATCH: Protocol version mismatch between client and server
        INTEGRITY_ERROR: File integrity verification failed
    """

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    INTEGRITY_ERROR = "INTEGRITY_ERROR"


@dataclass
class FileMetadata:
    """Class for holding file metadata."""

    path: str
    size: int
    mode: int
    mtime: float
    checksum: str


class SecureTransfer:
    """Base class for secure file transfer operations."""

    def __init__(
        self,
        host: str,
        port: int,
        cert_dir: str,
        buffer_size: int = 8192,
        debug: bool = False,
        logging: bool = True,
    ):
        self.host = host
        self.port = port
        self.cert_dir = Path(cert_dir)
        self.buffer_size = buffer_size

        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="secure_transfer"
        )
        self.crypto = Cryptography(debug=debug, logging=logging)

        self.cert_dir.mkdir(parents=True, exist_ok=True)

        self.cert_path = self.cert_dir / "selfsigned.crt"
        self.key_path = self.cert_dir / "private.key"
        if not (self.cert_path.exists() and self.key_path.exists()):
            self.logger.append_log("Generating new self-signed certificate", "INFO")
            self.crypto.gen_self_signed_cert(
                commonName="localhost",  # Set to localhost instead of the host
                emailAddress="admin@localhost",
                countryName="US",
                localityName="Local",
                stateOrProvinceName="State",
                organizationName="Org",
                organizationUnitName="Unit",
                CERT_FILE=str(self.cert_path),
                KEY_FILE=str(self.key_path),
            )

    def verify_file_integrity(
        self,
        expected_hash: str,
        target_path: Path,
        algorithm: str = "sha256",
    ) -> bool:
        """Verify file integrity using hash comparison.

        Args:
            expected_hash: Expected hash value
            target_path: Path to verify
            algorithm: Hashing algorithm to use

        Returns:
            bool: True if hash matches, False otherwise
        """
        try:
            calculated_hash = self.crypto.hash_file(str(target_path), algorithm)
            return calculated_hash == expected_hash
        except Exception as e:
            self.logger.append_log(f"Error verifying file integrity: {e}", "ERROR")
            return False

    def send_protocol_message(self, sock: ssl.SSLSocket, message: bytes) -> None:
        """
        Send a protocol message.

        Args:
            sock: SSL socket to send on. Must be provided.
            message: Bytes message to send

        Raises:
            RuntimeError: If no socket is provided
            socket.error: If there's an error sending the message
        """
        if sock is None:
            raise RuntimeError("Socket must be provided")

        size = len(message)
        sock.send(str(size).encode(ENCODING))
        sock.recv(1)  # Wait for acknowledgment
        sock.send(message)

    def receive_message(self, sock: ssl.SSLSocket) -> bytes:
        """Receive a length-prefixed message from the socket.

        Args:
            sock: SSL socket to receive from

        Returns:
            bytes: Received message data

        Raises:
            socket.error: If there's an error reading from the socket
            ValueError: If the message size is invalid
        """
        size = int(sock.recv(1024).decode(ENCODING))
        sock.send(b"1")  # Send acknowledgment
        message = sock.recv(size)
        return message

    def get_file_metadata(self, path: str) -> FileMetadata:
        """Get metadata for a file.

        Args:
            path: Path to the file

        Returns:
            FileMetadata: Object containing file metadata including size,
                        permissions, modification time, and checksum

        """
        stat_result = os.stat(path)
        return FileMetadata(
            path=path,
            size=stat_result.st_size,
            mode=stat_result.st_mode,
            mtime=stat_result.st_mtime,
            checksum=self.crypto.hash_file(path),
        )

    def apply_file_metadata(
        self, metadata: FileMetadata, target_path: Path = None
    ) -> None:
        """
        Apply metadata to a file.

        Args:
            metadata: FileMetadata object containing the metadata
            target_path: Optional path to apply metadata to. If None, uses metadata.path
        """
        path_to_use = target_path if target_path else metadata.path
        os.chmod(path_to_use, metadata.mode)
        os.utime(path_to_use, (metadata.mtime, metadata.mtime))


class SecureServer(SecureTransfer):
    """Secure file transfer server implementation."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8009,
        cert_dir: str = "./certs",
        max_clients: int = 5,
        buffer_size: int = 8192,
        debug: bool = False,
        logging: bool = True,
    ):
        super().__init__(host, port, cert_dir, buffer_size, debug, logging)

        self.max_clients = max_clients
        self.active_clients = 0
        self.client_lock = threading.Lock()
        self.running = False

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(self.cert_path, self.key_path)

    @staticmethod
    @contextmanager
    def socket_timeout(sock: ssl.SSLSocket, timeout: Optional[float] = None):
        """Context manager for temporarily setting socket timeout.

        Args:
            sock: The SSL socket to set timeout on
            timeout: Timeout in seconds, or None for no timeout
        """
        original_timeout = sock.gettimeout()
        try:
            sock.settimeout(timeout)
            yield
        finally:
            sock.settimeout(original_timeout)

    def handle_client(self, conn: ssl.SSLSocket, addr: tuple) -> None:
        """Handle an individual client connection.

        Args:
            conn: SSL socket connection to client
            addr: Tuple of (host, port) identifying the client

        This method runs in its own thread and handles all communication
        with a single client until disconnection.
        """
        self.logger.append_log(f"New client connected from {addr}", "INFO")

        try:
            # Version check
            try:
                client_version = conn.recv(1024).decode(ENCODING)
                if client_version != PROTOCOL_VERSION:
                    conn.send(TransferStatus.VERSION_MISMATCH.value.encode(ENCODING))
                    self.logger.append_log(
                        f"Protocol version mismatch: got {client_version}, expected {PROTOCOL_VERSION}",
                        "ERROR",
                    )
                    return
                conn.send(TransferStatus.SUCCESS.value.encode(ENCODING))
            except (socket.error, UnicodeDecodeError) as e:
                self.logger.append_log(f"Error during version check: {str(e)}", "ERROR")
                return

            while True:
                try:
                    command_data = conn.recv(1024).decode(ENCODING).strip()
                    if not command_data:
                        self.logger.append_log("Empty command received", "ERROR")
                        break

                    try:
                        command = TransferType(command_data)
                    except ValueError:
                        self.logger.append_log(
                            f"Invalid transfer type: {command_data}", "ERROR"
                        )
                        conn.send(TransferStatus.PROTOCOL_ERROR.value.encode(ENCODING))
                        break

                    if command == TransferType.EXIT:
                        break

                    handlers = {
                        TransferType.FILE: self._handle_file_transfer,
                        TransferType.DIRECTORY: self._handle_directory_transfer,
                        TransferType.MESSAGE: self._handle_message,
                    }

                    if command in handlers:
                        handlers[command](conn)
                    else:
                        self.logger.append_log(f"Unknown command: {command}", "ERROR")
                        conn.send(TransferStatus.PROTOCOL_ERROR.value.encode(ENCODING))
                        break

                except (socket.error, UnicodeDecodeError) as e:
                    self.logger.append_log(f"Error handling command: {str(e)}", "ERROR")
                    break

        except Exception as e:
            self.logger.append_log(f"Error handling client {addr}: {str(e)}", "ERROR")

        finally:
            with self.client_lock:
                self.active_clients -= 1
            conn.close()
            self.logger.append_log(f"Client {addr} disconnected", "INFO")

    def _handle_file_transfer(
        self, conn: ssl.SSLSocket, target_path: Path = None
    ) -> None:
        """Handle receiving a file from a client.

        Args:
            conn: SSL socket connection to client
            target_path: Optional path where file should be saved. If None,
                        saves to downloads directory using original filename.

        The method receives file metadata first, then the file content,
        and finally verifies file integrity using the checksum.
        """
        try:
            self.logger.append_log("Receiving file metadata", "DEBUG")
            metadata_json = self.receive_message(conn).decode(ENCODING)
            metadata = FileMetadata(**json.loads(metadata_json))

            if target_path is None:
                # If no target path specified, save to downloads directory
                downloads_dir = Path("downloads")
                downloads_dir.mkdir(exist_ok=True)
                target_path = downloads_dir / Path(metadata.path).name

            self.logger.append_log(
                f"Receiving file: {target_path} ({metadata.size} bytes)", "INFO"
            )

            total_received = 0
            # Use PathLib's open() with context manager
            with target_path.open("wb") as f:
                while total_received < metadata.size:
                    remaining = metadata.size - total_received
                    chunk = conn.recv(min(self.buffer_size, remaining))
                    if not chunk:
                        raise ConnectionError("Connection closed prematurely")
                    f.write(chunk)
                    total_received += len(chunk)

            if total_received != metadata.size:
                raise ValueError(
                    f"Incomplete transfer: got {total_received} of {metadata.size} bytes"
                )
            self.logger.append_log(
                f"File receive complete. Verifying integrity...", "DEBUG"
            )
            self.apply_file_metadata(metadata, target_path)

            if self.verify_file_integrity(metadata.checksum, target_path):
                self.logger.append_log(
                    "Integrity check passed, sending SUCCESS", "DEBUG"
                )
                conn.send(TransferStatus.SUCCESS.value.encode(ENCODING))
                self.logger.append_log(
                    f"File {target_path} received successfully", "SUCCESS"
                )
            else:
                self.logger.append_log("Integrity check failed, sending ERROR", "DEBUG")
                conn.send(TransferStatus.INTEGRITY_ERROR.value.encode(ENCODING))
                self.logger.append_log(
                    f"File {target_path} integrity check failed", "ERROR"
                )

        except Exception as e:
            self.logger.append_log(f"Error receiving file: {str(e)}", "ERROR")
            try:
                conn.send(TransferStatus.FAILURE.value.encode(ENCODING))
            except (socket.error, OSError) as e:
                self.logger.append_log(f"Failed to send failure status: {e}", "ERROR")

    def _handle_message(self, conn: ssl.SSLSocket) -> None:
        """Handle receiving a text message from a client.

        Args:
            conn: SSL socket connection to client

        Messages are logged and an acknowledgment is sent back to the client.
        """
        try:
            message = self.receive_message(conn)
            if message:
                self.logger.append_log(f"Received message: {message}", "INFO")
                conn.send(TransferStatus.SUCCESS.value.encode(ENCODING))
            else:
                conn.send(TransferStatus.FAILURE.value.encode(ENCODING))

        except Exception as e:
            self.logger.append_log(f"Error receiving message: {str(e)}", "ERROR")
            try:
                conn.send(TransferStatus.FAILURE.value.encode(ENCODING))
            except (socket.error, OSError) as e:
                self.logger.append_log(f"Failed to send failure status: {e}", "ERROR")

    def _handle_directory_transfer(self, conn: ssl.SSLSocket) -> None:
        """Handle receiving a directory and its contents from a client.

        Args:
            conn: SSL socket connection to client

        Receives directory structure information first, then handles
        individual file transfers for each file in the directory.
        """
        try:
            # Get directory info first
            dir_info = json.loads(self.receive_message(conn).decode(ENCODING))
            src_path = Path(dir_info["path"])
            file_count = dir_info["file_count"]

            # Create base directory in downloads
            downloads_dir = Path("downloads")
            target_dir = downloads_dir / src_path.name
            target_dir.mkdir(parents=True, exist_ok=True)

            self.logger.append_log(
                f"Receiving directory: {target_dir} ({file_count} files)", "INFO"
            )

            # Handle each file
            for _ in range(file_count):
                try:
                    # Get relative path for current file
                    rel_path = self.receive_message(conn).decode(ENCODING)
                    save_path = target_dir / rel_path

                    # Create parent directories
                    save_path.parent.mkdir(parents=True, exist_ok=True)

                    # Handle the actual file transfer
                    self._handle_file_transfer(conn, save_path)

                except Exception as e:
                    self.logger.append_log(f"Error receiving file: {str(e)}", "ERROR")
                    raise

            conn.send(TransferStatus.SUCCESS.value.encode(ENCODING))
            self.logger.append_log(
                f"Directory {target_dir} received successfully", "SUCCESS"
            )

        except Exception as e:
            self.logger.append_log(f"Error receiving directory: {str(e)}", "ERROR")
            try:
                conn.send(TransferStatus.FAILURE.value.encode(ENCODING))
            except (socket.error, OSError) as e:
                self.logger.append_log(f"Failed to send failure status: {e}", "ERROR")

    def start(self) -> None:
        """Start the secure file transfer server.

        Creates a socket bound to the configured host and port,
        wraps it in SSL/TLS, and begins accepting client connections.
        Each client connection is handled in a separate thread.

        The server runs until interrupted by Ctrl+C or a shutdown command.
        Server commands available while running:
        - shutdown: Gracefully stop the server
        - status: Show number of active client connections

        Raises:
            OSError: If unable to bind to the specified host/port
            ssl.SSLError: If there are SSL configuration issues
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind((self.host, self.port))
                sock.listen(self.max_clients)

                with self.context.wrap_socket(sock, server_side=True) as ssock:
                    self.logger.append_log(
                        f"Server listening on {self.host}:{self.port}", "SUCCESS"
                    )
                    self.logger.append_log("Press Ctrl+C to shutdown server", "INFO")
                    self.running = True

                    # Add a separate thread for server commands
                    def handle_server_commands():
                        while self.running:
                            command = (
                                input("Server command (shutdown/status): ")
                                .strip()
                                .lower()
                            )
                            if command == "shutdown":
                                self.logger.append_log(
                                    "Server shutdown initiated", "INFO"
                                )
                                self.running = False
                                break
                            elif command == "status":
                                self.logger.append_log(
                                    f"Active clients: {self.active_clients}", "INFO"
                                )

                    command_thread = threading.Thread(target=handle_server_commands)
                    command_thread.daemon = True
                    command_thread.start()

                    while self.running:
                        try:
                            # Set a timeout so we can check running status
                            ssock.settimeout(1)
                            try:
                                conn, addr = ssock.accept()
                            except socket.timeout:
                                continue

                            with self.client_lock:
                                if self.active_clients >= self.max_clients:
                                    self.logger.append_log(
                                        f"Rejected connection from {addr}: Max clients reached",
                                        "WARNING",
                                    )
                                    conn.close()
                                    continue
                                self.active_clients += 1

                            client_thread = threading.Thread(
                                target=self.handle_client, args=(conn, addr)
                            )
                            client_thread.daemon = True
                            client_thread.start()

                        except Exception as e:
                            if self.running:  # Only log if not shutting down
                                self.logger.append_log(
                                    f"Error accepting connection: {str(e)}", "ERROR"
                                )

            self.logger.append_log("Server stopped successfully", "SUCCESS")

        except Exception as e:
            self.logger.append_log(f"Server error: {str(e)}", "ERROR")

        finally:
            self.running = False
            self._cleanup()

    def _cleanup(self) -> None:
        """Clean up server resources before shutdown.

        Waits for a short period to allow active clients to disconnect
        gracefully before forcing shutdown.
        """
        # Wait for active clients to disconnect
        if self.active_clients > 0:
            self.logger.append_log(
                f"Waiting for {self.active_clients} clients to disconnect...", "INFO"
            )
            timeout = 5  # Wait up to 5 seconds
            start_time = time.time()
            while self.active_clients > 0 and (time.time() - start_time) < timeout:
                time.sleep(0.1)


class SecureClient(SecureTransfer):
    """Secure file transfer client implementation.

    The client connects to a SecureServer instance and provides methods to:
    - Send files and directories with integrity verification
    - Send text messages
    - Handle secure connection establishment and teardown

    Attributes:
        host (str): Server hostname to connect to
        port (int): Server port number
        cert_dir (str): Directory containing SSL certificates
        buffer_size (int): Size of transfer chunks in bytes
        rate_limit (float): Transfer speed limit in MB/s (not implemented)
        debug (bool): Enable debug output
        logging (bool): Enable logging to file
        sock (ssl.SSLSocket): SSL socket connection to server
        connected (bool): Connection status flag
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8009,
        cert_dir: str = "./certs",
        buffer_size: int = 8192,
        debug: bool = False,
        logging: bool = True,
    ):
        super().__init__(host, port, cert_dir, buffer_size, debug, logging)

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.check_hostname = False  # Disable hostname checking
        self.context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
        self.context.load_verify_locations(self.cert_path)

        self.sock = None
        self.connected = False

    @contextmanager
    def socket_timeout(self, timeout: Optional[float] = None):
        """Context manager for temporarily setting socket timeout.

        Args:
            timeout: Timeout in seconds, or None for no timeout

        Raises:
            RuntimeError: If not connected to server
        """
        if not self.connected or self.sock is None:
            raise RuntimeError("Not connected to server")

        original_timeout = self.sock.gettimeout()
        try:
            self.sock.settimeout(timeout)
            yield
        finally:
            self.sock.settimeout(original_timeout)

    def connect(self) -> bool:
        """Connect to the secure file transfer server.

        Returns:
            bool: True if connection successful, False otherwise

        Establishes SSL/TLS connection and performs protocol version
        verification with the server.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock = self.context.wrap_socket(sock)
            self.sock.connect((self.host, self.port))

            self.sock.send(PROTOCOL_VERSION.encode(ENCODING))
            response = TransferStatus(self.sock.recv(1024).decode(ENCODING))

            if response != TransferStatus.SUCCESS:
                self.logger.append_log("Protocol version mismatch", "ERROR")
                return False

            self.connected = True
            self.logger.append_log(f"Connected to {self.host}:{self.port}", "SUCCESS")
            return True

        except Exception as e:
            self.logger.append_log(f"Connection failed: {str(e)}", "ERROR")
            return False

    def disconnect(self) -> None:
        """Gracefully disconnect from the server.

        Sends exit command to server and closes the connection.
        Waits briefly for server to process the disconnection.
        """
        if self.connected:
            try:
                # Send exit command
                self.logger.append_log("Sending exit command to server", "DEBUG")
                self.sock.send(TransferType.EXIT.value.encode(ENCODING))

                # Give server time to process
                time.sleep(0.5)

                # Close socket
                self.sock.close()
                self.connected = False
                self.logger.append_log("Disconnected from server", "SUCCESS")

            except Exception as e:
                self.logger.append_log(f"Error during disconnect: {str(e)}", "ERROR")
            finally:
                self.sock = None

    def send_file(self, filepath: str) -> bool:
        if not self.connected:
            self.logger.append_log("Not connected to server", "ERROR")
            return False

        try:
            filepath = Path(filepath)
            if not filepath.exists():
                raise FileNotFoundError(f"File not found: {filepath}")

            # Send transfer type
            self.logger.append_log("Sending transfer type", "DEBUG")
            self.sock.send(TransferType.FILE.value.encode(ENCODING))

            # Get and send metadata
            self.logger.append_log("Sending metadata", "DEBUG")
            metadata = self.get_file_metadata(str(filepath))
            metadata_json = json.dumps(metadata.__dict__)
            self.send_protocol_message(None, metadata_json.encode(ENCODING))

            # Send file data
            self.logger.append_log(
                f"Starting file transfer of {metadata.size} bytes", "DEBUG"
            )
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(self.buffer_size)
                    if not chunk:
                        break
                    self.sock.send(chunk)

            self.logger.append_log("File data sent, waiting for confirmation", "DEBUG")

            # Wait for confirmation with timeout
            with self.socket_timeout(10):  # 10 second timeout
                try:
                    response_data = self.sock.recv(1024).decode(ENCODING).strip()
                    if not response_data:
                        self.logger.append_log(
                            "Received empty response from server", "ERROR"
                        )
                        return False

                    response = TransferStatus(response_data)
                    success = response == TransferStatus.SUCCESS

                    if success:
                        self.logger.append_log(
                            f"File {filepath} sent successfully", "SUCCESS"
                        )
                    else:
                        self.logger.append_log(
                            f"File transfer failed: {response}", "ERROR"
                        )

                    return success
                except socket.timeout:
                    self.logger.append_log(
                        "Timeout waiting for server response", "ERROR"
                    )
                    return False
                except (socket.error, OSError) as e:
                    self.logger.append_log(
                        f"Socket error during confirmation: {e}", "ERROR"
                    )
                    return False
                except ValueError as e:
                    self.logger.append_log(
                        f"Invalid response from server: {e}", "ERROR"
                    )
                    return False

        except Exception as e:
            self.logger.append_log(f"Error sending file: {str(e)}", "ERROR")
            return False

        except Exception as e:
            self.logger.append_log(f"Error sending file: {str(e)}", "ERROR")
            return False

    def send_protocol_message(self, sock: ssl.SSLSocket | None, message: bytes) -> None:
        """
        Send a protocol message using the established socket connection.

        Args:
            sock: Ignored in client (uses self.sock)
            message: Bytes message to send

        Raises:
            RuntimeError: If not connected to server
            socket.error: If there's an error sending the message
        """
        if not self.connected or self.sock is None:
            raise RuntimeError("Not connected to server")
        super().send_protocol_message(self.sock, message)

    def send_message(self, message: str) -> bool:
        """Send a text message to the server.

        Args:
            message: Text message to send

        Returns:
            bool: True if message was sent successfully, False otherwise
        """
        if not self.connected:
            self.logger.append_log("Not connected to server", "ERROR")
            return False

        try:
            # Send transfer type
            self.sock.send(TransferType.MESSAGE.value.encode(ENCODING))

            # Send message - make sure to encode it first
            message_bytes = message.encode(ENCODING)
            self.send_protocol_message(None, message_bytes)

            # Wait for confirmation
            response = TransferStatus(self.sock.recv(1024).decode(ENCODING))
            success = response == TransferStatus.SUCCESS

            if success:
                self.logger.append_log("Message sent successfully", "SUCCESS")
            else:
                self.logger.append_log(f"Message send failed: {response}", "ERROR")

            return success

        except Exception as e:
            self.logger.append_log(f"Error sending message: {str(e)}", "ERROR")
            return False

    def send_directory(self, dirpath: str) -> bool:
        """Send a directory and all its contents to the server.

        Args:
            dirpath: Path to the directory to send

        Returns:
            bool: True if directory was sent successfully, False otherwise

        Handles sending directory structure information followed by
        individual file transfers for each file in the directory.
        """
        if not self.connected:
            self.logger.append_log("Not connected to server", "ERROR")
            return False

        try:
            dirpath = Path(dirpath)
            if not dirpath.is_dir():
                raise NotADirectoryError(f"Not a directory: {dirpath}")

            # Get list of all files
            files = list(dirpath.rglob("*"))
            files = [f for f in files if f.is_file()]

            # Send transfer type
            self.sock.send(TransferType.DIRECTORY.value.encode(ENCODING))

            # Send directory info first
            dir_info = {"path": str(dirpath), "file_count": len(files)}
            self.send_protocol_message(None, json.dumps(dir_info).encode(ENCODING))

            # Send each file
            for filepath in files:
                try:
                    # Send relative path first
                    rel_path = str(filepath.relative_to(dirpath))
                    self.send_protocol_message(None, rel_path.encode(ENCODING))

                    # Now send the actual file
                    self.logger.append_log(f"Sending file: {rel_path}", "DEBUG")

                    # Get and send metadata
                    metadata = self.get_file_metadata(str(filepath))
                    metadata_json = json.dumps(metadata.__dict__)
                    self.send_protocol_message(None, metadata_json.encode(ENCODING))

                    # Send file data
                    self.logger.append_log(
                        f"Starting file transfer of {metadata.size} bytes", "DEBUG"
                    )
                    with open(filepath, "rb") as f:
                        remaining = metadata.size
                        while remaining > 0:
                            chunk_size = min(self.buffer_size, remaining)
                            chunk = f.read(chunk_size)
                            if not chunk:
                                break
                            self.sock.send(chunk)
                            remaining -= len(chunk)

                    # Wait for file confirmation
                    response = TransferStatus(
                        self.sock.recv(1024).decode(ENCODING).strip()
                    )
                    if response != TransferStatus.SUCCESS:
                        self.logger.append_log(
                            f"Failed to send file {rel_path}: {response}", "ERROR"
                        )
                        return False

                except Exception as e:
                    self.logger.append_log(
                        f"Error sending file {filepath}: {str(e)}", "ERROR"
                    )
                    return False

            # Wait for directory transfer completion confirmation
            response = TransferStatus(self.sock.recv(1024).decode(ENCODING).strip())
            success = response == TransferStatus.SUCCESS

            if success:
                self.logger.append_log(
                    f"Directory {dirpath} sent successfully", "SUCCESS"
                )
            else:
                self.logger.append_log(
                    f"Directory transfer failed: {response}", "ERROR"
                )

            return success

        except Exception as e:
            self.logger.append_log(f"Error sending directory: {str(e)}", "ERROR")
            return False


def main():
    """Main entry point for the script."""
    # Define argument configuration
    arg_config = {
        "script": {
            "name": "SecureFileTransfer.py",
            "description": "Secure File Transfer Utility",
        },
        "args": {
            "mode": {
                "help": "Operating mode (server/client)",
                "choices": ["server", "client"],
                "positional": True,
            },
            "host": {
                "flag": "--host",
                "default": "localhost",
                "help": "Host address",
            },
            "port": {
                "flag": "--port",
                "type": int,
                "default": 8009,
                "help": "Port number",
            },
            "cert_dir": {
                "flag": "--cert-dir",
                "default": "./certs",
                "help": "Certificate directory",
            },
            "max_clients": {
                "flag": "--max-clients",
                "type": int,
                "default": 5,
                "help": "Maximum simultaneous clients",
            },
            "buffer_size": {
                "flag": "--buffer-size",
                "type": int,
                "default": 8192,
                "help": "Transfer buffer size",
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

    try:
        if args.mode == "server":
            server = SecureServer(
                host=args.host,
                port=args.port,
                cert_dir=args.cert_dir,
                max_clients=args.max_clients,
                buffer_size=args.buffer_size,
                debug=args.debug,
                logging=args.logging,
            )
            server.start()

        else:  # client mode
            client = SecureClient(
                host=args.host,
                port=args.port,
                cert_dir=args.cert_dir,
                buffer_size=args.buffer_size,
                debug=args.debug,
                logging=args.logging,
            )

            if not client.connect():
                sys.exit(1)

            try:
                while True:
                    print("\nAvailable commands:")
                    print("1. Send file")
                    print("2. Send directory")
                    print("3. Send message")
                    print("4. Exit")

                    choice = input("\nEnter choice (1-4): ").strip()

                    if choice == "1":
                        filepath = input("Enter file path: ").strip()
                        client.send_file(filepath)

                    elif choice == "2":
                        dirpath = input("Enter directory path: ").strip()
                        client.send_directory(dirpath)

                    elif choice == "3":
                        message = input("Enter message: ").strip()
                        client.send_message(message)

                    elif choice == "4":
                        break

                    else:
                        print("Invalid choice")

            finally:
                client.disconnect()

    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
