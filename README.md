# DNS Exfiltration Server

A Python-based DNS server that can receive and reconstruct data transmitted through DNS queries. This tool is useful for data exfiltration scenarios where traditional network communication methods are restricted.

## Features

- Receives data chunks through DNS queries
- Reconstructs data from base64-encoded chunks
- Configurable chunk size and total data size limits
- Colored console output for better visibility
- File and console logging
- Rate limiting to prevent DoS attacks
- Configurable through a central configuration file

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/DNS-Exfiltration.git
cd DNS-Exfiltration
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the server with default settings:
```bash
python server.py -o output.txt
```

Run the server with custom port:
```bash
python server.py -o output.txt -p 5353
```

### Command Line Arguments

- `-o, --output`: Path to the output file (required)
- `-p, --port`: Server listening port (default: 53)
![](https://i.imgur.com/f2D0Z7p.png)

## Configuration

The server can be configured through the `config.py` file. Available settings include:

- Port number
- Server address
- Maximum chunk size
- Maximum total data size
- Chunk timeout
- Log directory
- Output directory
- Authentication requirements
- Rate limiting

## Security Considerations

- The server includes rate limiting to prevent DoS attacks
- Optional authentication can be enabled
- Configurable size limits to prevent memory issues
- Input validation for all parameters

## Logging

Logs are stored in the `logs` directory with timestamps. Both file and console logging are supported.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.