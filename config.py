import json
import os
from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class ServerConfig:
    """Configuration for the DNS server."""
    port: int = 53
    address: str = "0.0.0.0"
    max_chunk_size: int = 1024  # Maximum size of each chunk in bytes (legacy, for Base64)
    max_total_size: int = 10 * 1024 * 1024  # Maximum total size (10MB)
    chunk_timeout: int = 300  # Timeout for chunks in seconds
    log_dir: str = "logs"
    output_dir: str = "output"
    
    # Security settings
    require_auth: bool = False
    auth_key: Optional[str] = None
    rate_limit: int = 100  # Maximum requests per minute (legacy)
    
    # New Base32 format settings
    chunk_size: int = 45  # Base32 chunk size in characters (40-50 range)
    session_id_length: int = 6  # Session ID length in Base32 characters
    checksum_length: int = 3  # Checksum length in Base32 characters
    base_rate_limit: int = 75  # Base queries per minute
    max_rate_limit: int = 150  # Maximum queries per minute
    enable_adaptive_rate: bool = True  # Enable adaptive rate limiting
    enable_jitter: bool = True  # Add random jitter to delays
    checksum_algorithm: str = "crc16"  # Checksum algorithm

    # Server limits
    max_sessions: int = 100  # Maximum concurrent sessions to track
    max_total_chunks: int = 50000  # Maximum total chunks across all sessions
    server_rate_limit: Optional[int] = None  # Max queries per minute (global); None = disabled

    def __post_init__(self):
        """Validate and create necessary directories."""
        # Create required directories
        for directory in [self.log_dir, self.output_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
        
        # Validate port number
        if not 1 <= self.port <= 65535:
            raise ValueError("Port number must be between 1 and 65535")
        
        # Validate sizes
        if self.max_chunk_size <= 0:
            raise ValueError("Maximum chunk size must be positive")
        if self.max_total_size <= 0:
            raise ValueError("Maximum total size must be positive")
        if self.max_chunk_size > self.max_total_size:
            raise ValueError("Maximum chunk size cannot be larger than maximum total size")
        
        # Validate rate limit
        if self.rate_limit <= 0:
            raise ValueError("Rate limit must be positive")
        
        # Validate new Base32 format settings
        if not 40 <= self.chunk_size <= 50:
            raise ValueError("Chunk size must be between 40 and 50 characters")
        if not 4 <= self.session_id_length <= 8:
            raise ValueError("Session ID length must be between 4 and 8 characters")
        if not 2 <= self.checksum_length <= 4:
            raise ValueError("Checksum length must be between 2 and 4 characters")
        if self.base_rate_limit <= 0:
            raise ValueError("Base rate limit must be positive")
        if self.max_rate_limit < self.base_rate_limit:
            raise ValueError("Max rate limit must be >= base rate limit")
        if self.max_sessions <= 0:
            raise ValueError("max_sessions must be positive")
        if self.max_total_chunks <= 0:
            raise ValueError("max_total_chunks must be positive")
        if self.server_rate_limit is not None and self.server_rate_limit <= 0:
            raise ValueError("server_rate_limit must be positive when set")


# Default configuration
default_config = ServerConfig()

def load_config(config_path: Optional[str] = None) -> ServerConfig:
    """Load configuration from a file or use default values."""
    defaults = asdict(default_config)
    if not config_path or not os.path.exists(config_path):
        return ServerConfig(**defaults)
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    allowed = set(ServerConfig.__dataclass_fields__)
    overrides = {k: v for k, v in data.items() if k in allowed}
    merged = {**defaults, **overrides}
    return ServerConfig(**merged)