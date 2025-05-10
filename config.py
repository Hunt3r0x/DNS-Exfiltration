import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class ServerConfig:
    """Configuration for the DNS server."""
    port: int = 53
    address: str = "0.0.0.0"
    max_chunk_size: int = 1024  # Maximum size of each chunk in bytes
    max_total_size: int = 10 * 1024 * 1024  # Maximum total size (10MB)
    chunk_timeout: int = 300  # Timeout for chunks in seconds
    log_dir: str = "logs"
    output_dir: str = "output"
    
    # Security settings
    require_auth: bool = False
    auth_key: Optional[str] = None
    rate_limit: int = 100  # Maximum requests per minute
    
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

# Default configuration
default_config = ServerConfig()

def load_config(config_path: Optional[str] = None) -> ServerConfig:
    """Load configuration from a file or use default values."""
    if config_path and os.path.exists(config_path):
        # TODO: Implement configuration loading from file
        pass
    return default_config 