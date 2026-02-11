#!/usr/bin/env python3
"""
Encoding utilities for DNS exfiltration.

Provides Base32 encoding/decoding without padding and checksum functions.
"""

import base64
import binascii
import secrets
import zlib
from typing import Tuple


def encode_base32_no_padding(data: bytes) -> str:
    """
    Encode bytes to Base32 string without padding.
    
    Args:
        data: Bytes to encode
        
    Returns:
        Base32-encoded string without padding characters
    """
    encoded = base64.b32encode(data).decode("ascii")
    # Strip trailing padding characters
    return encoded.rstrip("=")


def decode_base32_no_padding(encoded: str) -> bytes:
    """
    Decode Base32 string that may be missing padding.
    
    Args:
        encoded: Base32-encoded string (may be missing padding)
        
    Returns:
        Decoded bytes
        
    Raises:
        binascii.Error: If the string is not valid Base32
    """
    # Base32 requires padding to be a multiple of 8 characters
    padding_needed = (8 - len(encoded) % 8) % 8
    if padding_needed > 0:
        encoded += "=" * padding_needed
    
    return base64.b32decode(encoded, casefold=True)


def generate_session_id(length: int = 6) -> str:
    """
    Generate a random Base32 session ID.
    
    Args:
        length: Length of session ID in characters (default: 6)
        
    Returns:
        Base32-encoded session ID string
    """
    # Generate random bytes: 6 chars = 30 bits, need 4 bytes
    bytes_needed = (length * 5 + 7) // 8
    random_bytes = secrets.token_bytes(bytes_needed)
    session_id = encode_base32_no_padding(random_bytes)
    return session_id[:length].upper()


def calculate_checksum(data: str, length: int = 3) -> str:
    """
    Calculate a Base32 checksum for the given data.
    
    Uses CRC32 masked to 16 bits for checksum calculation, then encodes as Base32.
    This provides good error detection while keeping the checksum small.
    
    Args:
        data: String data to checksum
        length: Length of checksum in characters (default: 3)
        
    Returns:
        Base32-encoded checksum string
    """
    # Calculate CRC32 and mask to 16 bits (provides 65536 possible values)
    crc = zlib.crc32(data.encode("ascii")) & 0xFFFF
    
    # Convert to bytes (2 bytes for 16-bit checksum)
    crc_bytes = crc.to_bytes(2, byteorder="big")
    
    # Encode as Base32 and take first 'length' characters
    checksum = encode_base32_no_padding(crc_bytes)
    
    # Ensure we have at least 'length' characters
    # Base32 encoding of 2 bytes = 4 characters, so this should always be sufficient
    if len(checksum) < length:
        # Pad with 'A' if needed (shouldn't happen with 2 bytes = 4 Base32 chars)
        checksum = checksum.ljust(length, "A")
    
    return checksum[:length].upper()


def validate_checksum(data: str, checksum: str) -> bool:
    """
    Validate a checksum against data.
    
    Args:
        data: Original data string
        checksum: Checksum to validate
        
    Returns:
        True if checksum is valid, False otherwise
    """
    expected_checksum = calculate_checksum(data, len(checksum))
    return expected_checksum.upper() == checksum.upper()


def is_valid_base32(data: str) -> bool:
    """
    Check if a string contains only valid Base32 characters.
    
    Args:
        data: String to validate
        
    Returns:
        True if string contains only valid Base32 characters
    """
    valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    return all(c.upper() in valid_chars for c in data)
