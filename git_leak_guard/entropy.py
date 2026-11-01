"""
Shannon entropy calculation for detecting high-entropy secrets and tokens.
"""

import math
from typing import Optional


def shannon_entropy(data: str) -> float:
    """
    Compute Shannon entropy of a string: H = -sum(p * log2(p)).
    Higher entropy indicates more randomness (e.g. Base64 or Hex encoded tokens).
    """
    if not data:
        return 0.0

    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


# Typical character sets
HEX_CHARS = set("0123456789abcdefABCDEF")
BASE64_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=")


def is_high_entropy(token: str, min_length: int = 16, threshold: float = 3.5) -> bool:
    """
    Check if a string qualifies as high-entropy based on character set and entropy threshold.
    """
    if len(token) < min_length:
        return False

    entropy = shannon_entropy(token)
    
    # Hex tokens typically have max entropy ~4.0, threshold 3.0+
    is_hex = all(c in HEX_CHARS for c in token)
    if is_hex and len(token) >= 32 and entropy >= 3.0:
        return True

    # Base64 tokens have max entropy ~6.0, threshold 3.8+
    is_b64 = all(c in BASE64_CHARS for c in token)
    if is_b64 and len(token) >= 20 and entropy >= threshold:
        return True

    return entropy >= threshold
