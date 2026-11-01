import math
from git_leak_guard.entropy import shannon_entropy, is_high_entropy


def test_shannon_entropy_empty():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_uniform():
    # String of identical characters has 0 entropy
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_shannon_entropy_random():
    # High entropy string
    token = "aF9#k2!xP0$wL9@z"
    ent = shannon_entropy(token)
    assert ent > 3.5


def test_is_high_entropy():
    # Long random token
    assert is_high_entropy("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", min_length=16, threshold=3.0)
    # Simple dictionary word / identifier
    assert not is_high_entropy("passwordpassword", min_length=16, threshold=3.5)
