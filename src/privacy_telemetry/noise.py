"""Deterministic, reproducible randomization for aggregation output.

Noise is *fixed per output cell*: given ``(noise_seed, aggregation_id,
bin_key, epsilon)`` the same Laplace sample is always produced. Removing a
user's contribution therefore leaves every remaining cell's noise untouched,
so a post-revocation aggregate is bit-for-bit identical to the aggregate
computed with that user never present.
"""

from __future__ import annotations

import hashlib
import math


def _uniform_unit(seed: int, aggregation_id: str, bin_key: str) -> float:
    """Return a deterministic pseudo-uniform value in (0, 1)."""
    digest = hashlib.sha256(
        f"{seed}|{aggregation_id}|{bin_key}".encode("utf-8")
    ).digest()
    # 64 bits -> integer, map into open interval (0, 1)
    value = int.from_bytes(digest[:8], "big")
    return (value + 1) / (2**64 + 2)


def laplace_sample(seed: int, aggregation_id: str, bin_key: str, sensitivity: float) -> float:
    """Deterministic Laplace(0, ``sensitivity``) sample."""
    u = _uniform_unit(seed, aggregation_id, bin_key) - 0.5
    return -sensitivity * math.log(1 - 2 * abs(u)) * (1 if u >= 0 else -1)


def noisy_value(
    true_value: float, seed: int, aggregation_id: str, bin_key: str, epsilon: float
) -> float:
    """Add Laplace noise with sensitivity 1 to one cell."""
    if epsilon <= 0:
        raise ValueError("epsilon must be positive")
    noise = laplace_sample(seed, aggregation_id, bin_key, 1.0 / epsilon)
    return true_value + noise


def clip_nonneg(value: float) -> float:
    """Clamp a noisy count to a non-negative, two-decimal value."""
    return round(max(0.0, value), 6)
