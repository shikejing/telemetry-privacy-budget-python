"""Seeded, reproducible randomization.

Noise for a given aggregate bucket is derived *purely* from the tenant master
seed and the bucket coordinates (tenant, window start, dimension values).
There is no global RNG state and no dependence on processing order:
processing the same input twice, or in a different order, yields the exact
same noise. The additive Laplace noise bounds the influence of a single user
on a published aggregate.
"""
from __future__ import annotations

import hashlib
import math
import random
import struct


def _derive_stream_key(
    master_seed: int,
    tenant_id: str,
    window_start_ms: int,
    dims: tuple[tuple[str, str], ...],
) -> bytes:
    h = hashlib.sha256()
    h.update(b"priv-telemetry-noise/v1")
    h.update(str(master_seed).encode("utf-8"))
    h.update(b"\x00")
    h.update(tenant_id.encode("utf-8"))
    h.update(struct.pack(">q", window_start_ms))
    for k, v in sorted(dims):
        h.update(b"\x1f")
        h.update(k.encode("utf-8"))
        h.update(b"=")
        h.update(v.encode("utf-8"))
    return h.digest()


def bucket_noise(
    master_seed: int,
    tenant_id: str,
    window_start_ms: int,
    dims: tuple[tuple[str, str], ...],
    sensitivity: float = 1.0,
    epsilon: float = 1.0,
) -> float:
    """Laplace noise scaled to ``sensitivity / epsilon`` for one bucket.

    Both the scale and the pseudo-random draw are deterministic functions of
    the arguments. Repeated calls with identical arguments return the
    identical float; reordering the input events changes nothing.
    """
    if epsilon <= 0:
        raise ValueError("epsilon must be positive")
    key = _derive_stream_key(master_seed, tenant_id, window_start_ms, dims)
    rng = random.Random(int.from_bytes(key[:8], "big"))
    scale = sensitivity / epsilon
    # Inverse-CDF sampling of Laplace(0, scale) from a uniform draw.
    p = rng.random()
    if p < 0.5:
        return scale * math.log(2.0 * p)
    return -scale * math.log(2.0 * (1.0 - p))
