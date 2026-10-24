import base64
import random


def random_base64(num_bytes, seed=0):
    """Deterministic base64 of random bytes: a stand-in for an encoded payload."""
    rng = random.Random(seed)
    return base64.b64encode(bytes(rng.randrange(256) for _ in range(num_bytes))).decode()
