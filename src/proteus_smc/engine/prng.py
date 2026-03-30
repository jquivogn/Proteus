"""
=============================================================================
Proteus-SMC — engine/prng.py
=============================================================================
Moteur de synchronisation déterministe : xoroshiro128+
Période : 2^128 − 1.  Synchronisé entre émetteur et récepteur via graine.
=============================================================================
"""

import hashlib
import struct


class DeterministicPRNG:
    """
    PRNG xoroshiro128+ initialisé par une graine dérivée via PBKDF2-SHA256.
    État : 2 × uint64 → période 2^128 - 1.
    Synchronisé entre émetteur et récepteur via la même graine.
    """

    def __init__(self, seed: bytes, session_id: bytes = b""):
        material = hashlib.pbkdf2_hmac(
            'sha256', seed, session_id + b"smc-prng", iterations=100, dklen=16
        )
        s = list(struct.unpack(">2Q", material))
        self._s = [x if x != 0 else 0xDEADBEEFCAFEBABE for x in s]

    def next_u64(self) -> int:
        s = self._s
        s0, s1 = s[0], s[1]
        result = (s0 + s1) & 0xFFFFFFFFFFFFFFFF
        s1 ^= s0
        s[0] = (((s0 << 55) | (s0 >> 9)) ^ s1 ^ (s1 << 14)) & 0xFFFFFFFFFFFFFFFF
        s[1] = ((s1 << 36) | (s1 >> 28)) & 0xFFFFFFFFFFFFFFFF
        return result

    def next_float(self) -> float:
        return (self.next_u64() >> 11) / (2**53)

    def choice(self, n: int) -> int:
        threshold = (1 << 64) - ((1 << 64) % n)
        while True:
            v = self.next_u64()
            if v < threshold:
                return v % n

    def bernoulli(self, p: float) -> bool:
        return self.next_float() < p

    def shuffle(self, lst: list) -> list:
        r = list(lst)
        for i in range(len(r) - 1, 0, -1):
            j = self.choice(i + 1)
            r[i], r[j] = r[j], r[i]
        return r
