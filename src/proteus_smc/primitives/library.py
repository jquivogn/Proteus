"""
=============================================================================
Proteus-SMC — primitives/library.py
=============================================================================
Bibliothèque de "gènes" mathématiques : 9 primitives bijectives.
=============================================================================
"""

import hashlib
import struct
from typing import Callable, List, Tuple


def _xor(b: int, k: int) -> int:
    return b ^ k

def _add(b: int, k: int) -> int:
    return (b + k) & 0xFF

def _sub(b: int, k: int) -> int:
    return (b - k) & 0xFF

def _mul(b: int, k: int) -> int:
    return (b * (k | 1)) & 0xFF          # k forcé impair → bijectif mod 256

def _rol(b: int, k: int) -> int:
    r = k & 7
    return b if r == 0 else ((b << r) | (b >> (8 - r))) & 0xFF

def _ror(b: int, k: int) -> int:
    r = k & 7
    return b if r == 0 else ((b >> r) | (b << (8 - r))) & 0xFF

def _bit_swap(b: int, k: int) -> int:
    if k & 1:
        b = ((b & 0x0F) << 4) | ((b >> 4) & 0x0F)
    if k & 2:
        b = int(f"{b:08b}"[::-1], 2)
    return b & 0xFF

def _sbox(b: int, k: int) -> int:
    m = hashlib.md5(struct.pack("B", k)).digest()
    return (m[b & 0x0F] ^ m[(b >> 4) & 0x0F] ^ k) & 0xFF

def _fmix(b: int, k: int) -> int:
    x = ((b & 0x0F) << 4) | ((b >> 4) & 0x0F)
    return ((x ^ k) * 0x9E ^ ((x ^ k) >> 3)) & 0xFF


PRIMITIVES: List[Tuple[str, Callable]] = [
    ("XOR",   _xor),
    ("ADD",   _add),
    ("SUB",   _sub),
    ("MUL",   _mul),
    ("ROL",   _rol),
    ("ROR",   _ror),
    ("BSWAP", _bit_swap),
    ("SBOX",  _sbox),
    ("FMIX",  _fmix),
]
N_PRIM = len(PRIMITIVES)
