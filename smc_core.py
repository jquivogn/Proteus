"""
=============================================================================
Stochastic Metamorphic Cipher (SMC) - Core Implementation  v1.0
=============================================================================
Architecture : Réseau de Feistel à rondes variables et stochastiques
Moteur       : PRNG déterministe (XorShift128+) synchronisé par graine
Stochastie   : Sélection probabiliste des primitives + bruit temporel neutre
=============================================================================
"""

import hashlib
import struct
import secrets
from typing import Callable, List, Tuple
from dataclasses import dataclass


# ─────────────────────────────────────────────────────────────────────────────
# ÉTAPE 1 : MOTEUR DE SYNCHRONISATION DÉTERMINISTE
# ─────────────────────────────────────────────────────────────────────────────

class DeterministicPRNG:
    """
    PRNG XorShift128+ initialisé par une graine dérivée via PBKDF2-SHA256.
    Période : 2^128 - 1.  Synchronisé entre émetteur et récepteur.
    """

    def __init__(self, seed: bytes, session_id: bytes = b""):
        material = hashlib.pbkdf2_hmac(
            'sha256', seed, session_id + b"smc-prng", iterations=100, dklen=32
        )
        s = list(struct.unpack(">4Q", material))
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


# ─────────────────────────────────────────────────────────────────────────────
# ÉTAPE 2 : BIBLIOTHÈQUE DE PRIMITIVES ("GÈNES")
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# ÉTAPE 4 : COUCHE STOCHASTIQUE — OPÉRATIONS DE BRUIT NEUTRES
# ─────────────────────────────────────────────────────────────────────────────

def _noise_fadd(b: int, k: int) -> int:
    return ((b + k) - k) & 0xFF

def _noise_frot(b: int, k: int) -> int:
    r = k & 7
    return b if r == 0 else (((b << r) | (b >> (8 - r))) >> r | ((b << r) | (b >> (8 - r))) << (8 - r)) & 0xFF

def _noise_dxor(b: int, k: int) -> int:
    return b ^ k ^ k   # identité

def _noise_noop(b: int, k: int) -> int:
    return b

NOISE_OPS: List[Tuple[str, Callable]] = [
    ("FADD", _noise_fadd),
    ("FROT", _noise_frot),
    ("DXOR", _noise_dxor),
    ("NOOP", _noise_noop),
]
N_NOISE = len(NOISE_OPS)


# ─────────────────────────────────────────────────────────────────────────────
# ÉTAPE 3 : CONFIGURATION ET CŒUR FEISTEL
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SMCConfig:
    block_size: int = 8            # octets (64 bits)
    min_rounds: int = 8
    max_rounds: int = 16
    noise_prob: float = 0.30       # probabilité d'insertion de bruit
    prims_per_round: int = 3       # primitives empilées dans F


class SMCCipher:
    """
    Interface principale du Stochastic Metamorphic Cipher.

    Format ciphertext :
      [ b"SMC" (3) | version (1) | n_blocks (4) | checksum (4) |
        IV (16) | round_meta (2×n_blocks) | blocs chiffrés ]
    """

    MAGIC   = b"SMC"
    VERSION = 0x01
    BS      = 8   # block size fixe
    HALF    = 4   # demi-bloc

    def __init__(self, key: bytes, seed: bytes, cfg: SMCConfig = None):
        if len(key) < 16:
            raise ValueError("Clé ≥ 16 octets requise")
        self.cfg = cfg or SMCConfig()
        self._mk = hashlib.pbkdf2_hmac(
            'sha256', key, seed + b"smc-master", iterations=2000, dklen=64
        )
        self._seed = seed

    # ── PRNG de bloc ────────────────────────────────────────────────────────

    def _block_prng(self, iv: bytes, blk_idx: int) -> DeterministicPRNG:
        sid = iv + struct.pack(">I", blk_idx)
        return DeterministicPRNG(self._mk, sid)

    # ── Clé de ronde ────────────────────────────────────────────────────────

    def _round_key(self, blk_idx: int, rnd: int) -> bytes:
        return hashlib.sha256(
            self._mk + struct.pack(">II", blk_idx, rnd)
        ).digest()

    # ── Fonction F stochastique ──────────────────────────────────────────────

    def _F(self, data: bytes, rnd: int, blk_idx: int,
           prng: DeterministicPRNG) -> bytes:
        """
        Cœur métamorphique : sélection + permutation + bruit + application.
        """
        cfg = self.cfg

        # Sélection probabiliste des primitives
        seq = [PRIMITIVES[prng.choice(N_PRIM)] for _ in range(cfg.prims_per_round)]
        seq = prng.shuffle(seq)   # permutation stochastique de l'ordre

        rk = self._round_key(blk_idx, rnd)
        out = bytearray(data)

        for i in range(len(out)):
            k = rk[i % 32]
            v = out[i]

            for _, fn in seq:
                # Bruit temporel — neutre sur la valeur
                if prng.bernoulli(cfg.noise_prob):
                    _, nfn = NOISE_OPS[prng.choice(N_NOISE)]
                    v = nfn(v, k)   # idempotent
                v = fn(v, k)

            out[i] = v
        return bytes(out)

    # ── Capture de la séquence PRNG pour le déchiffrement ───────────────────

    def _replay_F_sequence(self, rnd: int, blk_idx: int,
                           prng: DeterministicPRNG):
        """
        Rejoue exactement le PRNG de _F et retourne :
        (seq_primitives, round_key, noise_flags_per_byte)
        """
        cfg = self.cfg
        seq = [PRIMITIVES[prng.choice(N_PRIM)] for _ in range(cfg.prims_per_round)]
        seq = prng.shuffle(seq)

        rk = self._round_key(blk_idx, rnd)
        noise_flags = []  # [(applied: bool, noise_idx: int|None)] × HALF × prims_per_round

        for i in range(self.HALF):
            for _ in seq:
                applied = prng.bernoulli(cfg.noise_prob)
                nidx = prng.choice(N_NOISE) if applied else None
                noise_flags.append((applied, nidx))

        return seq, rk, noise_flags

    # ── Chiffrement d'un bloc ────────────────────────────────────────────────

    def _encrypt_block(self, block: bytes, blk_idx: int,
                       iv: bytes) -> Tuple[bytes, int]:
        prng = self._block_prng(iv, blk_idx)
        n_rnd = self.cfg.min_rounds + prng.choice(
            self.cfg.max_rounds - self.cfg.min_rounds + 1
        )

        L, R = block[:self.HALF], block[self.HALF:]
        for r in range(n_rnd):
            FR = self._F(R, r, blk_idx, prng)
            new_R = bytes(a ^ b for a, b in zip(L, FR))
            L, R = R, new_R

        return R + L, n_rnd   # swap final standard

    # ── Déchiffrement d'un bloc ──────────────────────────────────────────────

    def _decrypt_block(self, block: bytes, blk_idx: int,
                       iv: bytes, n_rnd: int) -> bytes:
        """
        Stratégie : rejouer entièrement le PRNG pour collecter toutes
        les séquences par ronde, puis appliquer les rondes inverses.
        """
        prng = self._block_prng(iv, blk_idx)

        # Consomme le token du n_rnd (pour aligner le PRNG)
        _ = prng.choice(self.cfg.max_rounds - self.cfg.min_rounds + 1)

        # Collecte des séquences de toutes les rondes
        round_data = []
        for r in range(n_rnd):
            seq, rk, noise = self._replay_F_sequence(r, blk_idx, prng)
            round_data.append((seq, rk, noise))

        # Annuler le swap final
        L, R = block[self.HALF:], block[:self.HALF]

        # Rondes inverses
        for r in reversed(range(n_rnd)):
            seq, rk, noise = round_data[r]
            FL = self._F_deterministic(L, seq, rk, noise)
            orig_L = bytes(a ^ b for a, b in zip(R, FL))
            L, R = orig_L, L

        return L + R

    def _F_deterministic(self, data: bytes, seq, rk: bytes, noise_flags) -> bytes:
        """Version déterministe de F utilisant les séquences précalculées."""
        out = bytearray(data)
        nf_iter = iter(noise_flags)

        for i in range(len(out)):
            k = rk[i % 32]
            v = out[i]
            for _, fn in seq:
                applied, nidx = next(nf_iter, (False, None))
                if applied and nidx is not None:
                    _, nfn = NOISE_OPS[nidx]
                    v = nfn(v, k)   # neutre
                v = fn(v, k)
            out[i] = v
        return bytes(out)

    # ── Padding PKCS#7 ───────────────────────────────────────────────────────

    def _pad(self, data: bytes) -> bytes:
        n = self.BS - (len(data) % self.BS)
        return data + bytes([n] * n)

    def _unpad(self, data: bytes) -> bytes:
        n = data[-1]
        if n == 0 or n > self.BS or data[-n:] != bytes([n] * n):
            raise ValueError("Padding PKCS#7 invalide")
        return data[:-n]

    # ── API publique ─────────────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = secrets.token_bytes(16)
        padded = self._pad(plaintext)
        n_blks = len(padded) // self.BS

        ct_blocks, round_counts = [], []
        for i in range(n_blks):
            blk = padded[i*self.BS:(i+1)*self.BS]
            ct, nr = self._encrypt_block(blk, i, iv)
            ct_blocks.append(ct)
            round_counts.append(nr)

        ct_data   = b"".join(ct_blocks)
        rnd_meta  = b"".join(struct.pack(">H", r) for r in round_counts)
        header    = self.MAGIC + bytes([self.VERSION]) + struct.pack(">I", n_blks)
        checksum  = hashlib.sha256(self._mk + header + iv + rnd_meta + ct_data).digest()[:4]

        return header + checksum + iv + rnd_meta + ct_data

    def decrypt(self, ciphertext: bytes) -> bytes:
        pos = 0

        if ciphertext[pos:pos+3] != self.MAGIC:
            raise ValueError("Magic invalide")
        pos += 3
        if ciphertext[pos] != self.VERSION:
            raise ValueError("Version incompatible")
        pos += 1
        n_blks = struct.unpack(">I", ciphertext[pos:pos+4])[0]
        pos += 4
        checksum = ciphertext[pos:pos+4]
        pos += 4
        iv = ciphertext[pos:pos+16]
        pos += 16
        rnd_meta = ciphertext[pos:pos+n_blks*2]
        round_counts = [struct.unpack(">H", rnd_meta[i*2:i*2+2])[0] for i in range(n_blks)]
        pos += n_blks * 2
        ct_data = ciphertext[pos:]

        # Vérification intégrité
        header = ciphertext[:8]
        exp_cs = hashlib.sha256(self._mk + header + iv + rnd_meta + ct_data).digest()[:4]
        if exp_cs != checksum:
            raise ValueError("Checksum invalide — clé incorrecte ou données corrompues")

        pt_blocks = []
        for i in range(n_blks):
            blk = ct_data[i*self.BS:(i+1)*self.BS]
            pt_blocks.append(self._decrypt_block(blk, i, iv, round_counts[i]))

        return self._unpad(b"".join(pt_blocks))
