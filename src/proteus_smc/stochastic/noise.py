"""
=============================================================================
Proteus-SMC — stochastic/noise.py
=============================================================================
Module d'injection de variables aléatoires et de bruit temporel neutre.
Ces opérations modifient le profil d'exécution sans altérer la valeur.
=============================================================================
"""

from typing import Callable, List, Tuple


def _noise_fadd(b: int, k: int) -> int:
    return ((b + k) - k) & 0xFF

def _noise_frot(b: int, k: int) -> int:
    # Rotation gauche puis droite de r bits — résultat toujours identique à b. Neutre.
    return b

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
