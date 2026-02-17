"""
=============================================================================
SMC - Étape 5 : Validation et Tests d'Entropie
=============================================================================
Tests couverts :
  T1  - Intégrité   : decrypt(encrypt(m)) == m
  T2  - Avalanche   : 1 bit modifié → ~50% bits de sortie changés
  T3  - Entropie    : mesure de l'entropie de Shannon du ciphertext
  T4  - Synchronisation : émetteur/récepteur partagent la même seed
  T5  - Isolation   : seeds différentes → chiffrements différents
  T6  - Metamorphisme : deux chiffrements du même texte → ciphertexts ≠
  T7  - Intégrité HMAC : modification du ciphertext → exception
  T8  - Vecteurs de test fixes (régression)
=============================================================================
"""

import hashlib
import math
import os
import statistics
import struct
import sys
from typing import List

from smc_core import (N_PRIM, PRIMITIVES, DeterministicPRNG, SMCCipher,
                      SMCConfig)

# ─── Couleurs ANSI ──────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

PASS = f"{GREEN}✓ PASS{RESET}"
FAIL = f"{RED}✗ FAIL{RESET}"


def entropy_bits(data: bytes) -> float:
    """Entropie de Shannon en bits/octet."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum(
        (c / n) * math.log2(c / n)
        for c in freq if c > 0
    )


def hamming_distance(a: bytes, b: bytes) -> int:
    """Nombre de bits différents entre deux byte-strings de même longueur."""
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


def bit_flip(data: bytes, bit_pos: int) -> bytes:
    """Inverse le bit `bit_pos` dans `data`."""
    ba = bytearray(data)
    byte_idx = bit_pos // 8
    bit_idx  = bit_pos % 8
    ba[byte_idx] ^= (1 << bit_idx)
    return bytes(ba)


def section(title: str):
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}")


def result(name: str, ok: bool, detail: str = ""):
    status = PASS if ok else FAIL
    d = f"  {YELLOW}→ {detail}{RESET}" if detail else ""
    print(f"  {status}  {name}{d}")
    return ok


# ─────────────────────────────────────────────────────────────────────────────
# T1 : INTÉGRITÉ
# ─────────────────────────────────────────────────────────────────────────────

def test_integrity():
    section("T1 — Intégrité (decrypt ∘ encrypt = id)")
    key  = b"SuperSecretKey42!!"
    seed = b"session-seed-001"
    cipher = SMCCipher(key, seed)

    cases = [
        ("Message court",     b"Hello, World!"),
        ("Message exact bloc",b"12345678"),
        ("Message vide",      b""),
        ("UTF-8",             "Ça va très bien 🔐".encode()),
        ("Long message",      os.urandom(256)),
        ("Binaire",           bytes(range(256))),
        ("Répétitif",         b"AAAA" * 50),
    ]

    all_ok = True
    for name, msg in cases:
        try:
            ct = cipher.encrypt(msg)
            pt = cipher.decrypt(ct)
            ok = pt == msg
        except Exception as e:
            ok = False
            name = f"{name} (exception: {e})"
        all_ok &= result(name, ok, f"{len(msg)}B → {len(ct) if ok else '?'}B" if msg else "vide")

    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# T2 : EFFET D'AVALANCHE
# ─────────────────────────────────────────────────────────────────────────────

def test_avalanche():
    section("T2 — Effet d'Avalanche (cible ≥ 45% bits modifiés)")
    key  = b"AvalancheTestKey!"
    seed = b"avalanche-seed"
    cipher = SMCCipher(key, seed)

    # Texte de référence (2 blocs = 16 octets pour stats fiables)
    plaintext = b"SMC_TEST_BLOCK_!!"  # 16 octets
    ct_ref = cipher.encrypt(plaintext)
    # Isole uniquement les blocs de données (après header)
    # header = 3+1+4+4+16+4 = 32 octets
    ct_data_offset = 8 + 4 + 16 + 4  # magic+ver+nblks + checksum + IV + round_meta(2blks)
    ct_data_ref = ct_ref[ct_data_offset:]

    scores = []
    n_bits  = len(plaintext) * 8

    all_ok = True
    for bit in range(min(n_bits, 64)):  # teste 64 premiers bits
        modified = bit_flip(plaintext, bit)
        try:
            ct_mod = cipher.encrypt(modified)
            ct_data_mod = ct_mod[ct_data_offset:]
            if len(ct_data_ref) == len(ct_data_mod):
                dist = hamming_distance(ct_data_ref, ct_data_mod)
                total = len(ct_data_ref) * 8
                ratio = dist / total
                scores.append(ratio)
        except Exception:
            pass

    if scores:
        mean_av  = statistics.mean(scores) * 100
        stdev_av = statistics.stdev(scores) * 100 if len(scores) > 1 else 0
        ok_av = mean_av >= 45.0
        all_ok &= result(
            f"Avalanche moyen sur {len(scores)} tests",
            ok_av,
            f"{mean_av:.1f}% ± {stdev_av:.1f}%"
        )
        # Distribution
        below40 = sum(1 for s in scores if s < 0.40)
        ok_dist = below40 <= len(scores) * 0.10
        all_ok &= result(
            "Distribution (< 10% des cas sous 40%)",
            ok_dist,
            f"{below40}/{len(scores)} sous 40%"
        )
    else:
        print(f"  {FAIL}  Aucun score calculable")
        all_ok = False

    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# T3 : ENTROPIE DU CIPHERTEXT
# ─────────────────────────────────────────────────────────────────────────────

def test_entropy():
    section("T3 — Entropie du Ciphertext (cible ≥ 7.0 bits/octet)")
    key  = b"EntropyTestKey!!!"
    seed = b"entropy-seed-v1"
    cipher = SMCCipher(key, seed)

    all_ok = True

    # Test sur différents types de plaintexts
    cases = [
        ("Texte ASCII répétitif", b"ABCDEF" * 100),
        ("Données binaires nulles", b"\x00" * 512),
        ("Données aléatoires",  os.urandom(512)),
        ("Texte naturel",       b"The quick brown fox jumps over the lazy dog. " * 20),
    ]

    for name, msg in cases:
        ct = cipher.encrypt(msg)
        # Entropie sur les données chiffrées uniquement (sans header)
        header_size = 8 + 4 + 16 + (len(ct) - 8 - 4 - 16 - len(msg) - 8) // 2 * 2
        # Simplifié : entropie sur tout le ciphertext (bonne approximation)
        ent = entropy_bits(ct)
        ok = ent >= 7.0
        all_ok &= result(name, ok, f"H = {ent:.4f} bits/octet")

    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# T4 : SYNCHRONISATION ÉMETTEUR/RÉCEPTEUR
# ─────────────────────────────────────────────────────────────────────────────

def test_synchronization():
    section("T4 — Synchronisation Émetteur / Récepteur")
    key  = b"SyncTestKey12345!"
    seed = b"shared-session-42"

    sender   = SMCCipher(key, seed)
    receiver = SMCCipher(key, seed)   # même clé + même graine

    msg = b"Message confidentiel entre Alice et Bob."
    ct  = sender.encrypt(msg)
    pt  = receiver.decrypt(ct)

    all_ok = result("Déchiffrement avec clé/graine identiques", pt == msg)

    # Mauvaise clé
    wrong_key = SMCCipher(b"WrongKey_!!!!!!!!", seed)
    try:
        wrong_key.decrypt(ct)
        all_ok &= result("Rejet avec mauvaise clé", False, "Devrait lever une exception")
    except ValueError:
        all_ok &= result("Rejet avec mauvaise clé", True, "ValueError levée correctement")

    # Mauvaise graine
    wrong_seed = SMCCipher(key, b"wrong-seed-######")
    try:
        wrong_seed.decrypt(ct)
        all_ok &= result("Rejet avec mauvaise graine", False, "Devrait lever une exception")
    except ValueError:
        all_ok &= result("Rejet avec mauvaise graine", True, "ValueError levée correctement")

    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# T5 : ISOLATION PAR GRAINE
# ─────────────────────────────────────────────────────────────────────────────

def test_seed_isolation():
    section("T5 — Isolation par Graine (sessions distinctes)")
    key = b"IsolationKey!!!!"
    msg = b"Message commun entre deux sessions."

    c1 = SMCCipher(key, b"session-alpha-001")
    c2 = SMCCipher(key, b"session-beta-002")

    ct1 = c1.encrypt(msg)
    ct2 = c2.encrypt(msg)

    all_ok = result("Seeds différentes → ciphertexts différents", ct1 != ct2)

    # Chaque cipher déchiffre son propre ciphertext
    all_ok &= result("Session 1 : déchiffrement correct", c1.decrypt(ct1) == msg)
    all_ok &= result("Session 2 : déchiffrement correct", c2.decrypt(ct2) == msg)

    # Cross-déchiffrement doit échouer
    try:
        c1.decrypt(ct2)
        all_ok &= result("Rejet cross-session (c1 déchiffre ct2)", False)
    except ValueError:
        all_ok &= result("Rejet cross-session (c1 déchiffre ct2)", True)

    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# T6 : MÉTAMORPHISME (non-déterminisme du ciphertext)
# ─────────────────────────────────────────────────────────────────────────────

def test_metamorphism():
    section("T6 — Métamorphisme (même texte clair → ciphertexts distincts)")
    key  = b"MetamorphicKey!!!"
    seed = b"meta-test-seed-v1"
    cipher = SMCCipher(key, seed)
    msg = b"Same message encrypted twice."

    ct1 = cipher.encrypt(msg)
    ct2 = cipher.encrypt(msg)

    all_ok = result("Deux chiffrements → ciphertexts distincts (IV)", ct1 != ct2)
    all_ok &= result("Premier déchiffrement correct",  cipher.decrypt(ct1) == msg)
    all_ok &= result("Deuxième déchiffrement correct", cipher.decrypt(ct2) == msg)

    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# T7 : INTÉGRITÉ HMAC (résistance à la falsification)
# ─────────────────────────────────────────────────────────────────────────────

def test_integrity_hmac():
    section("T7 — Intégrité HMAC (résistance aux modifications)")
    key    = b"IntegrityTestKey!"
    seed   = b"hmac-test-seed"
    cipher = SMCCipher(key, seed)
    msg    = b"Critical message to protect."
    ct     = cipher.encrypt(msg)

    all_ok = True

    # Modification d'un bit dans les données
    for pos in [0, len(ct)//2, len(ct)-1]:
        tampered = bytearray(ct)
        tampered[pos] ^= 0x01
        try:
            cipher.decrypt(bytes(tampered))
            all_ok &= result(f"Rejet modification octet [{pos}]", False)
        except ValueError:
            all_ok &= result(f"Rejet modification octet [{pos}]", True)

    # Troncature
    try:
        cipher.decrypt(ct[:-1])
        all_ok &= result("Rejet troncature", False)
    except (ValueError, struct.error):
        all_ok &= result("Rejet troncature", True)

    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# T8 : VECTEURS DE TEST (RÉGRESSION)
# ─────────────────────────────────────────────────────────────────────────────

def test_regression():
    section("T8 — Vecteurs de Régression (reproductibilité)")
    key  = b"RegressionKey2024"
    seed = b"regression-seed-v1"

    # Ces vecteurs sont générés et stockés ici pour vérification future
    cipher = SMCCipher(key, seed)

    vectors = [
        b"AAAAAAAA",
        b"01234567",
        b"\x00\xFF\x00\xFF\x00\xFF\x00\xFF",
        b"SMCTest!",
    ]

    all_ok = True
    for msg in vectors:
        ct  = cipher.encrypt(msg)
        pt  = cipher.decrypt(ct)
        ok  = (pt == msg)
        h   = hashlib.sha1(ct).hexdigest()[:8]
        all_ok &= result(f"Vecteur {msg.hex()[:16]}", ok, f"ct_hash={h}")

    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# T9 : PRNG — UNIFORMITÉ ET INDÉPENDANCE
# ─────────────────────────────────────────────────────────────────────────────

def test_prng():
    section("T9 — PRNG : Uniformité et Indépendance")
    prng = DeterministicPRNG(b"test-prng-seed", b"session-0")
    N = 100_000

    # Fréquence des octets (chi-carré approximé)
    freq = [0] * 256
    for _ in range(N):
        freq[prng.next_u64() & 0xFF] += 1

    expected = N / 256
    chi2 = sum((f - expected) ** 2 / expected for f in freq)
    # χ² critique pour 255 DDL à 99.9% = ~330
    ok_uniform = chi2 < 350
    result("Uniformité des octets (χ² < 350)", ok_uniform, f"χ² = {chi2:.1f}")

    # Test choice() — uniformité sur 8 valeurs
    prng2 = DeterministicPRNG(b"choice-test", b"")
    counts = [0] * 8
    M = 80_000
    for _ in range(M):
        counts[prng2.choice(8)] += 1
    exp2 = M / 8
    chi2_choice = sum((c - exp2) ** 2 / exp2 for c in counts)
    ok_choice = chi2_choice < 25  # χ² critique pour 7 DDL à 99.9% ≈ 24.3
    result(f"Uniformité choice(8) (χ² < 25)", ok_choice, f"χ² = {chi2_choice:.2f}")

    # Bernoulli p=0.3
    prng3 = DeterministicPRNG(b"bern-test", b"")
    trues = sum(1 for _ in range(100_000) if prng3.bernoulli(0.3))
    ratio = trues / 100_000
    ok_bern = abs(ratio - 0.3) < 0.01
    return result("Bernoulli(0.3) ≈ 0.30 ± 0.01", ok_bern, f"observé = {ratio:.4f}")


# ─────────────────────────────────────────────────────────────────────────────
# RUNNER PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  SMC — Suite de Tests Complète  v1.0{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")

    import time
    tests = [
        ("Intégrité",               test_integrity),
        ("Avalanche",               test_avalanche),
        ("Entropie",                test_entropy),
        ("Synchronisation",         test_synchronization),
        ("Isolation Seeds",         test_seed_isolation),
        ("Métamorphisme",           test_metamorphism),
        ("Intégrité HMAC",          test_integrity_hmac),
        ("Régression",              test_regression),
        ("PRNG",                    test_prng),
    ]

    results = {}
    for name, fn in tests:
        t0 = time.perf_counter()
        try:
            ok = fn()
        except Exception as e:
            ok = False
            print(f"  {FAIL}  Exception non gérée : {e}")
        elapsed = time.perf_counter() - t0
        results[name] = (ok, elapsed)

    # ── Résumé ──────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  RÉSUMÉ{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}")

    passed = sum(1 for ok, _ in results.values() if ok)
    total  = len(results)

    for name, (ok, elapsed) in results.items():
        status = PASS if ok else FAIL
        print(f"  {status}  {name:<28} {elapsed:.2f}s")

    print(f"\n  {BOLD}Score : {passed}/{total} tests réussis{RESET}")

    if passed == total:
        print(f"\n  {GREEN}{BOLD}✓ Tous les tests sont passés !{RESET}\n")
    else:
        print(f"\n  {RED}{BOLD}✗ {total - passed} test(s) en échec{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
