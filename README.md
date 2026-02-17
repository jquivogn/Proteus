# Stochastic Metamorphic Cipher (SMC) — v1.0

## Vue d'ensemble

Le SMC est un prototype de chiffrement expérimental dans lequel l'algorithme
lui-même **mute à chaque exécution** de manière probabiliste, tout en restant
parfaitement synchronisé entre émetteur et récepteur grâce à une **graine commune**.

```
Plaintext  ──► Padding PKCS#7 ──► Blocs de 8 octets
                                       │
                              ┌────────▼────────────┐
                              │  SMCCipher.encrypt() │
                              │                      │
                              │  IV aléatoire (16B)  │
                              │         │            │
                              │  PRNG(master_key,    │
                              │       IV + bloc_idx) │
                              │         │            │
                              │  n_rounds ← PRNG     │
                              │  (min_rnd..max_rnd)  │
                              │         │            │
                              │  ┌──────▼──────┐     │
                              │  │  Feistel    │     │
                              │  │  L ─► R'    │     │
                              │  │  R ─► L'    │     │
                              │  │  F(R) = sto │     │
                              │  │  chastic    │     │
                              │  └─────────────┘     │
                              └─────────────────────┘
                                       │
                              Header + IV + RoundMeta + CT
```

## Architecture

### 1. Moteur de Synchronisation (`DeterministicPRNG`)

- **Algorithme** : XorShift128+ — période 2^128 − 1
- **Initialisation** : PBKDF2-SHA256(master_key, session_id, iter=100)
- **Propriété clé** : même graine → même séquence, toujours

### 2. Bibliothèque de Primitives (9 "gènes")

| ID | Nom       | Opération                              | Bijectif ? |
|----|-----------|----------------------------------------|------------|
| 0  | XOR       | b ⊕ k                                  | ✓ toujours |
| 1  | ADD       | (b + k) mod 256                        | ✓          |
| 2  | SUB       | (b − k) mod 256                        | ✓          |
| 3  | MUL       | (b × k_odd) mod 256                    | ✓ si k impair |
| 4  | ROL       | rotation gauche, r = k & 7 bits        | ✓          |
| 5  | ROR       | rotation droite, r = k & 7 bits        | ✓          |
| 6  | BSWAP     | permutation de bits guidée par k       | ✓          |
| 7  | SBOX      | substitution MD5-dérivée non-linéaire  | partielle  |
| 8  | FMIX      | mélange Feistel interne                | ✓          |

> Note : SBOX n'est pas garanti bijectif. Cela est acceptable dans une
> structure de Feistel car la réversibilité globale ne dépend pas de
> la bijectivité de F.

### 3. Réseau de Feistel Stochastique

```
L₀ = block[:4]    R₀ = block[4:]

Pour r = 0..n_rounds−1 :
    F_R  = F_stochastic(Rᵣ, r, block_idx, PRNG)
    Rᵣ₊₁ = Lᵣ ⊕ F_R
    Lᵣ₊₁ = Rᵣ

Ciphertext = R_{n} ∥ L_{n}   (swap final standard)
```

La fonction F est **stochastique** : à chaque appel, le PRNG sélectionne :
1. Une séquence de `prims_per_round` primitives parmi les 9 disponibles
2. Une permutation aléatoire de cette séquence
3. Des opérations de bruit (p ≈ 30%) insérées de manière transparente

### 4. Couche Stochastique (Bruit Temporel)

Quatre opérations neutres sont insérées aléatoirement entre les primitives :

| Nom     | Opération              | Effet sur la valeur |
|---------|------------------------|---------------------|
| FADD    | +k puis −k             | Aucun               |
| FROT    | ROL puis ROR           | Aucun               |
| DXOR    | ⊕k ⊕k                  | Aucun               |
| NOOP    | identité               | Aucun               |

Ces opérations **modifient le profil d'exécution** (temps, consommation
de registres) sans modifier la valeur chiffrée, rendant les attaques
par canaux auxiliaires plus complexes.

### 5. Format du Ciphertext

```
Offset  Taille  Contenu
──────  ──────  ───────────────────────────────────────────
0       3       Magic : b"SMC"
3       1       Version : 0x01
4       4       n_blocks : uint32 big-endian
8       4       Checksum SHA-256[:4] sur tout le reste
12      16      IV aléatoire (secrets.token_bytes)
28      2×N     Métadonnées rondes : n_rounds par bloc (uint16 BE)
28+2N   N×8     Blocs chiffrés
```

## Résultats des Tests

| Test                  | Résultat | Détail                          |
|-----------------------|----------|---------------------------------|
| T1 — Intégrité        | ✓ PASS   | 7 cas couverts                  |
| T2 — Avalanche        | ✓ PASS   | 48.0% ± 3.1% (cible ≥ 45%)     |
| T3 — Entropie         | ✓ PASS   | H ≥ 7.30 bits/octet             |
| T4 — Synchronisation  | ✓ PASS   | Rejet clé/graine incorrectes    |
| T5 — Isolation Seeds  | ✓ PASS   | Cross-session rejeté            |
| T6 — Métamorphisme    | ✓ PASS   | IVs distincts → CT distincts    |
| T7 — Intégrité HMAC   | ✓ PASS   | Toute modification détectée     |
| T8 — Régression       | ✓ PASS   | 4 vecteurs stables              |
| T9 — PRNG             | ✓ PASS   | χ² = 299.1/5.15, Bern = 0.2995 |

**Score : 9/9 — 100%**

## Limites Connues (POC v1)

1. **Performance** : La dérivation PBKDF2 par bloc rend le chiffrement O(N×2000) — inadapté à la production. Une dérivation unique par session est préférable.
2. **Entropie sur petits messages** : Le biais de Miller-Madow affecte la mesure pour N < 500 octets. L'entropie *réelle* est proche de 8 bits/octet mais l'estimateur de Shannon sur peu d'échantillons sous-estime.
3. **Sécurité** : Ce prototype n'a pas subi d'audit cryptographique. Le SBOX n'est pas garanti bijectif. À utiliser uniquement à des fins de recherche.

## Usage

```python
from smc_core import SMCCipher, SMCConfig

# Configuration (optionnelle)
cfg = SMCConfig(
    min_rounds=8,
    max_rounds=16,
    noise_prob=0.3,
    prims_per_round=3
)

# Initialisation (clé ≥ 16B, seed arbitraire)
cipher = SMCCipher(
    key  = b"ma-cle-secrete-16",
    seed = b"session-id-partagee",
    cfg  = cfg
)

# Chiffrement
plaintext  = b"Message confidentiel"
ciphertext = cipher.encrypt(plaintext)

# Déchiffrement (même clé + même seed)
receiver = SMCCipher(b"ma-cle-secrete-16", b"session-id-partagee")
recovered = receiver.decrypt(ciphertext)
assert recovered == plaintext
```

## Lancer les Tests

```bash
python3 smc_tests.py
```
