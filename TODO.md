# TODO — Proteus-SMC

Généré après architecture review + security review.
Format : `[ ]` à faire · `[x]` done · `[-]` won't fix / hors scope POC

---

## CRITICAL (bloquant pour soumission papier)

- [ ] **Remplacer xoroshiro128+ par un CSPRNG**
  - xoroshiro128+ n'est pas un CSPRNG : état reconstructible depuis 2 outputs 64-bit
  - Cible : HKDF-Expand (RFC 5869) ou ChaCha20 en mode keystream déterministe
  - Impact : toute la sécurité du cipher en dépend

- [ ] **Chiffrer ou supprimer `rnd_meta` du header**
  - `rnd_meta` expose `prng.choice(9)` par bloc en clair → fuite d'état PRNG
  - Option A : dériver `n_rnd` depuis le PRNG sans le transmettre (re-dérivé au déchiffrement)
  - Option B : chiffrer `rnd_meta` avec un keystream issu de `HKDF(mk, iv + "meta")`

- [ ] **PBKDF2 : passer à ≥ 200 000 itérations** (600 000 pour la production)
  - Actuellement 2000 → ~400 000 tentatives/s sur RTX 4090
  - Note : l'itération par bloc (PRNG) est à 100 — à réévaluer aussi

- [ ] **Corriger le test T2 (avalanche)**
  - Test actuel compare deux chiffrements avec IVs différents → mesure de l'entropie, pas de l'avalanche Feistel
  - Cible : fixer l'IV, comparer `_encrypt_block(p, i, iv)` vs `_encrypt_block(flip(p), i, iv)`

---

## HIGH (avant soumission)

- [ ] **`_round_key` : remplacer SHA-256(key ‖ data) par HMAC**
  - Construction actuelle vulnérable aux length extension attacks
  - `hmac.new(self._mk, struct.pack(">II", blk_idx, rnd), 'sha256').digest()`

- [ ] **Documenter et analyser les compositions dégénérées de primitives**
  - `(ADD, SUB)` s'annulent, `(XOR, XOR, XOR)` réduit à un seul XOR, etc.
  - Quantifier la probabilité d'une ronde faible et son impact sur la sécurité

- [ ] **Documenter que FMIX n'est pas bijective**
  - `0x9E = 2×79` → multiplication non injective mod 256
  - Même cas que SBOX : Feistel compense, mais le header du module est faux
  - Corriger le commentaire "9 primitives bijectives"

- [ ] **Preuve formelle ou réduction de sécurité**
  - Les tests empiriques (avalanche, Shannon, chi²) sont nécessaires mais pas suffisants
  - Formaliser : contre quel modèle d'attaquant le MTD apporte-t-il un avantage sur un cipher standard ?
  - Minimum : argumenter IND-CPA sous hypothèse CSPRNG

---

## MEDIUM (qualité du papier)

- [ ] **Supprimer `self._seed` (dead state)**
  - Assigné dans `__init__` mais jamais relu — soit l'utiliser, soit le retirer
  - Maintenir un secret en mémoire sans l'utiliser est une mauvaise pratique

- [ ] **Ajouter un commentaire sur l'invariant MAC-first**
  - L'ordre Encrypt-then-MAC protège contre les padding oracles
  - Documenter explicitement pourquoi inverser l'ordre serait catastrophique

- [ ] **Taille de bloc 64 bits : documenter le birthday bound**
  - Sweet32 : collisions possibles après ~32 GB de données avec la même clé
  - Ajouter dans le papier et dans le README (scope POC)

- [ ] **Rédiger le modèle de menace (threat model)**
  - Définir : attaquant passif, actif, avec/sans clé partielle
  - Définir ce que le MTD protège et ce qu'il ne protège pas

---

## LOW (nice to have)

- [-] **Side-channel resistance en Python**
  - Invalide par design : GC, bytecode CPython, thread scheduling
  - Won't fix pour le POC — à noter dans les limitations du papier

- [ ] **Implémenter le client chat** (`client/handshake.py`, `client/chat.py`)
  - Référencés dans CLAUDE.md mais absents du repo
  - Ajouter protection anti-replay (numéro de séquence ou nonce incrémental)

- [ ] **Régénérer les vecteurs de régression T8** après le remplacement du CSPRNG
  - Les vecteurs actuels sont liés à xoroshiro128+

---

## Done

- [x] Corriger PRNG : seed réduite à 16 octets, renommé xoroshiro128+
- [x] Remplacer SHA-256(key ‖ data) par HMAC-SHA256[:16] pour le MAC du ciphertext
- [x] Comparaison MAC en temps constant (`hmac.compare_digest`)
- [x] Cache MD5 pour `_sbox` (`lru_cache`)
- [x] Simplifier `_noise_frot` → `return b`
- [x] Offset T2 dynamique (ne plus hardcoder pour 2 blocs)
- [x] T8 : vrais vecteurs de régression avec IV fixe
