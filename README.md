# Proteus-SMC : Stochastic Metamorphic Cipher

**Proteus-SMC** (Stochastic Metamorphic Cipher) est un projet de recherche en cryptographie explorant le concept d'algorithmes à structure dynamique. Contrairement aux standards actuels comme l'AES dont la logique interne est statique, Proteus utilise un **moteur métamorphique** pour muter sa propre structure mathématique à chaque session, rendant la rétro-ingénierie et l'analyse de puissance (Side-Channel) statistiquement instables.

```
Plaintext  ──► Padding PKCS#7 ──► Blocs de 8 octets
                                       │
                              ┌────────▼────────────┐
                              │  SMCCipher.encrypt()│
                              │                     │
                              │  IV aléatoire (16B) │
                              │         │           │
                              │  PRNG(master_key,   │
                              │       IV + bloc_idx)│
                              │         │           │
                              │  n_rounds ← PRNG    │
                              │  (min_rnd..max_rnd) │
                              │         │           │
                              │  ┌──────▼──────┐    │
                              │  │  Feistel    │    │
                              │  │  L ─► R'    │    │
                              │  │  R ─► L'    │    │
                              │  │  F(R) = sto │    │
                              │  │  chastic    │    │
                              │  └─────────────┘    │
                              └─────────────────────┘
                                       │
                              Header + IV + RoundMeta + CT
```

---

## 📖 Fondements Théoriques & Définitions

Ce projet repose sur l'hybridation de plusieurs concepts avancés de la sécurité informatique et des mathématiques appliquées :

### 1. Métamorphisme Cryptographique
En informatique, le métamorphisme désigne un code capable de réécrire sa propre structure tout en conservant sa sémantique (sa fonction finale). Dans le cadre de **Proteus**, cela signifie que l'algorithme n'est pas une suite d'opérations fixes, mais une séquence générée dynamiquement à partir d'un catalogue de primitives.

### 2. Stochastie
La stochastie introduit la théorie des probabilités dans le processus de chiffrement. Au lieu d'une mutation purement linéaire, le système utilise des lois de distribution pour décider de l'insertion de "code mort" ou de la complexité des rondes. Cela crée une signature temporelle et algorithmique unique pour chaque message.

### 3. Réseau de Feistel
Structure algorithmique fondamentale qui divise les données en deux blocs ($L$ et $R$). Sa propriété majeure est la **réversibilité** : elle permet de déchiffrer un message sans que la fonction de mutation interne ($F$) ait besoin d'être elle-même inversible. C'est le cœur permettant l'usage de mutations chaotiques sécurisées.

### 4. Moving Target Defense (MTD)
Stratégie de cybersécurité visant à augmenter l'incertitude et la complexité pour un attaquant en changeant continuellement les propriétés de la cible. Proteus applique ce paradigme directement au niveau de la couche de chiffrement.

---

## 🎯 Objectifs de Recherche

L'ambition de ce dépôt est de servir de base à un papier de recherche intitulé :
> *"Stochastic Metamorphism in Feistel Networks: Enhancing Side-Channel Resistance through Algorithmic Mutation."*

Les axes de recherche principaux sont :
1. **Synchronisation Déterministe :** Prouver que deux entités peuvent générer le même algorithme complexe à partir d'une graine (seed) partagée sans échange de code.
2. **Analyse de l'Effet d'Avalanche :** Vérifier qu'une mutation mineure en entrée (1 bit) entraîne une modification radicale et imprévisible de la sortie (proche de 50%).
3. **Résistance Side-Channel :** Théoriser comment l'instabilité algorithmique empêche l'extraction de clés par analyse de consommation électrique ou de timing.

---

## 🛠️ Architecture du Projet (V1)

Le projet est divisé en modules distincts pour faciliter l'audit et la recherche :

```
src/
├── engine/       Le moteur de synchronisation basé sur le PRNG
├── primitives/   Bibliothèque de "gènes" mathématiques
├── core/         Réseau de Feistel et gestion des cycles de mutation
└── stochastic/   Module d'injection de variables aléatoires et de bruit
smc_tests.py      Suite de validation (9 tests)
```

### 1. Moteur de Synchronisation (`engine/`)

- **Algorithme** : XorShift128+ — période 2^128 − 1
- **Initialisation** : PBKDF2-SHA256(master_key, session_id, iter=100)
- **Propriété clé** : même graine → même séquence, toujours

### 2. Bibliothèque de Primitives (`primitives/`) — 9 "gènes"

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

### 3. Réseau de Feistel Stochastique (`core/`)

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

### 4. Couche Stochastique (`stochastic/`) — Bruit Temporel

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
Offset  Taille  Champ
──────  ──────  ───────────────────────────────────────────
0       3       Magic
3       1       Version
4       4       n_blocks
8       4       Checksum
12      16      IV
28      2×N     Round Metadata
28+2N   N×8     Blocs chiffrés
```

#### Magic — `b"SMC"` · 3 octets · offset 0

Signature fixe identifiant le format. Lu en premier par `decrypt()` avant tout
autre traitement. Si les trois octets ne correspondent pas exactement à
`b"SMC"`, une `ValueError` est levée immédiatement. Permet de rejeter sans
ambiguïté des données d'un format inconnu ou d'un autre protocole.

#### Version — `0x01` · 1 octet · offset 3

Numéro de version du format de ciphertext. Comparé à la constante
`SMCCipher.VERSION`. Permet l'évolution future du format sans casser
la rétrocompatibilité : un récepteur peut détecter un ciphertext produit
par une version plus récente et refuser de le déchiffrer plutôt que de
produire silencieusement un résultat incorrect.

#### n_blocks — `uint32 big-endian` · 4 octets · offset 4

Nombre de blocs de 8 octets qui composent le ciphertext. Calculé lors du
chiffrement comme `len(plaintext_paddé) // 8`. Utilisé par `decrypt()` pour
deux opérations critiques :
- lire exactement `n_blocks × 2` octets de métadonnées de rondes,
- itérer sur exactement `n_blocks × 8` octets de données chiffrées.

Sans ce champ, le récepteur ne peut pas déterminer où se terminent les
métadonnées et où commencent les blocs chiffrés.

#### Checksum — `SHA-256(master_key ∥ header ∥ IV ∥ RoundMeta ∥ CT)[:4]` · 4 octets · offset 8

Code d'intégrité calculé sur l'intégralité du ciphertext, **clé incluse** :

```
checksum = SHA-256(master_key ∥ header ∥ IV ∥ round_meta ∥ ct_data)[:4]
```

Vérifié par `decrypt()` **avant** toute tentative de déchiffrement. Remplit
deux rôles simultanément :

- **Intégrité** : toute modification d'un octet du ciphertext en transit
  invalide le checksum et lève une `ValueError` (protection contre le
  bit-flipping).
- **Authentification implicite** : comme `master_key` participe au calcul,
  un récepteur avec une clé incorrecte obtient un checksum attendu différent
  et échoue immédiatement, sans avoir à tenter de déchiffrer quoi que ce soit.

#### IV — `secrets.token_bytes(16)` · 16 octets · offset 12

Vecteur d'initialisation généré aléatoirement à chaque appel à `encrypt()`
via le CSPRNG du système. Utilisé comme composante du `session_id` de chaque
PRNG de bloc :

```
PRNG_bloc_i = DeterministicPRNG(master_key, IV ∥ uint32(i))
```

Un IV différent produit un PRNG différent, donc un nombre de rondes différent
et des primitives différentes, même à clé et plaintext identiques. C'est le
mécanisme qui garantit le **métamorphisme** : deux chiffrements successifs du
même message donnent deux ciphertexts distincts (validé par le test T6).
L'IV n'est pas secret — il est transmis en clair dans l'en-tête.

#### Round Metadata — `uint16 big-endian × N` · 2×N octets · offset 28

Tableau de N entiers sur 16 bits, un par bloc, indiquant combien de rondes
Feistel ont été appliquées à ce bloc lors du chiffrement. La valeur de chaque
entrée est comprise entre `min_rounds` (8) et `max_rounds` (16) et est
déterminée stochastiquement par le PRNG.

Ce champ est indispensable au déchiffrement : `_decrypt_block()` doit rejouer
le PRNG exactement autant de fois qu'à l'encryption pour reconstituer les
séquences de primitives de chaque ronde. Sans ce compte, il est impossible
de savoir combien de rondes inverses appliquer.

#### Blocs chiffrés — 8 octets × N · offset 28 + 2×N

Concaténation des N blocs de 8 octets produits par `_encrypt_block()`.
Chaque bloc est le résultat du réseau de Feistel après le swap final :
`CT_bloc = R_n ∥ L_n`. La taille totale est toujours un multiple de 8
grâce au padding PKCS#7 appliqué avant le découpage en blocs.

---

## 🔢 Concepts Mathématiques

### 1. L'arithmétique modulaire

C'est le socle de presque toute la cryptographie. L'idée est simple :
on fait des calculs dans un espace fini, comme une horloge qui revient
à 0 après 12.

Dans le SMC, on travaille toujours sur des octets, donc des entiers
entre 0 et 255. Quand un calcul dépasse 255, on "revient au début" :

```
200 + 100 = 300  →  300 mod 256 = 44
```

C'est noté (a + b) mod 256, ou &0xFF en code.

**Pourquoi c'est utile ?** Parce que l'opération inverse existe toujours.
Si on a ajouté k, on peut retrouver l'original en soustrayant k.
L'information n'est jamais détruite, juste transformée — propriété
indispensable pour pouvoir déchiffrer.

### 2. Le XOR (ou exclusif, ⊕)

Le XOR est l'opération la plus utilisée en cryptographie. Sur un bit :

```
0 ⊕ 0 = 0
0 ⊕ 1 = 1
1 ⊕ 0 = 1
1 ⊕ 1 = 0   ← deux fois le même = retour à 0
```

Sa propriété magique : **appliquer deux fois annule l'opération**.

```
message ⊕ clé = chiffré
chiffré ⊕ clé = message   ← on retrouve l'original
```

C'est la base du chiffrement par flot (one-time pad). Seul, le XOR
n'est pas sûr si la clé se répète. C'est pourquoi le SMC le combine
avec d'autres opérations.

### 3. Les rotations de bits (ROL / ROR)

Un octet est une suite de 8 bits, par exemple :

```
10110100
```

Une rotation gauche de 2 positions décale tous les bits vers la gauche,
et les bits qui "tombent" à gauche reviennent à droite :

```
ROL(10110100, 2) = 11010010
```

Contrairement à un simple décalage, aucun bit n'est perdu — ils font
le tour. L'opération inverse (ROR, rotation droite) restaure exactement
l'original. C'est donc **bijectif** : chaque entrée possible donne une
sortie différente.

### 4. La bijectivité — pourquoi c'est fondamental

Une fonction f est bijective si elle met en correspondance chaque entrée
avec **exactement une** sortie, et chaque sortie correspond à **exactement
une** entrée. Autrement dit : elle est inversible sans perte.

```
Bijective :     {0,1,2,3} → {3,1,0,2}   ✓ (chaque valeur apparaît une fois)
Non bijective : {0,1,2,3} → {0,0,1,2}   ✗ (0 apparaît deux fois → perte)
```

**Dans le SMC**, les primitives ADD, SUB, XOR, ROL, ROR, MUL (avec k
impair) sont toutes bijectives mod 256. Cela garantit qu'aucune
information n'est détruite pendant le chiffrement, et que le
déchiffrement est toujours possible.

La multiplication mérite une note : (b × k) mod 256 n'est bijective
que si k est impair. C'est pourquoi le code force k à être impair avec
`k | 1`. La raison mathématique : un nombre impair est toujours
premier avec 256 (= 2⁸), et deux nombres premiers entre eux ont
toujours un inverse multiplicatif modulo l'un d'eux.

### 5. Le réseau de Feistel

C'est la structure qui permet au SMC d'utiliser des fonctions **non
nécessairement inversibles** tout en garantissant que le chiffrement
reste réversible. C'est la même idée qui est à la base du DES (1977).

On coupe le bloc de 8 octets en deux moitiés L (gauche) et R (droite).
À chaque ronde :

```
L_nouveau  =  R
R_nouveau  =  L  ⊕  F(R)
```

où F est n'importe quelle fonction — même destructrice. Le XOR final
rend tout réversible car :

```
R  =  L_nouveau
L  =  R_nouveau  ⊕  F(L_nouveau)
```

Il suffit de rejouer F sur L_nouveau (qu'on connaît) pour retrouver L
par XOR. F n'a jamais besoin d'être inversée directement.

```
  L₀                   R₀
   │                     │
   │              ┌──────┤
   │              │      │
   │           F(R₀)     │
   │              │      │
   └──────⊕───────┘      │
          │               │
         R₁              L₁     R₁ = L₀ ⊕ F(R₀)
          │               │     L₁ = R₀
          │       ┌───────┤
          │       │       │
          │    F(R₁)      │
          │       │       │
          └───⊕───┘       │
              │             │
             R₂            L₂     R₂ = L₁ ⊕ F(R₁)
              ⋮             ⋮      L₂ = R₁
             Rₙ            Lₙ

  Ciphertext = Rₙ ∥ Lₙ   (swap final standard)
```

Plus on ajoute de rondes, plus le mélange est profond et plus l'effet
d'avalanche est fort.

### 6. Le PRNG et la notion de graine (seed)

Un PRNG (Pseudo-Random Number Generator) est un algorithme qui produit
une séquence de nombres qui *ressemble* à de l'aléatoire, mais qui est
en réalité entièrement déterminée par sa valeur initiale : la **graine**.

```
graine 42  →  7, 193, 4, 88, 201, 12, ...  (toujours la même séquence)
graine 43  →  251, 6, 177, 39, 14, 200, ...  (séquence complètement différente)
```

**Dans le SMC**, le PRNG utilisé est XorShift128+, dont l'état interne
est représenté par deux entiers de 64 bits. À chaque appel, l'état
évolue via des opérations XOR et des décalages de bits :

```
s1  ^=  s0
s0  =  ROL(s0, 55)  ^  s1  ^  (s1 << 14)
s1  =  ROL(s1, 36)
résultat = (s0 + s1) mod 2⁶⁴
```

Sa période est 2¹²⁸ − 1 : on peut générer 2¹²⁸ nombres avant que la
séquence ne se répète — un nombre astronomiquement grand.

**La synchronisation** repose entièrement sur cette propriété : si
l'émetteur et le récepteur initialisent leur PRNG avec la même graine,
ils génèrent exactement la même séquence et donc les mêmes choix
de primitives dans le même ordre.

### 7. La dérivation de clé (PBKDF2)

On ne se sert jamais directement de la clé brute. On la fait passer
par PBKDF2 (Password-Based Key Derivation Function 2), qui produit
une clé dérivée de longueur quelconque.

```
master_key = PBKDF2-SHA256(key, seed, iterations=2000, length=64)
```

Trois propriétés importantes :

**Étirement** : Les 2000 itérations rendent une attaque par force brute
2000 fois plus coûteuse qu'une attaque directe sur SHA-256.

**Avalanche** : Un seul bit changé dans `key` ou `seed` produit une
`master_key` complètement différente (propriété de SHA-256).

**Séparation des domaines** : La même clé avec deux seeds différentes
produit deux master_keys sans aucune relation mathématique entre elles —
ce qui isole les sessions les unes des autres.

### 8. L'effet d'avalanche

C'est le critère principal de qualité d'un chiffrement : modifier
**un seul bit** dans le message d'entrée doit modifier environ
**50% des bits** en sortie, de manière imprévisible.

Le SMC mesure cet effet via la **distance de Hamming** entre deux
ciphertexts obtenus depuis des plaintexts différant d'un seul bit :

```
distance_Hamming(a, b) = nombre de bits différents entre a et b
```

Le test T2 a mesuré **48.0% ± 3.1%** — très proche de l'idéal
théorique de 50%. C'est la signature d'un bon mélange cryptographique.
Un résultat inférieur à 40% indiquerait une structure exploitable.

### 9. L'entropie de Shannon

L'entropie mesure la **quantité d'information** (ou d'imprévisibilité)
d'une source. Pour une séquence d'octets, elle est définie par :

```
H = − Σ  p(x) × log₂(p(x))
```

où p(x) est la fréquence de l'octet x dans les données.

- H = 0 bits/octet : données complètement prévisibles (ex. : b"\x00" × N)
- H = 8 bits/octet : distribution parfaitement uniforme sur 0..255

Un bon ciphertext doit avoir H ≥ 7.0 bits/octet. Le SMC atteint
H ≈ 7.3 bits/octet sur des textes variés.

**Note sur le biais de Miller-Madow** : sur moins de ~512 octets,
l'estimateur de Shannon sous-estime l'entropie réelle. C'est un biais
statistique bien documenté, non un défaut du chiffrement.

### 10. Le checksum HMAC (intégrité)

Le SMC calcule un code d'intégrité sur l'ensemble du ciphertext :

```
checksum = SHA-256(master_key ∥ header ∥ IV ∥ round_meta ∥ données)[:4]
```

Si un seul octet du ciphertext est modifié pendant le transit, le
checksum recalculé ne correspondra plus — le déchiffrement sera rejeté.
Cela protège contre la falsification (attaque dite "bit flipping").

La master_key est incluse dans le calcul, ce qui signifie qu'un
attaquant sans la clé ne peut pas forger un checksum valide — même
s'il connaît la structure exacte du format. C'est la propriété
fondamentale d'un **MAC (Message Authentication Code)**.

### Résumé des dépendances entre concepts

```
Arithmétique modulaire
    └──► Bijectivité des primitives (ADD, MUL, ROL...)
             └──► Sécurité de la fonction F

XOR
    └──► Réversibilité du réseau de Feistel
             └──► Déchiffrement garanti même avec F non bijective

Graine + PBKDF2
    └──► master_key dérivée
             ├──► PRNG synchronisé → sélection stochastique des primitives
             └──► Clés de ronde → paramètre k de chaque primitive

IV aléatoire
    └──► PRNG distinct par chiffrement → métamorphisme (T6)

Effet d'avalanche + Entropie + HMAC
    └──► Métriques de validation du prototype (T2, T3, T7)
```

---

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

---

## Limites Connues (POC v1)

1. **Performance** : La dérivation PBKDF2 par bloc rend le chiffrement O(N×2000) — inadapté à la production. Une dérivation unique par session est préférable.
2. **Entropie sur petits messages** : Le biais de Miller-Madow affecte la mesure pour N < 500 octets. L'entropie *réelle* est proche de 8 bits/octet mais l'estimateur de Shannon sur peu d'échantillons sous-estime.
3. **Sécurité** : Ce prototype n'a pas subi d'audit cryptographique. Le SBOX n'est pas garanti bijectif. À utiliser uniquement à des fins de recherche.

---

## Installation

Le projet utilise un **src-layout** : les sources se trouvent dans `src/proteus_smc/`
et sont exposées comme paquet Python installable via `pyproject.toml`.

### Structure de packaging

```
pyproject.toml          ← déclaration du paquet (setuptools, PEP 517)
src/
└── proteus_smc/        ← paquet Python importable après installation
    ├── __init__.py     ← re-exporte SMCCipher, SMCConfig, DeterministicPRNG…
    ├── engine/
    ├── primitives/
    ├── stochastic/
    └── core/
```

`pyproject.toml` déclare deux cibles :

| Cible              | Commande                        | Dépendance ajoutée      |
|--------------------|---------------------------------|-------------------------|
| Bibliothèque seule | `pip install -e .`              | aucune (stdlib uniquement) |
| Avec client ECDH   | `pip install -e ".[client]"`    | `cryptography>=41.0`    |

### Environnement virtuel (recommandé)

```bash
python3 -m venv .venv
source .venv/bin/activate      # Linux / macOS
# .venv\Scripts\activate       # Windows

pip install -e .               # installe proteus-smc en mode éditable
pip install -e ".[client]"     # + cryptography pour le client ECDH
```

En mode éditable (`-e`), toute modification des sources dans `src/` est
immédiatement visible sans réinstallation.

### Vérification

```bash
python3 -c "import proteus_smc; print(proteus_smc.__version__ if hasattr(proteus_smc, '__version__') else 'proteus_smc OK')"
```

---

## Usage

```python
from proteus_smc import SMCCipher, SMCConfig

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

Les sous-modules restent accessibles directement si nécessaire :

```python
from proteus_smc.engine import DeterministicPRNG
from proteus_smc.primitives import PRIMITIVES, N_PRIM
from proteus_smc.stochastic import NOISE_OPS
from proteus_smc.core import SMCCipher, SMCConfig
```

## Lancer les Tests

```bash
python3 smc_tests.py
```

> `smc_tests.py` gère lui-même son `sys.path` et fonctionne sans installation
> préalable, directement depuis la racine du dépôt.
