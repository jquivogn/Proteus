# Proteus-SMC — Diagramme de protocole

## Vue d'ensemble du cycle de vie

```mermaid
flowchart TD
    subgraph INIT["🔑 Initialisation — SMCCipher"]
        K[/"key (≥16 bytes)"/]
        S[/"seed (bytes)"/]
        K & S --> PBKDF2_MK["PBKDF2-SHA256\nseed + 'smc-master'\n2000 itérations → 64 bytes"]
        PBKDF2_MK --> MK[("master_key\n64 bytes")]
    end

    subgraph ENC["🔒 Chiffrement — encrypt()"]
        PT[/"plaintext"/]
        PT --> PAD["PKCS#7 padding\n→ multiple de 8 bytes"]
        PAD --> SPLIT["Découper en blocs\nde 8 bytes chacun"]
        SPLIT --> IV["IV aléatoire\n16 bytes (secrets)"]
        IV & MK --> EB["_encrypt_block()\npour chaque bloc i"]
        EB --> CT_B["bloc chiffré\n+ n_rounds (i)"]
        CT_B --> HDR["Assembler l'entête\nMAGIC(3) + VER(1)\n+ n_blocks(4)"]
        HDR & IV & CT_B --> CS["SHA-256(\nmaster_key ‖ header\n‖ IV ‖ round_meta\n‖ ct_data\n)[:4]  → checksum"]
        CS --> WIRE["📦 Ciphertext final\nMAGIC|VER|n_blocks|checksum\n|IV|round_meta|blocs"]
    end

    subgraph DEC["🔓 Déchiffrement — decrypt()"]
        WIRE2[/"ciphertext"/]
        WIRE2 --> PARSE["Parser l'entête\n→ n_blocks, checksum,\nIV, round_meta"]
        PARSE --> CHK{"Vérifier\nchecksum"}
        CHK -->|"❌ invalide"| ERR["ValueError\n(tamper / clé incorrecte)"]
        CHK -->|"✅ valide"| DB["_decrypt_block()\npour chaque bloc i"]
        DB --> UNPAD["PKCS#7 unpad"]
        UNPAD --> PT2[/"plaintext récupéré"/]
    end

    MK -.->|partagé| DEC
```

---

## Réseau de Feistel — chiffrement d'un bloc

```mermaid
flowchart TD
    subgraph FEISTEL_ENC["_encrypt_block(block, blk_idx, IV)"]
        direction TB
        BLK[/"bloc 8 bytes"/]
        BLK --> SPLIT2["L = bloc[0:4]\nR = bloc[4:8]"]
        SPLIT2 --> PRNG_INIT["DeterministicPRNG\nPBKDF2(master_key,\nIV ‖ blk_idx ‖ 'smc-prng')"]
        PRNG_INIT --> NR["n_rounds ← PRNG.choice\n(max - min + 1) + min\n∈ [8, 16]"]
        NR --> LOOP["Pour r = 0 … n_rounds-1"]
        LOOP --> F["_F(R, r, blk_idx, PRNG)\n→ FR"]
        F --> XOR["new_R = L ⊕ FR"]
        XOR --> SWAP["L, R = R, new_R"]
        SWAP -->|"prochain round"| LOOP
        SWAP -->|"fin"| FSWAP["swap final\n→ R ‖ L"]
        FSWAP --> OUT[/"8 bytes chiffrés + n_rounds"/]
    end

    subgraph F_FUNC["Fonction F stochastique — _F(data, rnd, blk_idx, prng)"]
        direction TB
        RK["round_key = SHA-256(\nmaster_key ‖ blk_idx ‖ rnd\n)"]
        PSEL["Sélection de 3 primitives\nparmi 9 (XOR,ADD,SUB,\nMUL,ROL,ROR,BSWAP,\nSBOX,FMIX)"]
        PSHUF["Permutation stochastique\nde l'ordre (prng.shuffle)"]
        PSEL --> PSHUF
        PSHUF --> APPLY["Pour chaque byte v :"]
        APPLY --> NOISE{"Bernoulli(0.30)\n→ bruit ?"}
        NOISE -->|"oui"| NFUNC["noise_op(v, k)\n(FADD/FROT/DXOR/NOOP)\nneutre sur la valeur"]
        NFUNC --> PRIM["prim(v, k)"]
        NOISE -->|"non"| PRIM
        PRIM -->|"3 primitives"| APPLY
        RK --> APPLY
    end
```

---

## Déchiffrement d'un bloc — stratégie replay

```mermaid
flowchart TD
    subgraph FEISTEL_DEC["_decrypt_block(block, blk_idx, IV, n_rounds)"]
        CB[/"bloc chiffré 8 bytes"/]
        CB --> PRNG2["DeterministicPRNG\n(même graine qu'au chiffrement)"]
        PRNG2 --> CONSUME["Consommer le token n_rounds\n(aligner le PRNG)"]
        CONSUME --> REPLAY["Rejouer _replay_F_sequence()\npour chaque round r ∈ [0, n_rounds-1]\n→ (seq_primitives, round_key, noise_flags)"]
        REPLAY --> UNSWAP["Annuler swap final\nL = bloc[4:8]\nR = bloc[0:4]"]
        UNSWAP --> RLOOP["Pour r = n_rounds-1 … 0\n(ordre inverse)"]
        RLOOP --> FD["_F_deterministic(L, seq_r, rk_r, noise_r)\n→ FL  (séquences précalculées)"]
        FD --> RXOR["orig_L = R ⊕ FL"]
        RXOR --> RSWAP["L, R = orig_L, L"]
        RSWAP -->|"round précédent"| RLOOP
        RSWAP -->|"fin"| PLAIN[/"L ‖ R = 8 bytes déchiffrés"/]
    end
```

---

## PRNG déterministe — synchronisation émetteur/récepteur

```mermaid
flowchart LR
    subgraph SENDER["Émetteur"]
        SK[/"master_key + IV + blk_idx"/]
        SK --> P1["DeterministicPRNG\nXorShift128+\n(période 2¹²⁸−1)"]
        P1 --> SEQ1["séquence déterministe\nchoice / shuffle / bernoulli"]
    end

    subgraph RECEIVER["Récepteur"]
        RK2[/"master_key + IV + blk_idx\n(identiques)"/]
        RK2 --> P2["DeterministicPRNG\nXorShift128+\n(même état initial)"]
        P2 --> SEQ2["séquence identique\n→ replay exact"]
    end

    SEQ1 -. "même graine\n→ même séquence" .-> SEQ2
```

---

## Format du ciphertext

```mermaid
packet-beta
  0-23: "MAGIC (3 bytes)"
  24-31: "VER (1)"
  32-63: "n_blocks (4)"
  64-95: "checksum SHA-256[:4]"
  96-223: "IV (16 bytes)"
  224-255: "round_meta (2×N bytes)"
  256-383: "blocs chiffrés (N×8 bytes)"
```
