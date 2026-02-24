# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Activate the existing virtual environment
source .venv/bin/activate

# Install the library in editable mode (stdlib only, no external deps)
pip install -e .

# Install with the client optional extra (adds cryptography>=41.0 for ECDH)
pip install -e ".[client]"

# Run all tests — works without installing; smc_tests.py manages sys.path itself
python3 smc_tests.py

# Run the encrypted chat client (requires [client] extra)
python3 client/chat.py listen --port 5000               # Terminal 1
python3 client/chat.py connect --port 5000              # Terminal 2
python3 client/chat.py connect --host HOST --port 5000  # remote peer
```

**Packaging**: `pyproject.toml` uses a setuptools src-layout. `[tool.setuptools.packages.find] where = ["src"]` auto-discovers `proteus_smc` and its subpackages. The `[client]` optional dependency group adds `cryptography` without pulling it in for library-only consumers.

Core library: stdlib only. Client: requires `cryptography>=41.0` for X25519.

## Project

**Proteus-SMC** (Stochastic Metamorphic Cipher) is a cryptography research project targeting a paper on *"Stochastic Metamorphism in Feistel Networks: Enhancing Side-Channel Resistance through Algorithmic Mutation."* The cipher mutates its own mathematical structure per session using a shared seed, without exchanging code — applying Moving Target Defense (MTD) at the cipher layer.

## Architecture

All source packages live under `src/proteus_smc/`. The test runner sits at the root and injects `src/` into `sys.path`. The client folder holds the standalone chat application.

```
src/proteus_smc/
├── __init__.py   re-exports all public symbols
├── engine/       DeterministicPRNG (XorShift128+ PRNG)
├── primitives/   9 byte-level mathematical primitives ("genes")
├── stochastic/   4 neutral noise operations (timing layer)
└── core/         SMCConfig + SMCCipher (Feistel network)
client/
├── handshake.py  ECDH X25519 handshake (proposition Variante B)
└── chat.py       terminal messaging client (listen / connect modes)
smc_tests.py      test suite (9 test categories)
pyproject.toml    packaging (setuptools src-layout)
proposition.md    handshake protocol design (PSK + ECDH variants)
```

### `core/cipher.py`

**`engine/prng.py` → `DeterministicPRNG`** — XorShift128+ PRNG seeded via `PBKDF2-SHA256(seed, session_id + b"smc-prng", iter=100)`. This is the synchronization engine: same seed → same sequence on both sender and receiver.

**`primitives/library.py`** — 9 byte-level bijective operations (`PRIMITIVES` list): XOR, ADD, SUB, MUL, ROL, ROR, BSWAP, SBOX, FMIX. Note: SBOX is not guaranteed bijective, but correctness is ensured by the Feistel structure.

**`stochastic/noise.py`** — 4 neutral noise operations (`NOISE_OPS`): FADD, FROT, DXOR, NOOP. Modify execution timing without changing values (Side-Channel resistance layer).

**`core/cipher.py` → `SMCConfig`** — Dataclass with cipher parameters: `block_size=8`, `min_rounds=8`, `max_rounds=16`, `noise_prob=0.30`, `prims_per_round=3`.

**`core/cipher.py` → `SMCCipher`** — Stateless per-operation (all state derived from IV + block index), safe to share between concurrent send/receive threads. Key lifecycle:
1. Constructor derives a 64-byte master key via `PBKDF2-SHA256(key, seed + b"smc-master", iter=2000)`
2. `encrypt()`: pads with PKCS#7, generates a random 16-byte IV, encrypts each 8-byte block with `_encrypt_block()`, prepends header (`b"SMC" + version + n_blocks + SHA-256[:4] checksum + IV + round metadata`)
3. `decrypt()`: verifies checksum first (authenticates with master key), then calls `_decrypt_block()` for each block

**Feistel network** (`_encrypt_block` / `_decrypt_block`): Standard balanced Feistel over 8-byte blocks (L=4B, R=4B). The round function `_F` is stochastic — the PRNG selects and shuffles `prims_per_round` primitives and inserts noise at `noise_prob` probability. Decryption uses `_replay_F_sequence()` to replay the PRNG state exactly, collecting all round sequences before applying inverse rounds in reverse order.

### `smc_tests.py`

Nine test categories (T1–T9): integrity, avalanche effect (≥45% bit diffusion), Shannon entropy (≥7.0 bits/byte), sender/receiver synchronization, seed isolation, metamorphism (same plaintext → distinct ciphertexts via random IV), HMAC integrity (tamper detection), regression vectors, and PRNG uniformity (chi-squared).

### Ciphertext format

```
Offset   Size    Content
0        3       Magic: b"SMC"
3        1       Version: 0x01
4        4       n_blocks (uint32 BE)
8        4       SHA-256[:4] checksum (keyed with master key)
12       16      IV (random)
28       2×N     Round counts per block (uint16 BE each)
28+2N    N×8     Encrypted blocks
```

### `client/` — Chat application

**`handshake.py`** — Implements the ECDH (X25519) handshake from `proposition.md` (Variante B). Three message types over a length-prefixed TCP framing: `HELLO` (65B), `HELLO_ACK` (65B), `ACK_CONFIRM` (17B). Returns `(session_key: bytes, session_seed: bytes, fingerprint: str)`. Both sides display the same 16-hex-char fingerprint derived from `SHA256(session_seed)` as a visual integrity check.

**`chat.py`** — CLI with two subcommands (`listen`, `connect`). After handshake, wraps the socket with `SMCCipher` and runs a receive thread + main-thread input loop. Encrypted messages are length-prefixed ciphertexts on the wire. `SMCCipher` is shared between threads safely (stateless per operation).

## Known limitations (POC v1)

- PBKDF2 is re-derived per block, making encryption O(N×2000) — not production-suitable
- No external cryptographic audit has been performed; for research use only
