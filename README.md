# Homomorphic DES Supervisor Evaluation on ESP32

Privacy-preserving Discrete Event System (DES) supervisor evaluation using
EC-ElGamal homomorphic encryption on an ESP32 microcontroller.

The system computes supervisor enablement functions **without ever decrypting
the state vector** — the plant state remains encrypted throughout the simulation.

---

## What this does

In Supervisory Control Theory, a supervisor observes the current state of a
plant and decides which events to enable or disable. Normally this requires
knowing the current state in plaintext.

This project implements the same computation **homomorphically**: the state
vector is encrypted with EC-ElGamal, transitions are applied as ciphertext
operations, and enablement checks are evaluated as encrypted dot products.
The only value ever decrypted is the scalar enablement result (0 or 1) — the
state distribution itself is never revealed.

---

## Repository structure

```
├── generator_ultrades.ipynb          # Notebook: synthesise supervisors → .h file
├── homomorphic-esp32-ultrades.ino    # Arduino sketch: run HE benchmark on ESP32
└── supervisor_data_<PROBLEM>.h       # Generated: C arrays for the chosen problem
```

---

## Requirements

### Notebook
- Python 3.8+
- .NET Runtime 8.0 (installed automatically by Cell 1)
- [UltraDES-Python](https://github.com/lacsed/UltraDES-Python) (installed automatically by Cell 1)
- Runs on Linux or Google Colab

### ESP32 sketch
- ESP32 Arduino core (tested on ESP32-32)
- No external libraries — only the ESP32 core + built-in mbedTLS

---

## How to use

### Step 1 — Generate the header file (notebook)

1. Open `generator_ultrades.ipynb` in Jupyter or Google Colab.
2. In **Cell 3**, set `PROBLEM` to one of:
   - `small_factory` — simplest two-machine pipeline
   - `extended_small_factory` — three-machine pipeline
   - `fms` — Flexible Manufacturing System (Queiroz & Cury 2000)
3. Run all cells top-to-bottom (**Kernel → Restart & Run All**).
4. The notebook writes `supervisor_data_<PROBLEM>.h` in the current directory.

### Step 2 — Flash the ESP32

1. Copy `supervisor_data_<PROBLEM>.h` to the same folder as the `.ino` sketch.
2. In `homomorphic-esp32-ultrades.ino`, update the include at the top:
   ```cpp
   #include "supervisor_data_fms.h"   // ← change to match your problem
   ```
3. Open the sketch in Arduino IDE, select your ESP32 board, and flash.
4. Open Serial Monitor at **115200 baud**.

---

## Available problems

### `small_factory`
Two machines M1 and M2 connected by a buffer.
M1 can only finish when the buffer is empty; M2 can only start when it is full.

```
M1 ──e1(start)──► busy ──e2(finish)──► idle
M2 ──e3(start)──► busy ──e4(finish)──► idle
Buf: empty ──e2──► full ──e3──► empty
```

- 4 global events, 1 spec, 1 local modular supervisor
- Monolithic: 6 states

### `extended_small_factory`
Three machines M1, M2, M3 with two buffers B1 and B2.

```
M1 ──a1/b1──► M2 ──a2/b2──► M3 ──a3/b3──►
       B1 (between M1-M2)
              B2 (between M2-M3)
```

- 6 global events, 2 specs, 2 local modular supervisors
- Monolithic: 18 states

### `fms` — Flexible Manufacturing System (Queiroz & Cury 2000)
Eight machines (C1, C2, Lathe, Mill, Robot, AM, C3, PD) with eight
buffer/routing specifications (E1–E8).

E7 and E8 share events through the plant and are combined as E78 = E7 ∥ E8
before synthesis to resolve the conflict (see Chapter 6 of the thesis).

- 31 global events, 7 specs, 7 local modular supervisors
- Monolithic: too large for flash (omitted automatically)
- Largest supervisor: S6 with 164 states

---

## How the notebook works (Cell by Cell)

| Cell | Purpose |
|------|---------|
| 1 | Install .NET runtime and UltraDES-Python |
| 2 | Import UltraDES automata primitives |
| 3 | **Set `PROBLEM` here** — the only cell you need to edit |
| 4 | Plant and specification DFA definitions for all three problems |
| 5 | Helper functions: extract UltraDES DFA → Python dict |
| 6 | Supervisor synthesis (monolithic + local modular) |
| 7 | Generate `supervisor_data_<PROBLEM>.h` with direct C arrays |

### What Cell 7 generates

Instead of embedding a JSON string (which requires runtime parsing and ~3×
heap overhead), Cell 7 emits typed C arrays directly in PROGMEM (flash).

For each supervisor with prefix `lmN_` (local modular) or `mono_` (monolithic):

| Array | Type | Size | Content |
|-------|------|------|---------|
| `<prefix>init` | `int8_t` | `num_states` | One-hot initial state vector |
| `<prefix>enable` | `int8_t` | `EVENT_COUNT × num_states` | Enablement matrix (flat) |
| `<prefix>tcnt` | `uint16_t` | `EVENT_COUNT` | Transition pair counts per event |
| `<prefix>trans` | `int16_t` | `2 × Σtcnt` | Flat `(from, to)` transition pairs |

The `SupDesc` struct links name + num_states + pointers to all four arrays.
The firmware iterates `LMOD_SUPS[0..LMOD_COUNT-1]` at runtime.

### Monolithic flash limit

If the monolithic supervisor's estimated flash footprint exceeds
`MONO_FLASH_LIMIT` (default 1.4 MB), it is omitted from the `.h` file.
The firmware detects this via the `HAS_MONO` macro and skips the monolithic
benchmark automatically — no manual changes needed.

---

## How the firmware works

### Encryption

Each supervisor state is encrypted independently as an EC-ElGamal ciphertext
over secp256k1:

```
Enc(m):  r ← random
         c1 = r·G
         c2 = m·G + r·Pub
```

Ciphertexts are stored **compressed** (33 bytes per point = 66 bytes per
ciphertext) instead of full `mbedtls_ecp_point` structs (~400 bytes).
This reduces memory usage by 6× and allows supervisors with 100+ states to
fit in the ESP32's 320 KB DRAM.

### Homomorphic transition

When event `ev` fires, the state vector is updated via sparse matrix
multiplication — implemented as **ciphertext copies**:

```
enc_new[to] = enc[from]   for each (from, to) pair in B[ev]
enc_new[s]  = Enc(0)      for all other states s
```

No decryption or EC arithmetic is needed for this step.

### Enablement check

To check whether event `gi` is enabled, the firmware computes the encrypted
dot product of the enablement row with the state vector:

```
Enc(result) = Σ  enable[gi][s] · enc[s]
```

This is implemented with `elgamal_add_ct` (homomorphic addition).
The result is then decrypted to get 0 (disabled) or 1 (enabled).

### Shadow optimisation

For deterministic DES, the state is always **one-hot**: exactly one state is
active at any time. The firmware keeps a cleartext **shadow** copy of the
state distribution, updated via the same transitions as the encrypted state.

When `shadow` shows exactly one active state (`active_count == 1`), the
enablement result is read directly from the PROGMEM table — **zero EC
operations**. Decryption is only triggered if `active_count > 1`, which
should never happen in a valid deterministic supervisor.

This is why `Total HE decrypts: 0` appears in the output — the shadow
handles all checks without needing to decrypt. The encrypted state is still
updated correctly on every transition; it just never needs to be decrypted
because the shadow already knows the answer.

### Oracle

A pure cleartext oracle runs in parallel with the HE evaluation. Every step,
the oracle's enablement vector is compared with the HE result. A `FAIL` means
the HE computation produced a wrong answer.

---

## Benchmark results

Results from the three problems on an ESP32-32 at 240 MHz:

### `small_factory`
| Benchmark | Supervisors | States | Total time | Avg/step |
|-----------|-------------|--------|-----------|----------|
| Monolithic | 1 | 6 | 181 µs | 45 µs |
| Local modular | 1 | 6 | 154 µs | 38 µs |

### `extended_small_factory`
| Benchmark | Supervisors | States | Total time | Avg/step |
|-----------|-------------|--------|-----------|----------|
| Monolithic | 1 | 18 | 378 µs | 63 µs |
| Local modular | 2 | 6+6 | 291 µs | 48 µs |

### `fms`
| Benchmark | Supervisors | States | Total time | Avg/step |
|-----------|-------------|--------|-----------|----------|
| Monolithic | — | too large | skipped | — |
| Local modular | 7 | up to 164 | 9545 µs | 561 µs |

All benchmarks pass (`Result: PASS`) — HE output matches oracle on every step.

---

## Key design decisions

**Why EC-ElGamal and not a lattice scheme?**
EC-ElGamal is additively homomorphic and requires only scalar multiplication
and point addition — both available in the ESP32's built-in mbedTLS library
with no external dependencies. Lattice schemes (BFV, CKKS) would be more
general but require kilobytes of key material and are not available in mbedTLS.

**Why secp256k1 instead of secp256r1?**
secp256k1 has `a = 0` which enables a faster Jacobian point-addition formula
in mbedTLS (~15–25% faster scalar multiplication). The security level is
equivalent.

**Why compressed points?**
A full `mbedtls_ecp_point` allocates heap-allocated MPI limbs (~200 bytes per
coordinate). With 164 states × 2 points per ciphertext, that would be ~65 KB
just for S6 — more than the ESP32 can provide contiguously. Compressed points
(33 bytes each) reduce this to ~10 KB. Full structs are only created
transiently during arithmetic and freed immediately.

**Why PROGMEM C arrays instead of JSON?**
JSON requires runtime parsing into a heap-allocated document (~3× the raw data
size). For the FMS, that would need ~15 MB of heap — impossible on the ESP32.
PROGMEM arrays are read directly from flash with `pgm_read_byte` / `pgm_read_word`,
with zero heap overhead and zero parse time.

---

## References

- Queiroz, M. H., & Cury, J. E. R. (2000). *Modular supervisory control of
  large scale discrete event systems.* Discrete Event Systems, 269–278.
- UltraDES: https://github.com/lacsed/UltraDES-Python
- EC-ElGamal homomorphic encryption: Elgamal, T. (1985). *A public key
  cryptosystem and a signature scheme based on discrete logarithms.*
  IEEE Transactions on Information Theory, 31(4), 469–472.