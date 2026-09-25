# Homomorphic DES Supervisor Evaluation on ESP32

Privacy-preserving evaluation of Discrete Event System (DES) supervisors with
EC-ElGamal homomorphic encryption on ESP32 microcontrollers, in two forms:

* a **single-board benchmark** that runs every supervisor on one MCU, and
* a **distributed engine** that partitions the supervisors across several nodes,
  each holding only its own encrypted state, under its own key.

State cells are encrypted, transitions are applied as ciphertext permutations,
and enablement is evaluated by homomorphically OR-ing the enabled cells. The only
value ever decrypted is that single enablement bit; the state vector exists only
as ciphertext.

A detailed walkthrough of every layer, with the literature behind each decision,
is in [`docs/code-explained.md`](docs/code-explained.md).

---

## Repository layout

```
homomorphic-esp32-ultrades/
├── homomorphic-esp32-ultrades.ino         SINGLE-BOARD benchmark sketch
├── supervisor_data_small_factory.h         generated supervisor data
├── supervisor_data_extended_small_factory.h
├── supervisor_data_fms.h
│
├── des_distributed/                        DISTRIBUTED engine (its own sketch)
│   ├── des_distributed.ino                   ESP32 entry point (config only)
│   ├── des_generic.h                         the engine — no Arduino/ESP-IDF
│   ├── des_transport.h                       UDP/IP multicast transport
│   ├── host_main.cpp                         POSIX entry point
│   ├── secrets.example.h                     template for secrets.h (Wi-Fi + cell key;
│   │                                         secrets.h itself is in .gitignore)
│   ├── README.md                             design, protocol, transport analysis
│   └── supervisor_data_*.h                   hard links to the root copies
│
├── notebook/
│   └── generator_ultrades.ipynb            synthesise supervisors → .h
│
└── docs/
    └── code-explained.md                   detailed walkthrough + references
```

The root doubles as the single-board sketch folder (Arduino requires the folder
to match the sketch name), which is why the generated headers live at the top.

```
  notebook/generator_ultrades.ipynb
        │  UltraDES: synthesise monolithic + local-modular + reduced supervisors
        │  Cell 6b:  validate the simulation trace against those supervisors
        │  Cell 7:   emit C arrays
        ▼
  supervisor_data_<PROBLEM>.h          PROGMEM arrays, no runtime parsing
        ├──────────────► homomorphic-esp32-ultrades.ino   one board, all supervisors
        └──────────────► des_distributed/                 N boards, one partition each
```

---

## Quick start

1. **Generate a header.** Open `notebook/generator_ultrades.ipynb` in Jupyter or
   Colab, set `PROBLEM` in Cell 3 and Restart & Run All. Cell 7 writes
   `supervisor_data_<PROBLEM>.h`; copy it to the repo root. Cell 6b refuses to
   emit a header whose simulation sequence the supervisors disable.
2. **Single board.** Point the `#include` in `homomorphic-esp32-ultrades.ino` at
   the header, select your ESP32 board, Serial 115200, flash. On an **ESP32-S3**,
   set `USB CDC On Boot` to `Enabled` on the native USB port and `Disabled` on
   the UART port — the wrong setting shows the ROM banner and then nothing.
3. **Distributed.** Copy `des_distributed/secrets.example.h` to `secrets.h`
   (Wi-Fi and the cell's authentication key), set `DES_DATA_HEADER`,
   `DES_NODE_ID` and `DES_NUM_NODES` in `des_distributed.ino`, and flash each
   board with a different `DES_NODE_ID`. See
   [`des_distributed/README.md`](des_distributed/README.md).

---

## Problems

| problem | events | supervisors | |
|---|---|---|---|
| `small_factory` | 4 | 1 | two machines, one-slot buffer; monolithic 6 states |
| `extended_small_factory` | 6 | 2 | three machines, two buffers; monolithic 18 states; only `a2`/`b2` are shared |
| `fms` (Queiroz & Cury 2000) | 31 | 7 | eight machines; E7 and E8 composed as `E78 = E7 ∥ E8` to resolve their conflict; largest supervisor 164 states; monolithic too large for flash, omitted |

---

## How it works

**Encryption.** Textbook EC-ElGamal on NIST P-192 (secp192r1):

```
Setup:  priv ← random in [1, N-1],   Y = priv · G
Enc(m): r ← random,   (c1, c2) = (r · G,  m · G + r · Y)
Dec:    m·G = c2 − priv · c1,   m = 0 iff m·G is the point at infinity
```

A ciphertext is 50 bytes (two compressed points); 96-bit security.

**OR by addition.** EC-ElGamal is additively homomorphic: `Enc(a) + Enc(b)`
decrypts to `(a+b)·G`. With binary cells and far fewer than N summands, the sum
is zero iff every cell is zero — a logical OR. The enable row's OR-sum over the
state vector is 1 iff the active state is in the enabled set, which is exactly
the supervisor's question. The runtime path only adds points; scalar
multiplications happen at setup (encryption) and in each row's final decryption.

**Transition.** The next state set is the image of the current one:

```
nxt[t] = ⋃ { enc[f] : (f,t) is a transition on ev }      nxt[s] = Enc(0) otherwise
```

Sources holding the literal `Enc(0)` are skipped, so the common case is one
ciphertext copy per pair; converging active sources are combined homomorphically.

**Optimisations**, from ~33 s (naive) to ~1 s on the heavy steps:

| # | optimisation | what it does |
|---|---|---|
| 1 | Conditional invariance | Precompute, per `(sup, event, row)`, whether the row can flip; re-decrypt only rows that can. |
| 2 | Persistent decompressed cache | Keep every cell as an `mbedtls_ecp_point` so the hot path never runs a modular square root. |
| 3 | Skip-`g_zero` summands | Inactive cells equal the global `Enc(0)` and are skipped — rows sum 1–2 cells instead of dozens. |
| 4 | Fused row-sum + decrypt | One `mbedtls_ecp_muladd` does the secret scalar mul and the final add. |
| 5 | Dual-core split | Work units split across both cores (sketches with two or more supervisors). Steps that decrypt several sums get 11–24 % faster; steps with one decryption gain nothing. |
| 6 | Share identical row sums | Rows are grouped by their set of non-`Enc(0)` cells; each set is decrypted once. 2.7–4.6× on `fms`. |

---

## Distributed operation

`des_distributed/` runs the same homomorphic core, but each node holds **only its
own supervisors**, encrypted under **its own keypair**. No ciphertext crosses the
network — only enablement bits — so there is no shared homomorphic key, no
threshold cryptography and no re-encryption.

Routing is derived at boot from the generated header:

| event class | mechanism | frames |
|---|---|---|
| local | apply locally | **0** |
| shared + controllable | `REQ → VOTE* → COMMIT → ACK*` (any participant may veto) | 2 + 2p |
| shared + uncontrollable | `NOTIFY → ACK*`, retransmitted until acknowledged | 1 + p |

An uncontrollable event cannot be vetoed: SCT forbids disabling it, and the plant
has already done it. The same property gives a plant check: a reported
uncontrollable event that a node's supervisors disable is one no machine could
have produced, and is rejected. The full local-modular family, which carries the
plant, catches every such event, so the sketch uses it; a reduced supervisor may
let one through. The protocol supplies sequencing, acknowledgement,
retransmission and atomicity end to end, so the transport only has to be
best-effort: **UDP/IP multicast** (RFC 1112), open and brokerless. Every frame is
signed with HMAC-SHA256/128 under the cell's key.

Protocol, transport analysis and the two-board results:
[`des_distributed/README.md`](des_distributed/README.md).

---

## Benchmark results

Single board, **ESP32-S3** @ 240 MHz, Arduino core 3.3.8, secp192r1, scalar
blinding on. All nine runs `PASS`: every homomorphic enablement vector matched the
cleartext oracle at every step. Measured `scalar_mul` = 69 ms, `muladd` = 5 ms.

| problem | family | sups | ciphertext | warm-up | avg/step | min | max | decryptions |
|---|---|---|---|---|---|---|---|---|
| `small_factory` | monolithic | 1 | 300 B | 237 ms | 77.8 ms | 74.9 | 85.4 | 4 |
| 4 events, 4 steps | local modular | 1 | 300 B | 239 ms | 77.5 ms | 74.8 | 85.0 | 4 |
| | **reduced** | 1 | **100 B** | 189 ms | **37.5 ms** | 0.16 | 74.9 | **2** |
| `extended_small_factory` | monolithic | 1 | 900 B | 487 ms | 94.4 ms | 75.5 | 126.1 | 7 |
| 6 events, 6 steps | local modular | 2 | 600 B | 513 ms | 91.4 ms | 74.9 | 120.6 | 8 |
| | **reduced** | 2 | **200 B** | 352 ms | **50.0 ms** | 0.18 | 75.0 | **4** |
| `fms` | monolithic | — | *omitted, exceeds flash* | | | | | |
| 31 events, 44 steps | local modular | 7 | 16 350 B | 12 358 ms | 335.4 ms | 75.4 | 1 423.7 | 190 |
| | **reduced** | 7 | **1 850 B** | 4 917 ms | **233.9 ms** | 0.19 | 916.4 | **145** |

* **Runtime is decryptions × scalar multiplication.** Time per decryption ranges
  68.6–80.9 ms across the runs, against 69 ms for one scalar multiplication;
  steps needing no decryption cost ~0.2 ms. The only software lever left is the
  number of decryptions.
* **Reduced is the fastest family** on all three problems, 1.4–2.1× faster than
  local modular.
* **Monolithic is not slower per step; it is infeasible at scale.** On
  `extended_small_factory` it needs fewer decryptions than local modular (7 vs 8),
  but the `fms` monolithic supervisor does not fit in flash. Local-modular
  decomposition is what makes `fms`, and distribution, possible.
* **The ESP32-S3 has no ECC accelerator** (`SOC_ECC_SUPPORTED` is off; it has
  RSA/MPI, AES and SHA). The ESP32-C6 and ESP32-H2 have one, and the core's
  prebuilt mbedTLS enables `CONFIG_MBEDTLS_HARDWARE_ECC` for them; the H2 has no
  Wi-Fi.

---

## Security notes

The cryptography is standard (textbook EC-ElGamal, NIST curve, hardware-RNG
entropy); the firmware is research-grade.

| # | channel | status | if exploited |
|---|---|---|---|
| 1 | Timing / power on the private scalar | **Closed** — every scalar mul is blinded | private-key recovery |
| 2 | Inactive cells are byte-identical to the global `Enc(0)` | Open | reveals the active state after each transition |
| 3 | The active cell's bytes are copied unchanged | Open | fingerprints the state trajectory |

Channels 2 and 3 need RAM access and are the price of optimisation 3: the skip is
fast *because* inactive cells equal `g_zero`. Closing them means re-randomising
every cell after every transition, about two scalar multiplications per cell —
tens of seconds per `fms` step. Not implemented.

In the distributed engine, frames are authenticated but not encrypted: the state
stays encrypted, but the timing of shared events is visible on the wire.

---

## Notebook

| cell | purpose |
|---|---|
| 1–2 | install and import UltraDES-Python (.NET 8; automatic on Linux/Colab) |
| 3 | **set `PROBLEM`** — normally the only cell you edit |
| 4 | plant and spec DFAs, and the per-problem `sim_seq` |
| 5 | UltraDES DFA → Python dict |
| 6 | synthesis: monolithic, local modular, local modular reduced |
| 6b | validate `sim_seq` against the supervisors; optionally synthesise a valid one |
| 7 | emit `supervisor_data_<PROBLEM>.h` as PROGMEM C arrays; the monolithic supervisor is omitted above 1.2 MB (`HAS_MONO`) |

The header does not record controllability. The distributed engine needs it
(vote vs notify), infers it from the event labels and prints what it inferred at
boot; override with `DES_CONTROLLABLE_MASK`.

---

## Verification

* **Single board:** compiles with `-Wall -Wextra` and zero warnings against all
  three headers; nine runs on an ESP32-S3, all `PASS` (one run each, no variance
  reported). An independently written cost model predicted optimisation 6's
  190 / 145 decryptions before the change; the hardware matched step by step.
* **Distributed:** two ESP32-S3 boards run `fms` for 5 cycles — 220/220 steps,
  0 skipped, oracle `PASS` on both, 100 + 397 decryptions as predicted. The
  engine also runs on Linux (`host_main.cpp`) under injected loss, reboots and
  forged or replayed frames. Details in
  [`des_distributed/README.md`](des_distributed/README.md#verification-status).

---

## References

- Queiroz, M. H., & Cury, J. E. R. (2000). *Modular supervisory control of large
  scale discrete event systems.* Discrete Event Systems, 269–278.
- Rudie, K., & Wonham, W. M. (1992). *Think globally, act locally: decentralized
  supervisory control.* IEEE TAC 37(11).
- ElGamal, T. (1985). *A public key cryptosystem and a signature scheme based on
  discrete logarithms.* IEEE Trans. Information Theory 31(4), 469–472.
- Saltzer, J. H., Reed, D. P., & Clark, D. D. (1984). *End-to-End Arguments in
  System Design.* ACM TOCS 2(4).
- Rosenkrantz, D. J., Stearns, R. E., & Lewis, P. M. (1978). *System level
  concurrency control for distributed database systems.* ACM TODS 3(2) —
  wound-wait.
- UltraDES: https://github.com/lacsed/UltraDES-Python
- mbedTLS ECP: https://mbed-tls.readthedocs.io/en/latest/
