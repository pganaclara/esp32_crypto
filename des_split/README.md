# des_split — supervisor and plant on two boards

One ESP32 is the **plant**: it replays the trace of the header, sends each
event to the supervisor and decrypts the decisions. The other is the
**supervisor**: it holds the monolithic supervisor's tables and its encrypted
state. The **private key is split** between them: each board draws its own
share at boot and nobody ever holds the whole key, so neither board can decrypt
anything alone. The state is never decrypted, and the plant never receives it.

## A step

The plant sends the event σ to the supervisor (`STEP`), as a supervisor of the
supervisory control theory receives it. The supervisor computes the next
encrypted state for σ only: the new cell of q' is the sum of the cells c[q] of
the states q that σ leads to q' (in these supervisors a copy of one cell), and
the cell of a state that σ leads nothing into is a fresh encryption of zero,
so that no cell is (O, O). It then computes the encrypted decisions — one
homomorphic sum per distinct row of R among the controllable events, plus a
fresh encryption of zero — adds its part of the decryption to each and sends
them one row per frame; the plant finishes each with a zero test.

The supervisor re-randomizes every cell of its state **before** the event
(see below), so at the event the new state is only copies, and the step's only
scalar multiplications are D = −k_S U, one per row, on the supervisor and the
zero tests on the plant. A sum is kept in Jacobian coordinates and costs one
field inversion per point at the end, instead of one per addition.

| message | direction | frames per step |
|---|---|---|
| `READY` | supervisor → plant, before the event: its encryptions of zero are ready | 1 |
| `STEP` | plant → supervisor: the step and the event | 1 |
| `DECS` | supervisor → plant: (events, sum, its part of the decryption), one row per frame | one per distinct controllable row (7, 11, 15 for 2, 3, 4 clusters) |
| `SIGN` | supervisor → plant: the signed record of the step | 1 |

A lost frame is asked for again: a `STEP` that gets no row is sent again, and
a missing row is asked for with a `NACK`. Cells are stored uncompressed (96
bytes on P-192, 128 on P-256), so no square root is computed to read a point;
a point that is not on the curve is refused. The supervisor sends each row as
soon as it is made, and the plant tests it while the supervisor makes the next.

## The keys

**The split key.** At boot each board draws its share k_i and sends `KEY`:
Y_i = k_i·G and a Schnorr proof that it knows k_i. Both encrypt under
Y = Y_P + Y_S. The proof keeps a board from choosing its share from the
other's: sending aG − Y_P would make the joint key aG, which that board alone
could decrypt. A share whose proof fails halts the run, and so does a joint key
that is the point at infinity. A cell (U, V) under Y decrypts to
mG = V − k_S·U − k_P·U. The supervisor sends D = −k_S·U with each decision
sum, never with the state; the plant computes V + D − k_P·U and tests for the
point at infinity. So the plant cannot decrypt the state either.

**One identity key per board.** Each board has its own identity key pair, made
by `make_keys.py`, and knows the other board's public key. `KEY` is signed with
the identity key; every other frame is signed with HMAC-SHA256/128 under a
session key, one per direction, derived from the two shares (k_P·k_S·G, which
only the two boards can compute) and both boards' epochs. Each board compiles
in only its own private key, so a copy of one board's flash does not let anyone
pass for the other board.

## What each board learns

**The supervisor** learns the events, and so, from its tables, it can follow
the state: the state is never decrypted, but the supervisor does not need to
decrypt it. **The plant** learns the decisions and nothing else of the
supervisor: it never receives a cell of the state, and every decision sum
carries its own fresh encryption of zero, so the rows of R do not show either
(without it, a row that is the union of two others would have the sum of their
U). The encryption protects the state against whoever reads the memory of
either board without knowing the events of the run: the supervisor board holds
only ciphertexts of the state, the plant board none. Whoever reads the
supervisor's memory both after a preparation and after the next event sees
which cells were copied where, and so that event. Frames are authenticated,
not encrypted, so whoever records the network sees the events.

**Threat model.** Both boards follow the protocol and try to learn what they
can from what they see (honest-but-curious).

**Integrity is not checked in real time.** A supervisor board that deviates
from the protocol can send wrong sums, and so make the plant enable a disabled
event. It is accountable instead: see the audit below.

## Audit: the supervisor is accountable

The plant cannot check the supervisor's sums without its tables. The
supervisor can still be held to them afterwards:

* at boot it draws a secret **seed**, from which it derives all its randomness
  (its key share, the initial encryption, the encryptions of zero of the state
  and of the sums), and sends in its signed `KEY` the **commitment**
  SHA-256("des_split commit" ‖ seed ‖ tables);
* both boards chain a SHA-256 over every step's event and decisions, and after
  every step the supervisor **signs** the chain head (`SIGN`). Between events,
  the plant checks that the signed head is the one it computed from what it
  sent and received, and that the signature is valid, before firing the next
  event; it prints the signed record (`[audit]` lines) and stops if a record is
  missing or wrong.

An auditor, who may see the tables, records the run from the network and, with
the seed the supervisor opens to it, redoes every step:

    python audit.py record run.bin --iface <this computer's IP on the boards' Wi-Fi>
    python audit.py check run.bin --header supervisor_data_cluster_tool_2.h --seed <hex> --supervisor-pub <DES_PUB_SUPERVISOR>

The computer must be on the boards' Wi-Fi network itself (the same SSID: a
router's 2.4 GHz and 5 GHz networks may not pass multicast to each other), and
`record` must start before the boards are reset, since the run begins with the
`KEY` frames. The seed changes at every boot: use the one of the recorded run.

The state never travels: `check` computes it from the seed and the events (in
the plant's `STEP` frames), so a frame that the recording lacks costs the check
of that frame only. A step whose `STEP` was not recorded is still checked: the
event is the one whose record matches the signature. `check` opens the
commitment, recomputes the supervisor's share, the state and every decision
with its part of the decryption, and compares them with the recording and with
the chain the supervisor signed: a difference is a deviation, which the
signature makes undeniable. The supervisor prints its seed in its summary (a
prototype: a deployment would keep it for the auditor only). Revealing the seed
reveals the supervisor's randomness and its key share of that run: the plant's
share stays secret.

The cost is one signature per step on the supervisor and one verification on
the plant, both between events.

## Encryptions of zero drawn before the event

Drawing an encryption of zero (sG, sY) costs two scalar multiplications. The
supervisor draws those of a step **before** the event, while it is idle, kept
in RAM only (regenerated at every boot, never written to flash):

* one per state, added at once to its cell, so that the cells copied at the
  event are not cells the board held before this preparation;
* a pool of them for the states that the event leads nothing into, topped up
  to the most an event can need (n minus the fewest states an event leads
  into; an event that leads nowhere has the rest drawn on the spot); the
  zeros are taken in the order they were drawn, so the auditor can redo it;
* one per decision row.

Each is used once and then erased, so no encryption of zero is ever used
twice; a step that comes before they are ready has the supervisor finish them
on the spot. The benchmark replays the trace
back to back, so the plant fires the next event once the supervisor's `READY`
has come: that stands for the time a real plant spends between two events. The
step time is then the latency from the event to the decisions, and the
preparation time is reported apart.

## Run

1. Make `secrets.h` in this folder from `secrets.example.h`: the Wi-Fi (as in
   `des_distributed/secrets.h`) and the identity keys,
   `python make_keys.py 256 >> secrets.h` (again whenever `DES_CURVE`
   changes). Both boards are built from the same `secrets.h`.
2. In `des_split.ino`, pick the header and the curve (`DES_CURVE`: 192, 224 or
   256 for NIST P-192, P-224, P-256, about 96, 112 or 128 bits of security;
   256 by default), and flash one board with `#define DES_ROLE DES_PLANT` and
   the other with `DES_SUPERVISOR`. Both boards need the same header and curve.
   The headers, generated by the notebook:

   | header | states | events | note |
   |---|---|---|---|
   | `supervisor_data_cluster_tool_2.h` | 45 | 14 | |
   | `supervisor_data_cluster_tool_3.h` | 419 | 22 | the supervisor keeps three vectors of 419 cells (54 KB each on P-256) |
   | `supervisor_data_cluster_tool_4.h` | 4184 | 30 | needs PSRAM on the supervisor board (Tools → PSRAM → OPI PSRAM): three vectors of 4184 cells, ~1.6 MB on P-256 |

3. Open both Serial Monitors, then RESET both boards.

The plant prints, at every step, the decisions next to those of the
supervisor in clear (an oracle a deployment would omit) and the time from the
event to the decisions, split into the wait for them (the supervisor's new
state and sums, and the link) and the zero tests, which overlap with the
supervisor's work. The summaries give the means, and how long the supervisor
needs between two events. At boot, before waiting for the other board, the
plant also prints `[clear]`: the time of a step of the same supervisor
unencrypted on that board (its move and its decisions, from the tables in
flash), over the whole trace 100 times. It is the baseline of the encrypted
step.

## On the boards

Two ESP32-S3, P-256, one run per size; every decision of every step matched
the supervisor in clear:

| | 2-cluster tool | 3-cluster tool |
|---|---|---|
| states, decision rows, steps | 45, 7, 28 | 419, 11, 44 |
| step, mean (from the event to the decisions) | 1083.1 ms (1074.0–1120.3) | 1972.0 ms (1933.9–2243.6) |
| plant: waiting for the rows | 214.0 ms | 606.4 ms |
| plant: zero tests | 869.1 ms (124.2 ms per row) | 1365.6 ms (124.1 ms per row) |
| supervisor: the new state | 0.3 ms | 5.5 ms |
| supervisor: the rows | 933.1 ms (133.3 ms per row) | 1787.5 ms (162.5 ms per row) |
| supervisor: Enc(0) per step, drawn before the event | 91.7 (45 + 39.7 + 7) | 804.8 (419 + 374.8 + 11) |
| supervisor, between events | 21.6 s (235.7 ms per Enc(0)) | 189.9 s (235.9 ms per Enc(0)) |
| encrypting the initial state | 10.3 s | 95.5 s |
| rows asked for again | 0 | 1 |

A row costs the supervisor more than a zero test costs the plant (most of it
is D = −k_S U, the rest the sum, larger for 3 clusters), so the step is the
supervisor's new state and rows, plus the last zero test and the link: the
plant tests each row while the supervisor makes the next. In the 3-cluster
run, steps 13–15 (2191–2244 ms) waited about 270 ms more for their rows, with
the same zero tests; without them the mean is 1953.7 ms. The step grows with
the rows and the size of their sums, no longer with the number of states; the
time between events grows with the number of states.

The board results of protocol 6, in which the supervisor never saw the event
(it sent a candidate for every transition of every event and the plant kept
those of the event that occurred), are in this file at commit `d281ad1`: on
P-256, 2058.1 ms per step (mean of 3 runs) and 19.7 s between events on the
supervisor for the 2-cluster tool, 10855.6 ms and 240.9 s for 3 clusters.

## Test on a host

`host_main.cpp` builds either role with g++ (see its header). With mbedTLS
(`libmbedtls-dev`, the 3.6 of the Arduino-ESP32 core 3.x), the 2- and 3-cluster
tools pass every step on P-256 (29.8 and 69.5 ms per step on a PC), the
2-cluster tool also with 20 % of the frames dropped
(`-DDES_SIMULATE_LOSS_PCT=20`); `audit.py check` passes every step of the
recorded 2- and 3-cluster runs, also when the recording lacks a `STEP`, and
reports `DEVIATION step 3: decision row 0` for a supervisor made to add an
encryption of 1 to that row. Without mbedTLS it uses a mock group with the same algebra
and no security, enough to test the protocol. The identity keys can be given
on the command line (`-DDES_ID_PLANT=...` and the three others), which then
wins over `secrets.h`.
