# des_split — supervisor and plant on two boards

One ESP32 is the **plant**: it replays the trace of the header and decrypts
the decisions. The other is the **supervisor**: it holds the monolithic
supervisor's tables and its encrypted state. The **private key is split**
between them: each board draws its own share at boot and nobody ever holds the
whole key, so neither board can decrypt anything alone. The supervisor board
never sees an event or a decision, and it keeps nothing between steps but the
encrypted state.

## How a step hides the event

The supervisor computes the next encrypted state for **every** event (for each
transition q → q' of every event, it sends the cell c[q], re-randomized and
tagged with a label of q'); the plant keeps the cells of the event that
occurred, adds a fresh encryption of zero to **every** cell, and sends the new
state back. The supervisor cannot link it to any of the candidates, so it does
not learn which event it was. It then computes the encrypted decisions — one
homomorphic sum per distinct row of R among the controllable events — and adds
its part of the decryption to each; the plant finishes it with a zero test.

| message | direction | frames per step, 2 / 3 clusters: P-192 | P-224 | P-256 |
|---|---|---|---|---|
| `READY` | supervisor → plant, before the event: the candidates are ready | 1 | 1 | 1 |
| `STEP` | plant → supervisor | 1 | 1 | 1 |
| `CAND` | supervisor → plant: (event, label, cell) per transition | 6 / 75 | 7 / 89 | 8 / 98 |
| `NEWST` | plant → supervisor: the re-randomized state | 4 / 30 | 4 / 35 | 5 / 42 |
| `DECS` | supervisor → plant: (events, sum, its part of the decryption), one row per frame | 7 / 11 | 7 / 11 | 7 / 11 |

The number of frames, the supervisor's work and the plant's work are the same
for every event: the plant waits for all the candidates, re-randomizes all the
cells (an empty one goes through the same operations on a dummy point) and
tests all the rows. A lost frame is asked for again (`NACK`). Cells travel
uncompressed (96 bytes on P-192, 128 on P-256), so the plant does not compute a
square root to read each point; a point that is not on the curve is refused.

## The two boards work at the same time

The plant sends the new state frame by frame, as it re-randomizes it, and the
supervisor adds each cell to the sums of its rows as it arrives. The supervisor
then sends the decisions one row per frame, and the plant tests each row while
the supervisor makes the next. Neither changes what is sent or computed, only
when: the frame counts and the work stay the same for every event.

## The keys

**The split key.** At boot each board draws its share k_i and sends `KEY`:
Y_i = k_i·G and a Schnorr proof that it knows k_i. Both encrypt under
Y = Y_P + Y_S. The proof keeps a board from choosing its share from the
other's: sending aG − Y_P would make the joint key aG, which that board alone
could decrypt. A share whose proof fails halts the run. A cell (U, V) under Y
decrypts to mG = V − k_S·U − k_P·U. The supervisor sends D = −k_S·U with each
decision sum, never with the state; the plant computes V + D − k_P·U and tests
for the point at infinity. So the plant cannot decrypt the state either.

**One identity key per board.** Each board has its own identity key pair, made
by `make_keys.py`, and knows the other board's public key. `KEY` is signed with
the identity key; every other frame is signed with HMAC-SHA256/128 under a
session key, one per direction, derived from the two shares (k_P·k_S·G, which
only the two boards can compute) and both boards' epochs. Each board compiles
in only its own private key, so a copy of one board's flash does not let anyone
pass for the other board — which a key shared by both boards did.

## What the plant learns about the supervisor

Before the event, while it is idle, the supervisor prepares the next step and
sends `READY`:

* it draws a fresh random **permutation** π of the states, tags every
  candidate (e, π(q')) instead of (e, q') and sends the candidates of each
  event in label order. The plant puts each cell at its label and sends the
  new state in label order; the supervisor puts cell π(q) back into state q.
  The number of a state never shows.
* it adds its own fresh **encryption of zero** to every candidate, so a
  candidate is no longer a copy of a cell the plant sent: telling which cell it
  came from would take the supervisor's key share.
* it draws one more encryption of zero per decision row, added to that row's
  sum, so the plant cannot find which of its cells make up a sum either (with
  45 states, a meet-in-the-middle search would otherwise give the enabled
  sets).

So the plant learns the number of states, the decisions and which labels each
event leads to: for every event, the set of states it leads into, up to a
renaming of the states. The renaming changes every step, but states that
differ in the events leading into them can still be told apart: 41 of the 45
states of the 2-cluster tool, 251 of the 419 of the 3-cluster tool. After an
event that leads into a single state (2 of the 14 events of the 2-cluster
tool), the plant therefore knows the state it reached. Hiding this would take
a candidate for every label of every event (14 × 45 = 630 per step instead of
74); we do not pad. The three measures cost one encryption of zero and one
addition per candidate and per row on the supervisor (81 per step for 2 clusters, 983 for
3), all before the event. In the benchmark the plant fires the next event once
its pool is full and the supervisor's `READY` has come, so the step time still
runs from the event to the decisions. A step that comes before the candidates
are ready has the supervisor finish them on the spot.

**Threat model.** Both boards follow the protocol and try to learn what they
can from what they see (honest-but-curious). A plant board that deviated could
send ciphertexts of its choice as the new state and decrypt them with the
supervisor's part of the decryption of the sums; that is out of scope.

**Integrity is not checked in real time.** A supervisor board that deviates
from the protocol can send wrong sums, and so make the plant enable a disabled
event. It is accountable instead: see the audit below.

## Audit: the supervisor is accountable

The plant cannot check the supervisor's sums without its tables, which it must
not learn. The supervisor can still be held to them afterwards:

* at boot it draws a secret **seed**, from which it derives all its randomness
  (its key share, the initial encryption, the permutations, the encryptions of
  zero of the candidates and of the sums), and sends in its signed `KEY` the
  **commitment** SHA-256("des_split commit" ‖ seed ‖ tables);
* both boards chain a SHA-256 over every step's messages (the candidates, the
  new state, the decisions), and after every step the supervisor **signs** the
  chain head (`SIGN`). Between events, the plant checks that the signed head is
  the one it computed from what it received, and that the signature is valid,
  before firing the next event; it prints the signed record (`[audit]` lines)
  and stops if a record is missing or wrong.

An auditor, who may see the tables, records the run from the network and, with
the seed the supervisor opens to it, redoes every step:

    python audit.py record run.bin --iface <this computer's IP on the boards' Wi-Fi>
    python audit.py check run.bin --header supervisor_data_cluster_tool_2.h --seed <hex> --supervisor-pub <DES_PUB_SUPERVISOR>

The computer must be on the boards' Wi-Fi network itself (the same SSID: a
router's 2.4 GHz and 5 GHz networks may not pass multicast to each other), and
`record` must start before the boards are reset, since the run begins with the
`KEY` frames. The seed changes at every boot: use the one of the recorded run.

The recorder only listens: a frame lost on the air on its way to the computer
is not sent again (multicast is not acknowledged; the boards ask each other for
the frames they lack, the recorder cannot). `check` reports what the recording
lacks apart from deviations, checks the rest, and goes on from the record the
supervisor signed, up to the last step, which the plant's `FIN` names (a step
whose frames were all lost is reported too, and a recording without `FIN` may
have ended before the run). In one board run the recording (702 frames of the run)
lacked 2 (a decision row of step 12, a frame of candidates of step 22): 27 steps were
checked entirely, 2 except those frames, and no deviation was found.

`check` opens the commitment, recomputes the supervisor's share, every
candidate and every decision with its part of the decryption, and compares
them with the recording and with the chain the supervisor signed: a difference
is a deviation, which the signature makes undeniable. On the host, a
supervisor made to add an encryption of 1 to one decision of step 3 was
reported as `DEVIATION step 3: decision row 0`; an honest run passed all 29
steps. The supervisor prints its seed in its summary (a prototype: a deployment
would keep it for the auditor only). Revealing the seed reveals the
supervisor's randomness and its key share of that run, not the events: the
plant's randomness and share stay secret.

The cost is one signature per step on the supervisor and one verification on
the plant, both between events.

## Encryptions of zero drawn before the event

Drawing an encryption of zero (sG, sY) costs two scalar multiplications, and a
step needs one per state. The plant draws them **before** the event, while it
is idle, into a pool of n entries kept in RAM only (regenerated at every boot,
never written to flash). Each entry is used for one cell and then erased, so
no encryption of zero is ever used twice; a step that finds the pool empty
draws what it lacks on the spot. The benchmark replays the trace back to back,
so the plant refills the pool before firing the next event: that stands for
the time a real plant spends between two events. The step time is then the
latency from the event to the decisions, and the refill time is reported
apart.

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
   | `supervisor_data_cluster_tool_3.h` | 419 | 22 | the supervisor board needs ~190 KB of heap on P-256 |
   | `supervisor_data_cluster_tool_4.h` | 4184 | 30 | needs PSRAM on both boards (Tools → PSRAM → OPI PSRAM): ~1.6 MB on the plant, ~2.2 MB on the supervisor on P-256 |

3. Open both Serial Monitors, then RESET both boards.

The plant prints, at every step, the decisions next to those of the
supervisor in clear (an oracle a deployment would omit) and the time from the
event to the decisions, split into candidates, re-randomizing and sending the
new state (of it, encryptions of zero drawn on the spot: 0 with the pool),
waiting for the decisions, and the zero tests, which overlap with the
supervisor's work. The summary gives the means, and how long each board needs
between two events.

## Test on a host

`host_main.cpp` builds either role with g++ (see its header). Without mbedTLS
it uses a mock group with the same algebra and no security, enough to test the
protocol: the 2-, 3- and 4-cluster tools pass every step, the 3-cluster tool
also with 20 % of the frames dropped (`-DDES_SIMULATE_LOSS_PCT=20`). With the fake mbedTLS of the
tests (real SHA-256, a mock group), `audit.py check --mock` audits a host run.
The identity keys can be given
on the command line (`-DDES_ID_PLANT=...` and the three others), which then
wins over `secrets.h`.
