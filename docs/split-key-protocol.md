# Split-key protocol

Status: implemented in [`des_split/`](../des_split/README.md), tested on a
host (mock group, with and without frame loss); not yet run on the boards.
For the paper after the ACC one; no deadline yet.

## 1. Goal

In the single-board sketch the board that stores and processes the encrypted
state also holds the private key, so the separation between the two is
logical, not physical: a memory dump yields the key and with it the state. Here
a **second microcontroller emulates the plant and holds the private key**. The
supervisor board keeps the encrypted state and only the public key, so no dump
of it can decrypt anything — and it never sees an event or a decision either.

## 2. Roles

| | supervisor board **S** | plant board **P** |
|---|---|---|
| holds | tables of the monolithic supervisor, encrypted state, public key `Y` | private key `k`, the plant (trace driver), the decisions |
| computes | the next state for every event (copies of cells), the row sums of `R` | the re-randomization of the new state, the zero tests |
| never sees | the key, the events, the decisions | the supervisor's tables (in a deployment; the oracle uses them in tests) |

## 3. One step

1. P fires an event σ and sends `STEP(k)`. The event itself is never sent.
2. S sends the **candidates**: for every event e and every transition
   q → q' of e, the cell c[q] tagged (e, q'). It is the next state for every
   event at once; in these supervisors no two states lead to the same state on
   the same event, so a candidate cell is a copy, never a sum.
3. P keeps the cells of σ and, for **every** state q, sends
   c'[q] = cell ⊞ Enc_Y(0) (or Enc_Y(0) alone if σ leads nothing into q).
4. S replaces its state by c' and sends one homomorphic sum per distinct row
   of `R` among the controllable events (all cells of the row included).
5. P zero-tests every sum: these are the decisions, and the next controllable
   event fires only if enabled.

Nothing in a step depends on σ except the content of what P sends back, which
is a fresh ciphertext in every cell: S cannot tell which candidate P kept.
The frame counts are fixed per problem (`des_split/README.md`), S's work does
not depend on σ, and P waits for every candidate, re-randomizes every cell
(an empty cell goes through the same decompression and addition on a dummy
point) and tests every row.

Without conditional invariance (it needs σ and the cached bits) every row is
summed and tested at every step; equal rows are still summed once.

## 4. What each party learns

| who | sees | learns |
|---|---|---|
| network adversary | frames of fixed size and count, all ciphertexts or public data | that a step happened, and when |
| snapshot of S's memory | encrypted state (fresh after every step), tables, `Y` | nothing about the state, the events or the decisions |
| S watching every step | the same as a snapshot, at every step | when steps happen |
| P (trusted) | events, decisions, the state if it decrypts it | what the plant knows anyway |

Limits:

* **Integrity.** A compromised S can send wrong sums and make P enable a
  disabled event. The guarantee is confidentiality against an S that follows
  the protocol, not integrity.
* **Timing.** When steps happen is visible: in a real plant, so is how long a
  disabled event waits.
* **Cost.** The re-randomization moved to P: n encryptions of zero per step
  (140 ms each on the ESP32-S3). Estimated per step: about 8 s for the
  2-cluster tool (45 states), about 2 s without drawing the encryptions of
  zero; over a minute for 3 clusters (419 states). To be measured.

## 5. Reliability and restarts

* **Lost frames.** The receiver of a multi-frame message sends a `NACK` with a
  bitmap of the missing frames; P resends `STEP` if no candidate arrives. S
  regenerates candidates on demand (its state does not change until the new
  one arrives) and caches its sums; P caches the new state.
* **Restarts.** Each board draws an epoch at boot, and every frame carries the
  sender's epoch and the epoch it believes the receiver has. A board that
  restarts mid-run is detected, and the run stops: RESET both boards. S cannot
  continue alone because it cannot re-encrypt a state it cannot read.

## 6. What to measure

1. Per-step latency and its split, with and without the time spent drawing the
   encryptions of zero, on the 2- and 3-cluster tools.
2. Frames and resends per step against the counts above.
3. A pool of encryptions of zero drawn by P while it waits (for the
   candidates, for the sums), to take most of the 140 ms per cell out of the
   step.
