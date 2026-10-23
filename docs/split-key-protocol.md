# Split-key protocol

Status: implemented in [`des_split/`](../des_split/README.md), tested on a
host (mock group, with and without frame loss) and run on two ESP32-S3 boards
on the 2-cluster tool: 7.7 s per step drawing the encryptions of zero during
the step, 1.34 s with the pool of §6, 1.93 s with the key split of §7 and the
hidden logic of §8 on P-192, 2.71 s on P-224 and 3.04 s on P-256 (§7).
Version 5 (the pipeline of §10, re-randomized decision sums, one identity key
per board, §9) takes 2.06 s per step on P-256 on the boards. Version 6 (the
audit of §12) passed every step on the boards, in 2058.1 ms per step on P-256
on average over three runs (2110.4, 2038.1 and 2025.7 ms), and the audit of a
recorded board run found no deviation. On the 3-cluster tool (419 states, with
PSRAM) it passed all 44 steps in 10855.6 ms per step, with the same cost per
operation, and needs 240.9 s between events.
For the paper after the ACC one; no deadline yet.

## 1. Goal

In the single-board sketch the board that stores and processes the encrypted
state also holds the private key, so the separation between the two is
logical, not physical: a memory dump yields the key and with it the state. Here
a **second microcontroller emulates the plant**, and the private key is **split
between the two boards** (§7), so no dump of either board can decrypt anything.
The supervisor board never sees an event or a decision either.

## 2. Roles

| | supervisor board **S** | plant board **P** |
|---|---|---|
| holds | tables of the monolithic supervisor, encrypted state, key share `k_S` | key share `k_P`, the plant (trace driver), the decisions |
| computes | the next state for every event (re-randomized, permuted candidates), the row sums of `R` (re-randomized), its part of their decryption | the re-randomization of the new state, the zero tests |
| never sees | `k_P`, the events, the decisions | `k_S`, the state, the supervisor's tables (in a deployment; the oracle uses them in tests) |

## 3. One step

0. Before the event, S prepares the **candidates**: a fresh permutation π of
   the states, then, for every event e and every transition q → q' of e, the
   cell c[q] ⊞ Enc_Y(0) tagged (e, π(q')) (§8). It is the next state for every
   event at once; in these supervisors no two states lead to the same state on
   the same event, so a candidate is never a sum. S then sends `READY(k)`.
1. P fires an event σ and sends `STEP(k)`. The event itself is never sent.
2. S sends the candidates.
3. P keeps the cells of σ and, for **every** label l, sends
   c'[l] = cell ⊞ Enc_Y(0) (or Enc_Y(0) alone if σ leads nothing into l),
   each frame as soon as its cells are done. The Enc_Y(0) were drawn before
   the event (§6).
4. S puts c'[π(q)] back into state q and adds it to the sums of its rows as it
   arrives. Then, row by row, for each distinct row of `R` among the
   controllable events: the sum (U, V) of all its cells, plus a fresh
   Enc_Y(0), with its part of the decryption D = −k_S·U, one frame per row.
5. P zero-tests each row as it arrives, V + D − k_P·U, while S makes the
   next: these are the decisions, and the next controllable event fires only
   if enabled.

Nothing in a step depends on σ except the content of what P sends back, which
is a fresh ciphertext in every cell: S cannot tell which candidate P kept.
The frame counts are fixed per problem (`des_split/README.md`), S's work does
not depend on σ, and P waits for every candidate, re-randomizes every cell
(an empty cell goes through the same reading and addition on a dummy
point) and tests every row.

Without conditional invariance (it needs σ and the cached bits) every row is
summed and tested at every step; equal rows are still summed once.

## 4. What each party learns

| who | sees | learns |
|---|---|---|
| network adversary | frames of fixed size and count, all ciphertexts or public data | that a step happened, and when |
| snapshot of S's memory | encrypted state (fresh after every step), tables, `k_S`, `Y`, the session's MAC keys | nothing about the state, the events or the decisions |
| copy of one board's flash | its identity private key, the other's public key, the Wi-Fi credentials | it can pass for that board, not for the other |
| S watching every step | the same as a snapshot, at every step | when steps happen |
| snapshot of P's memory | `k_P`, events, decisions, the last state it sent | the events and the decisions, not the state: `k_P` alone decrypts nothing |
| P | events, decisions, the candidates, the decision sums | the number of states, the decisions, the set of states each event leads into (up to a renaming of the states) |

Limits:

* **Integrity.** A compromised S can send wrong sums, or a wrong part of the
  decryption, and make P enable a disabled event: nothing checks it in real
  time. S is accountable instead (§12): every step is signed, and an auditor
  can prove a deviation afterwards.
* **The supervisor's logic.** P learns the number of states, the decisions
  and, for every event, the set of states it leads into up to a renaming of
  the states, which tells most states apart (§8); not the transitions nor the
  enabled sets, beyond what its own run shows.
* **Threat model.** Both boards follow the protocol and try to learn what they
  can (honest-but-curious). A P that deviated could send ciphertexts of its
  choice as c' and decrypt them with S's part of the decryption of the sums;
  that is out of scope.
* **Availability.** Lost frames are resent, but a jammed network, or a board
  that restarts, stops the run: the shares live only in RAM.
* **Timing.** When steps happen is visible: in a real plant, so is how long a
  disabled event waits.
* **Cost.** The re-randomization moved to P: n encryptions of zero per step
  (141 ms each on the ESP32-S3). Measured for the 2-cluster tool (45 states),
  drawing them during the step: 7.7 s per step, 6.4 s of it in the draws. P
  now draws them between events (§6), so they leave the step, and P needs
  n × 141 ms of idle time between two events (6.4 s for 2 clusters, about a
  minute for 3). With the pool and uncompressed cells the step takes 1.34 s
  (2-cluster tool, 28 steps, 1325–1357 ms): zero tests 502 ms, re-randomization
  484 ms, decisions (NEWST, S's sums, DECS) 327 ms, candidates 24 ms. With
  the key split and the hidden logic (P-192, 2-cluster tool, 28 steps) the
  step takes 1.93 s (1868–2111 ms): decisions 856 ms, of them 810 ms on S
  (its sums, 315 ms before, and 7 partial decryptions of about 71 ms each);
  zero tests 540 ms (5 ms more per row: the addition of D); re-randomization
  484 ms; candidates 49 ms (S's own share unchanged at 12 ms). Between events
  S needs 11.3 s to prepare the 74 candidates (152 ms each) and P 6.4 s to
  refill its pool, so S sets the pace: about 13 s per event in all.
  The same run on P-224 and P-256 is in §7. Version 5 adds, per step, one
  Enc_Y(0) per row on S (before the event) and one addition per row (in the
  step), and overlaps S's work with P's (§10); on the host, with every scalar
  multiplication slowed to 20 ms, the step went from 288 to 193 ms. On the
  boards (P-256, 2-cluster tool, 28 steps, all 29 checks passed): 2.06 s per
  step (1935–2301 ms), against 3.04 s for version 4: candidates 54 ms,
  re-randomizing and sending c' 794 ms, waiting for the decisions 340 ms, zero
  tests 869 ms, which now overlap S's work (its sums, their Enc_Y(0) and its
  parts of the decryption take 1455 ms, 147 ms more than in version 4). Between
  events S needs 19.7 s (81 items of 243 ms) and P 10.2 s.

## 5. Reliability and restarts

* **Lost frames.** The receiver of a multi-frame message sends a `NACK` with a
  bitmap of the missing frames; P resends `STEP` if no candidate arrives, and S
  resends `READY` every second while it waits. S resends the candidates it
  prepared (the same bytes) and the rows it made; P keeps the new state.
* **Restarts.** Each board draws an epoch at boot, and every frame carries the
  sender's epoch and the epoch it believes the receiver has. A board that
  restarts mid-run is detected, and the run stops: RESET both boards. S cannot
  continue alone because it cannot re-encrypt a state it cannot read.

## 6. Encryptions of zero drawn before the event

P keeps a pool of n fresh encryptions of zero (sG, sY), in RAM only, drawn
while it is idle between two events. Each re-randomizes one cell and is then
erased, so none is ever used twice: S sees every cell of c' masked by an
Enc_Y(0) it has never seen. If an event comes before the pool is full, P draws
what it lacks on the spot; the step is slower but no less private. The
benchmark replays the trace back to back, so P refills the pool before firing
the next event, which stands for the plant's time between events.

Cells travel uncompressed (96 bytes instead of 50 on P-192): P no longer
computes a square root to read each point, and checks instead that it is on
the curve, which a compressed point guaranteed. CAND takes 6 frames instead of
3 for 2 clusters, 75 instead of 39 for 3.

## 7. The split key

Each board draws its share k_i at boot, keeps it in RAM only, and sends `KEY`:
its share Y_i = k_i·G and a Schnorr proof that it knows k_i (R = tG for a
random t, c = SHA-256(role ‖ Y_i ‖ R) mod N, z = t + c·k_i; the receiver
checks zG − cY_i = R). Both boards encrypt under Y = Y_P + Y_S; nobody ever
holds k = k_P + k_S.

* **Why the proof.** Without it, a board that saw Y_P first could send
  Y_S = aG − Y_P: the joint key would be aG, and that board alone could
  decrypt everything. The role in the challenge keeps a board from sending the
  other's proof back as its own. A failed proof halts the run.
* **Decryption.** V − k_S·U − k_P·U = mG. S sends D = −k_S·U with the decision
  sums only, never with the state, so P can finish the zero test of a decision
  and nothing else. Everything else — encryption, sums, re-randomization, the
  pool, the cell format — is unchanged.
* **Self-test.** P checks its share at boot by encrypting 0 and 1 under it
  alone and zero-testing them with D = 0, before joining the keys.
* **Frames.** `KEY` goes both ways at boot, signed with each board's identity
  key (§9). `DECS` carries one row per frame: 7 frames for 2 clusters, 11 for
  3.
* **Curve.** `DES_CURVE` picks NIST P-192, P-224 or P-256 (about 96, 112 or
  128 bits of security; P-256 by default). The shares travel raw like the cells: mbedTLS cannot
  decompress a P-224 point. The curve is part of the configuration
  fingerprint, so boards built for different curves refuse each other.

Measured on two ESP32-S3, 2-cluster tool, 28 steps, with the pool, the split
key and the hidden logic of version 4 (ms unless noted; every run passed all 29
checks):

| | P-192 | P-224 | P-256 |
|---|---|---|---|
| security, bits | ~96 | 112 | 128 |
| per step (event to decisions) | 1928.7 | 2706.5 | 3035.9 |
| — candidates | 48.5 | 44.9 | 43.4 |
| — re-randomization (P) | 483.6 | 772.6 | 783.6 |
| — decisions (S's sums and partial decryptions, link) | 856.4 | 1174.6 | 1341.2 |
| — zero tests (P) | 540.1 | 714.4 | 867.6 |
| one Enc(0) | 141.3 | 183.7 | 227.2 |
| initial encryption, 45 cells | 6353 | 8293 | 10259 |
| P's refill between events | 6.4 s | 8.3 s | 10.2 s |
| S's candidates between events | 11.3 s | 14.9 s | 18.1 s |

Against P-192, P-256 costs 1.57× per step and 1.61× per scalar multiplication.
P-224 costs 1.30× per scalar multiplication, but its point additions cost
about as much as P-256's (re-randomization 773 against 784 ms), so its step
is only 11 % shorter than P-256's.

## 8. Hiding the supervisor's logic from the plant

With the candidates as copies of the cells P sent, tagged (e, q'), one byte
comparison per candidate gave P every transition q → q', and the tags let it
build the enabled sets of each state over the steps. Three changes, all made
by S before the event, while it is idle:

* **Re-randomized candidates.** Each carries its own fresh Enc_Y(0). Telling
  whether a candidate came from a given cell of P means telling whether their
  difference encrypts zero, which P cannot do without k_S (DDH).
* **Labels permuted every step.** S draws a fresh random permutation π of the
  states, tags the candidates (e, π(q')) and sends those of each event in
  label order (in the order of the states, they would show how the true
  numbers of their labels compare). P puts each cell at its label and sends c'
  in label order; S puts c'[π(q)] back into state q. The number of a state
  never shows, but the labels of each event do, at every step: states that
  differ in the events leading into them can be told apart (41 of the 45
  states of the 2-cluster tool, 251 of the 419 of the 3-cluster tool).
* **Re-randomized decision sums.** P knows every cell it sent, so with few
  states (45) it could find which of them make up a decision sum by a
  meet-in-the-middle search (about 2^23 additions per sum): the enabled sets,
  up to the labels. S adds a fresh Enc_Y(0) to every sum, drawn before the
  event, which closes it.

S sends `READY(k)` once the candidates of step k are made; in the benchmark P
fires the event only when its pool is full and `READY` has come, which stands
for the plant's time between events. A `STEP` that comes earlier has S finish
the candidates on the spot: the step is slower, not less private. P learns the
number of states, the decisions and, for every event, the set of states it
leads into up to a renaming (a candidate for every label of every event would
hide it: 630 per step instead of 74 for 2 clusters).

Checked on the host with a probe on P: no candidate equals a cell P sent, and
in 1 step of 28 the labels of σ's candidates equalled the true state indices
(chance, for an event with a single target); with the re-randomization turned
off the probe found 1998 copies, with the permutation turned off 28 steps of
28.

## 9. One identity key per board

A key shared by both boards for the frame MACs let anyone who read one board's
flash pass for the other board. Each board now has its own identity key pair,
made by `des_split/make_keys.py`, and is given the other board's public key.
`KEY` is signed with the identity key (a Schnorr signature over the header,
which carries both epochs, and the share with its proof); every other frame is
signed with HMAC-SHA256/128 under a session key, one per direction, derived as
HMAC-SHA256(x(k_P·k_S·G), direction ‖ epochs). Only the two boards can compute
k_P·k_S·G, and both epochs change at every boot. Each board compiles in only
its own private key and both public keys, and checks at boot that its public
key fits its private key. On the host, a plant given a wrong public key for
the supervisor refuses its `KEY` and never starts.

## 10. The two boards at the same time

P sends c' frame by frame, as it re-randomizes it, and S adds each cell to the
sums of its rows as it arrives, one cell per pass of its loop so that frames
keep being received. Once every cell is in, S makes the decisions row by row
and sends each at once; P tests each row while S makes the next. The frames
and the work are unchanged, only their order in time.

## 11. What to measure

1. Frames and resends per step against the counts above.
2. The 4-cluster tool on boards with PSRAM, for a few steps.

## 12. Audit: S is accountable

P cannot check S's sums without R, which it must not learn; zero-knowledge
proofs of them are far beyond the boards' budget. S is made accountable
instead:

* **Commitment.** At boot S draws a secret seed and sends, in its signed `KEY`,
  C = SHA-256("des_split commit" ‖ seed ‖ T), where T is a canonical encoding
  of its tables. All of S's randomness is derived from the seed with
  HMAC-SHA256(seed, tag ‖ a ‖ b ‖ ctr): its share k_S, the initial encryption,
  the permutation of every step, the Enc_Y(0) of every candidate and of every
  decision sum. Given the seed, everything S sends is determined.
* **Signed record.** Both boards chain h_k = SHA-256(h_{k−1} ‖ k ‖ H(CAND) ‖
  H(NEWST) ‖ H(DECS)) over every step, from h_init = SHA-256("des_split record"
  ‖ both KEYs ‖ both epochs). After every step S signs h_k with its identity
  key (`SIGN`); before firing the next event, P checks that the signed h_k is
  the one it computed and that the signature is valid, prints it, and stops
  otherwise.
* **Audit.** `des_split/audit.py record` captures the run from the network;
  `audit.py check`, given the seed and the tables, opens C, recomputes k_S, every
  candidate and every decision with D, and compares them with the recording,
  whose frames the signed chain authenticates. A difference is a deviation that
  S signed.

On the host, an honest run passed all 29 steps of the 2-cluster tool, and a
supervisor made to add an encryption of 1 to one decision of step 3 was
reported at that step and row. Revealing the seed reveals S's randomness and
share for that run, not the events or the state: P's randomness and share stay
secret. The audit detects; it does not prevent: an unsafe event can still be
fired before the audit.
