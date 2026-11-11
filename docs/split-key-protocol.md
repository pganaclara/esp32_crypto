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

**Version 7 replaces §3, §6, §8 and §10: the plant sends the event to S (§13).**
Sections 1–12 describe versions 1–6, in which S never saw the event; they are
kept as the record of those runs.

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
2. The 4-cluster tool on boards with PSRAM, for a few steps: done, the first
   10 steps of its trace (`des_split/README.md`, "On the boards"). There S no
   longer keeps up with the cells of c' as they arrive, since each cell belongs
   to 1.47 sums on average, and P waits for the decisions.

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

## 13. Version 7: the event goes to S

Lucas's proposal: as a supervisor of the supervisory control theory, S
receives the event and updates its state for that event only, instead of
preparing a candidate for every transition of every event (versions 1–6).

* **Before the event.** S draws one fresh Enc_Y(0) per decision row (tag
  "dz").
* **Step.** P sends `STEP` with the event σ, encrypted (below). S moves the
  cells: c'[q'] = c[q] for the q that σ leads to q' (the sum of their cells if
  σ leads several states to q'). The cells of the states that σ does not leave
  all encrypt 0, since the current state is one that σ leaves; they go, in the
  order of the states, to the states that σ leads nothing into. When no two
  states go to the same state on one event there are exactly as many, and so
  in every supervisor of the repository (the 2-, 3- and 4-cluster tools, the
  small and the extended small factory); otherwise the states left get fresh
  Enc_Y(0) drawn at the event (tag "z0"). Then every distinct controllable
  row: the sum of its cells and of its Enc_Y(0), and D = −k_S·U, sent one row
  per frame. P zero-tests each row as it arrives. There is no permutation, no
  candidate and no `NEWST`: P never receives a cell of the state. The step's
  only scalar multiplications are the D of S, one per row, and the zero tests
  of P; a sum is kept in Jacobian coordinates, with one field inversion per
  point at the end.
* **Encryptions of zero.** S draws one per decision row and step, 7 for the
  2-cluster tool and 11 for 3 clusters (P none), against |transitions| + rows
  for S and n for P in version 6 (81 + 45 for 2 clusters, 983 + 419 for 3).
* **The event on the network.** σ travels encrypted with a symmetric stream
  cipher, apart from the ElGamal encryption of the state, and S decrypts it as
  it arrives: σ ⊕ the first two bytes of HMAC-SHA256(K_k, "des_split event"), where K_1 = HMAC-SHA256 under
  x(k_P k_S G) of "des_split" ‖ 3 ‖ both epochs, as the MAC keys of §9 (version
  8 makes it from an ephemeral key instead, §14), and
  K_{k+1} = HMAC-SHA256(K_k, "des_split next"). A `STEP` sent again carries the
  same encrypted event. The record of §12 holds the encrypted event: with σ in the
  clear, whoever records the network could find it by trying every event
  against the signed h_k, since h_{k−1}, k and the `DECS` frames are all on the
  network.
* **S's memory.** The seed of §12 is erased once the initial state is
  encrypted (S prints it at boot, for the auditor). The Enc_Y(0) of step k come
  from z_k, with z_0 = HMAC-SHA256(seed, "des_split zeros") and z_{k+1} =
  HMAC-SHA256(z_k, "des_split next") as soon as step k's new state is made; K
  moves on in the same way (a hash ratchet). S keeps the event nowhere after
  the move, only its encrypted form for the record, and erases which states the
  event left and entered. With the seed, a memory read would redo the initial
  encryption and so decrypt every cell, since the cells only move.
* **What each party learns.** S learns the events and, with its tables, can
  follow the state; the split key no longer keeps the state from S. P learns
  the decisions only: no target sets, since it receives no candidates. The
  Enc_Y(0) of every decision sum stays: without it, a row that is the union of
  two others would show as U_3 = U_1 + U_2. The network sees neither the
  events nor the state, only when the frames go. One read of S's memory finds
  ciphertexts that it cannot relate to anything: neither the seed nor a key of
  an earlier step is left. Two reads see where each cell moved in between, and
  so the events in between; whoever knows the state at the first read (at
  boot, for instance, when it is the initial state of the tables) knows it at
  the second. One read and a recording of the network from then on decrypt the
  events that follow, since the next step's K is in RAM. S re-randomized every cell before every event in the version
  measured below, which limited this to two reads around one event, at the
  price of n + (the states σ leads nothing into) Enc_Y(0) more per step.
* **Audit.** h_k = SHA-256(h_{k−1} ‖ k ‖ x_k ‖ H(DECS)), x_k the encrypted event.
  The auditor derives k_S from the seed and K_1 from k_S and P's share in its
  `KEY`, decrypts the events, computes the state, and recovers the event of a
  step whose `STEP` it did not record from the signed h_k. The seed thus gives
  the auditor the events and the state of the run, which it needs to check
  the sums.

On the host with mbedTLS 3.6 (P-256), the 2- and 3-cluster tools passed every
step (18.7 and 34.8 ms per step), the 2-cluster tool also with 20 % of the
frames dropped; the audit passed every step of the recorded 2- and 3-cluster
runs, recovered the event of a step whose `STEP` was removed from the
recording, and reported a supervisor that added an encryption of 1 to row 0
of step 3. A copy of the 2-cluster tool with four transitions added that lead
a second state into a state that the event already enters passed every step,
and so did its audit. None of the 72 `STEP` frames recorded in the 2- and
3-cluster runs carries a value below 64, as a clear event would.

On two ESP32-S3 (P-256, one run per size), measured with the version in which
S re-randomized every cell before every event (tag "rr") and drew a pool of
Enc_Y(0) for the states that the event leads nothing into (commit `d185bfd`): on the 2-cluster
tool, 28 of 28 steps pass, no frame resent, 1083.1 ms per step
(1074.0–1120.3), against 2058.1 ms for version 6. Of that, 214.0 ms of
waiting and 869.1 ms of zero tests on P (124.2 ms per row); S makes the new
state in 0.3 ms and the rows in 933.1 ms (133.3 ms per row), overlapped with
the zero tests. S prepared 91.7 Enc(0) per step on average (45 + 39.7 + 7),
235.7 ms each: about 21.6 s between events (19.7 s for version 6).

On the 3-cluster tool (one run): 44 of 44 steps pass, one row asked for again,
1972.0 ms per step (1933.9–2243.6), against 10855.6 ms for version 6. Of that,
606.4 ms of waiting and 1365.6 ms of zero tests on P (124.1 ms per row); S
makes the new state in 5.5 ms and the rows in 1787.5 ms (162.5 ms per row). S
prepared 804.8 Enc(0) per step (419 + 374.8 + 11), 235.9 ms each: about
189.9 s between events (240.9 s for version 6). Encrypting the initial state
takes 95.5 s. The step now grows with the rows and their sums, not with the
number of states.

With the cells moved and the event encrypted, on the boards (P-256, 2-cluster
tool, one run): 28 of 28 steps pass, no frame resent, 1078.1 ms per step
(1071.9–1091.5). Of that, 210.1 ms of waiting and 868.0 ms of zero tests on P
(124.0 ms per row); S makes the new state, decrypting the event included, in
0.6 ms and the rows in 931.5 ms (133.1 ms per row). S prepares 7 Enc(0) per
step, 227.3 ms each: about 1.6 s between events, against 21.6 s before the
cells moved (235.7 ms per item there: an Enc(0), plus, for the one of a cell,
its addition to the cell). Encrypting the initial state takes 10.2 s.

On the 3-cluster tool (one run): 44 of 44 steps pass, 2 NACKs and 6 rows sent
again, 1961.3 ms per step (1937.1–2071.0; 1951.5 ms without the five steps
above 2 s, which waited 50–120 ms longer for their rows than the median step). Of that, 596.4 ms of
waiting and 1364.9 ms of zero tests on P (124.1 ms per row); S makes the new
state in 5.1 ms and the rows in 1787.0 ms (162.5 ms per row). S prepares 11
Enc(0) per step, 227.8 ms each: about 2.5 s between events, against 189.9 s
before the cells moved and 240.9 s for version 6. From the first event to the
end of the run, 194.0 s on P's clock (4.41 s per event); with the 95.5 s of
encrypting the initial state, a whole run takes about 5 min, against about
2.4 h before the cells moved (44 × (1.97 + 189.9 s) + 95.5 s, from that run's
means).

On the 4-cluster tool (4184 states, 15 rows, one run, PSRAM on S): 60 of 60
steps pass, 6876.1 ms per step (6844.4–7001.2), against 116411.5 ms for
version 6 (its first 10 steps). Of that, 5015.5 ms of waiting and 1860.6 ms
of zero tests on P (124.0 ms per row); S makes the new state in 50.0 ms and
the rows in 6627.6 ms (441.8 ms per row). S prepares 15 Enc(0) per step,
228.0 ms each: about 3.4 s between events, against 3101.0 s for version 6.
The 60 events took 614.5 s on P's clock (10.24 s per event), and encrypting
the initial state 952.8 s: 26.4 min from P's boot, against about 54 h for
version 6. Since a row took S longer than the 300 ms of silence after which
P then sent a `NACK`, P asked in almost every gap (821 `NACK`s) and S sent 896
of the 900 rows twice; every decision still came right. P now waits, before a
`NACK`, twice the gap at which the rows come (the larger of the fastest mean
gap of the earlier steps and the mean gap of this step's rows so far) plus
300 ms: on a host, with S
slowed to 450 ms per row, 168 `NACK`s in 28 steps before and 1 after.

## 14. Version 8: the key of the events from an ephemeral key

In version 7, K_1 came from x(k_P k_S G), as the MAC keys do. k_S stays in S's
RAM all run (S needs it for every D), and Y_P is in P's `KEY`, so whoever read
S's memory could redo K_1, then every K_k, and decrypt the encrypted event that
S keeps for the record and every `STEP` it had recorded; from the events and
the tables it would follow the state. The ratchet did not help: it kept no old
key in RAM, but K_1 could be made again.

Now S derives an ephemeral key e_S from the seed (tag "event", as k_S is
derived with "share") and sends E_S = e_S·G in its signed `KEY`, after the
commitment. Both boards make K_1 = HMAC-SHA256 under x(e_S k_P G) of
"des_split" ‖ 3 ‖ both epochs: S as (N − e_S)·Y_P, P as (N − k_P)·E_S, the same
point. S erases e_S as soon as K_1 is made, at the start of the session,
before it encrypts the initial state. A later read of S finds k_S, Y_P and
E_S, from which K_1 would take the Diffie–Hellman of E_S and Y_P. The MAC keys
are unchanged. The auditor derives e_S from the seed, checks it against E_S,
and makes K_1 from e_S and Y_P. The cost is two scalar multiplications on S
and one on P, at boot.

On the host with mbedTLS 3.6 (P-256): the 2- and 3-cluster tools pass every
step, the 2-cluster tool also with 20 % of the frames dropped, and the mock
group too; the audit passes every step of these recorded runs, recovers the
event of a step whose `STEP` was removed, and reports the supervisor that adds
an encryption of 1 to row 0 of step 3. With k_S, Y_P and the epochs of a
recorded 3-cluster run, the K_1 of version 7 decrypts all 44 events of that
run; on a run of version 8 it decrypts none, and the auditor's K_1, from e_S,
all 44. Both roles build for the ESP32-S3.

On the boards (P-256, 2-cluster tool, one run): 28 of 28 steps pass, no frame
resent, 1099.1 ms per step (1070.0–1228.0); four steps waited 79–134 ms
longer for their rows than the median step, with the same zero tests, and
without them the mean is 1081.9 ms, as in version 7 (1078.1 ms). S makes the
new state in 0.6 ms and the rows in 933.1 ms (133.3 ms per row); P waits
230.5 ms and tests the rows in 868.7 ms (124.1 ms per row). S prepares 7
Enc(0) per step, 227.5 ms each: 1.6 s between events. From the first event to
the end of the run, 73.4 s on P's clock (2.62 s per event); encrypting the
initial state took 10.3 s.

On the 3-cluster tool (one run): 44 of 44 steps pass, 1 `NACK` and 4 rows
sent again, 1975.9 ms per step (1933.0–2148.5); nine steps waited 63–212 ms
longer for their rows than the median step, with the same zero tests, and
without them the mean is 1947.2 ms, as in version 7 (1951.5 ms without its
five slow steps). S makes the new state in 5.1 ms and the rows in 1783.1 ms
(162.1 ms per row); P waits 613.5 ms and tests the rows in 1362.4 ms
(123.9 ms per row). S prepares 11 Enc(0) per step, 227.2 ms each: 2.5 s
between events. From the first event to the end of the run, 194.0 s on P's
clock (4.41 s per event); encrypting the initial state took 95.2 s.
