# Distributed Homomorphic DES — generic, transport-agnostic engine

Runs **any** supervisor set the UltraDES notebook generates, partitioned over
**any** number of nodes, over **any** transport, with each node's plant state
held only as EC-ElGamal ciphertexts under **its own** keypair.

Nothing here is specific to a plant, a board, or a protocol. The event routing,
the owner election, the shared/local partition and the participant sets are all
**derived at boot** from the generated header.

```
des_generic.h      the engine    — no Arduino, no FreeRTOS, no ESP-IDF
des_transport.h    the transport — UDP/IP multicast
des_distributed.ino  ESP32 entry point   (config + setup/loop)
host_main.cpp        POSIX entry point   (Linux / *BSD / macOS)
secrets.example.h    template for secrets.h — Wi-Fi + cell key (secrets.h is not versioned)
```

Verified against every header in this repo:

| problem | events | supervisors | largest |
|---|---|---|---|
| `small_factory` | 4 | 1 | 6 states |
| `extended_small_factory` | 6 | 2 | 6 states |
| `fms` | 31 | 7 | 164 states |

---

## 1. Why not ESP-NOW, and why not MQTT either

ESP-NOW is Espressif's own MAC-layer protocol. It is fast and needs no
infrastructure, but it is **vendor-specific**: it exists only on Espressif
silicon, is not specified by any standards body, and a paper that builds its
coordination layer on it cannot claim a path to industrial deployment. It has
been removed.

MQTT is genuinely open (OASIS, **ISO/IEC 20922**) with open-source brokers and
clients. It was not chosen, for three reasons: a broker is a third failure
domain between two controllers a metre apart; a well-tuned industrial
ESP32/MQTT path still measures 3 ms min / 12 ms avg / **72 ms max** round-trip,
and the jitter is what hurts an interlock; and the broker sees every frame,
which sits awkwardly with a design whose whole point is that the plant state
stays encrypted. (An MQTT binding was written and later removed: it was never
measured against a live broker, and untested code is no evidence.)

### The default: UDP/IP multicast

Open (**RFC 1112**, **RFC 3376**), implemented by every IP stack ever shipped,
no broker, no library, no vendor. Runs unmodified on ESP32 (lwIP), Linux, *BSD,
macOS, QNX, VxWorks — anything with BSD sockets. Joining the group *is* the
discovery step.

The decisive argument for a paper: **this is the same substrate the industrial
standards use.** OPC UA PubSub (IEC 62541-14) and DDS/RTPS both define UDP
mappings over exactly this. So the protocol here is not a toy that would need
redesigning for industry — it is the same shape, and moving to OPC UA PubSub or
DDS is a transport swap, not an architecture change.

### The transport is pluggable *because reliability is end-to-end*

```c
struct DesTransport {
    bool (*begin)();
    bool (*send)(const void* frame, int len);   // best effort, to all peers
    bool (*poll)(void* frame, int len);         // non-blocking
    void (*service)();                          // keepalive / reconnect
};
```

That is the entire contract. A transport only has to be **best effort**, because
sequencing, acknowledgement, retransmission and atomicity are supplied by the
protocol itself — the classic **end-to-end argument** (Saltzer, Reed & Clark
1984). It is also why a transport's own per-hop reliability, such as MQTT's QoS
1/2, would add nothing: it would redo, per frame, work the 2PC already
guarantees end to end.

| | UDP multicast | MQTT | OPC UA PubSub | DDS | (ESP-NOW) |
|---|---|---|---|---|---|
| standard | RFC 1112 | ISO/IEC 20922 | IEC 62541-14 | OMG | **vendor** |
| open-source stack | none needed | Mosquitto/EMQX | open62541 (MPL-2.0) | Cyclone (EPL-2.0), Fast DDS (Apache-2.0) | Espressif only |
| broker | no | **yes** | no | no | no |
| runs off-ESP32 | **yes** | yes | yes | yes | **no** |
| status here | **implemented** | not chosen | ~100 lines to add | ~80 lines to add | removed |

Adding OPC UA PubSub or DDS means implementing those four functions. Neither is
bundled only because each pulls in a build system this sketch does not assume.

---

## 2. Protocol

Conjunctive fusion over the nodes that constrain an event. The
controllable/uncontrollable distinction drives two different mechanisms — and
getting this backwards is the usual way a "distributed supervisor" turns out
unsound:

| event class | mechanism | frames |
|---|---|---|
| local (one node relevant) | apply locally | **0** |
| shared + **controllable** | `REQ → VOTE* → COMMIT → ACK*` — any participant may veto | 2 + 2p |
| shared + **uncontrollable** | `NOTIFY → ACK*`, retransmitted until acknowledged | 1 + p |

*(p = number of participants)*

An uncontrollable event **cannot be vetoed**: SCT controllability says a
supervisor may not disable one, and by the time a node hears about it the plant
has already done it. Asking permission would be meaningless, so it gets a
reliable notification instead. Safety is enforced upstream — the supervisor
already disabled the controllable event that would have led somewhere unsafe.

Only the **participants** of an event — the nodes holding a supervisor that
constrains it or moves on it — vote, apply and acknowledge. Multicast delivers
every frame to every node, so the others ignore it; an acknowledgement from a
non-participant would otherwise make "everyone answered" unreachable on three
or more nodes.

**Concurrency.** Participants hold a lock between `VOTE`-yes and
`COMMIT`/`ABORT`, so two initiators can never interleave transactions on the
same supervisor, and a locked node fires none of its own events until the
transaction settles — its YES was a promise about its current state. The
initiator is part of the same discipline: while it is collecting votes it
answers other requests by **wound-wait** (Rosenkrantz, Stearns & Lewis 1978) —
a lower-numbered (older) requester wounds it, and it aborts its own attempt; a
younger one is told no. The wait-for graph therefore cannot contain a cycle.
Preemption is always safe because nothing has been applied while a lock is
held. Once every vote is in, the decision is final: the initiator sends
`COMMIT` first and applies locally second, so participants are released at once
and their homomorphic step runs in parallel with its own.

**Loss.** Every `COMMIT`/`NOTIFY` is retransmitted until every participant has
acknowledged it; the per-sender sequence number only rejects duplicates. When
the budget is exhausted a node **SAFE-HALTS** rather than continue on state that
may have diverged from its peers, and keeps telling any peer still talking. This
is the Two Generals trade, made explicit: safety preserved, liveness sacrificed.
A single-board implementation cannot have this failure mode — it is a real cost
of distributing, and the engine surfaces it loudly rather than hiding it.

**Identity.** Every frame carries a random per-boot **epoch** and a
**fingerprint** of the configuration (protocol version, node count, lockstep,
event table, derived partition, trace). A peer whose epoch changes after
shared events has rebooted — its supervisors are back in their initial state —
and both sides halt; before any shared event it simply rejoins. A second board
flashed with the same `DES_NODE_ID`, or a board built from a different header,
family or partition, is reported by name and ignored instead of silently
talking past the others.

**Authentication.** Without it, anyone on the plant network could stop the
cell with a single datagram, or drive a shared event. Every 44-byte frame is
therefore signed, in three layers — the same three OPC UA PubSub uses in its
*Sign* mode (IEC 62541-14):

1. **Integrity and authenticity.** An HMAC-SHA256 tag over every other byte,
   under the cell's shared key `DES_AUTH_KEY`, truncated to 128 bits (RFC 2104
   §5: not below half the hash length). A frame whose tag does not verify is
   dropped before any of its fields is read; the comparison is constant-time.
2. **Freshness within a boot.** A per-sender counter that only increases; a
   frame whose counter has already been passed is dropped.
3. **Freshness across boots.** A counter cannot order two different boots, and a
   recording of yesterday's run carries yesterday's epoch — which, if believed,
   looks exactly like "the peer rebooted" and halts the cell. So a new epoch is
   never believed on sight: the receiver sends a random 64-bit nonce (`M_CHAL`)
   and accepts the epoch only when a correctly tagged `M_RESP` carrying that
   nonce comes back. A recording cannot answer a question that did not exist
   when it was made. The same challenge tells a second live board with our id
   apart from a recording of our own earlier boot.

What it does **not** provide: confidentiality — frames are signed, not
encrypted, so an observer still sees which shared events happen and how nodes
vote (OPC UA's *SignAndEncrypt* mode adds that) — and key distribution: the key
is pre-shared by hand, where OPC UA would use a Security Key Service to issue
and rotate it.

### Validation

The protocol was replayed against the real generated arrays on the host, for
every problem × family × node-count:

```
extended_small_factory  FULL/RED, 2 nodes: 18 fired (12 local, 3 2pc, 3 notify)
                                            4/6 events traffic-free
fms                     FULL,     3 nodes: 16/31 events traffic-free
                        RED,      7 nodes: 16/31 events traffic-free

packet loss (COMMIT/NOTIFY retried 5x), 60 runs each:
  15% loss:  0/60 SAFE-HALT, 0 silent divergence
  40% loss:  4/60 SAFE-HALT, 0 silent divergence
  70% loss: 34/60 SAFE-HALT, 0 silent divergence
```

On hardware each node additionally checks every homomorphic bit against a
cleartext oracle of its own supervisors, and — where the header carries a
monolithic supervisor — replays the global trace against it to confirm nothing
fires that the centralised supervisor forbids.

---

## 3. Two findings from validating against FMS

### 3a. Transitions must be a UNION, not an assignment

Both the single-board sketch and the first version of this engine applied an
event with

```c
nxt[to] = enc[from];          // WRONG when two sources share a target
```

The image of a state set under an event is a **union**. Several source states
may converge on the same target — `supervisor_data_fms.h` has **11 such
collisions** in its reduced supervisors — and plain assignment lets whichever
pair the generator emitted last win, so an **inactive source silently
overwrites an active one**.

The result therefore depends on the order the pairs happen to appear in the
header. Regenerating `supervisor_data_fms.h` reordered exactly those arrays
without changing the automaton, and the enablement trace changed — which is how
this surfaced. Shuffling the pair order confirms it: with assignment the trace
moves, with union it is stable.

Fixed here by skipping zero sources (a cell holding `Enc(0)` contributes nothing
to a union, so it can never clobber an active cell) and, if two active sources
ever converge, combining them with the additive homomorphism. The common path
costs exactly what it did before. The cleartext oracle got the same correction —
otherwise it would agree with a buggy homomorphic path and validate nothing.

**Also fixed in `../homomorphic-esp32-ultrades.ino`**, in both `do_transition`
and `Oracle::step`. Until then the oracle made the identical mistake, so the two
agreed and the benchmark printed `PASS` while certifying nothing. It only bites
problems with converging transitions — of the three headers here only `fms` does,
so `small_factory` and `extended_small_factory` results were unaffected.
Measured on the current FMS header over its 44-step sequence, the buggy version
reports a different enablement at **21 of 44 steps** for the REDUCED family
(0 of 44 for FULL LMOD), and is not stable under reordering.

### 3b. The generated `SIM_SEQ` for FMS was not admissible — now fixed

Step 10 fired event `39`, which `S3` disables, because the hand-written trace
never ran the Mill and `E4` only permits `39` after `54`. 28 of 85 replayed steps
were unreachable.

This is **not** a distribution problem — it reproduces at one node, with no
protocol involved. It is also not caught by the existing single-board sketch:
`homomorphic-esp32-ultrades.ino` fires each `SIM_SEQ` event unconditionally and
only compares the homomorphic result against its cleartext oracle. Both take the
same invalid transition, so they agree, and it prints `PASS`. Any published FMS
numbers from that benchmark are measured on a trace that leaves the supervisor's
admissible language.

The distributed engine gates every step on admissibility, **skipping and loudly
reporting** steps the supervisors disable rather than firing them.

(An alternative driver once had each node fire whichever of its own events its
supervisors enabled, with no script. It was removed: a supervisor only forbids
what the specification requires and is not a model of the machines, so the
traces it produced were ones no plant could — "start machine 1" five times in a
row. Plausible free-running traces need the plant model, which the generated
header does not carry.)

**Status: FIXED and regenerated.** The root cause was that `sim_seq` was
hand-written in Cell 4 while Cell 7 serialised it verbatim, with nothing checking
it against the supervisors Cell 6 had just synthesised. The notebook now carries
a corrected `fms` sequence and a new **Cell 6b** that replays `sim_seq` against
the synthesised supervisors and refuses to emit an inadmissible one.

`supervisor_data_fms.h` has been regenerated: `SIM_SEQ_LEN` 17 → 44, all 31
events covered, and the validator now replays it with **zero skipped steps**
(132 events fired over 3 cycles, against 23 before) on both families and at
1/2/3/7 nodes.

Regeneration also relabelled the states of `S4_red` (`1,2,3,4` cyclically
permuted). That is supervisor-reduction non-determinism, not a change of
behaviour — the automaton is isomorphic, confirmed by recovering the
permutation. Worth knowing if you diff generated headers between runs.

---

## 4. Configuring

Everything is a macro in `des_distributed.ino`; nothing in the engine needs
editing.

| macro | default | meaning |
|---|---|---|
| `DES_DATA_HEADER` | extended_small_factory | any generated header |
| `DES_NODE_ID` / `DES_NUM_NODES` | 1 / 2 | **different `DES_NODE_ID` per board** |
| `DES_FAMILY` | `LMOD_RED` | `LMOD_RED`, `LMOD`, or `MONO` (centralised baseline) |
| `DES_SUP_NODE_MAP` | *(even block partition)* | explicit supervisor→node, e.g. `{1,1,1,2,2,3,3}` |
| `DES_CONTROLLABLE_MASK` | *(inferred)* | override the controllability inference |
| `DES_BENCH_LOCKSTEP` | `0` | 0 = each node walks freely, waiting only on SHARED events (recommended); 1 = every node replays the whole trace — reproducible, but needs the nodes to keep step |
| `DES_SIMULATE_LOSS_PCT` | `0` | inject loss: `30` exercises retransmission, `90` forces a SAFE HALT |
| `DES_RXQ_LEN` | `64` | receive queue depth, power of two — see §4a |
| `DES_SYNC_TIMEOUT_MS` | `60000` | how long an owner waits for its participants to reach a shared step — see §4b |
| `DES_MCAST_LOOP` | `0` | `1` to run several nodes on one host (testing) |

### 4a. Why the engine keeps reading the socket while it computes

This is the single most important thing about running the engine on real
hardware, and it is worth stating plainly because it is not obvious.

A homomorphic step is slow. One scalar multiplication on secp192r1 costs
**~69 ms** on an ESP32-S3 — the chip has no ECC accelerator, unlike the C6 and
H2 — and a node owes **one per enablement row it must re-evaluate**, not one
per state. `row_decrypt()` sums a whole row homomorphically and then performs a
single blinded scalar multiplication on the sum, so a row is one scalar
multiplication however many states are still possible; extra possible states
only add `mbedtls_ecp_muladd` calls at ~5 ms each.

That distinction is measurable, and it sets the whole cost model:

| | ms per decryption |
|---|---|
| node holding S0–S3 (rows over 2–4 states) | 75.5 |
| node holding S4–S6 (rows over up to 13 states) | ~100 |

The 75.5 ms is the scalar multiplication; the rest is the row sum. A node is
expensive because of how many enablement rows it must re-evaluate per event —
S4/S5/S6 carry 47 constraining rows between them, and 22 to 47 were decrypted
per event on the first hardware runs — not because of how uncertain its state
estimate is.

Most of that turned out to be avoidable, for two reasons found by fitting a
ciphertext-level model to the hardware log (it reproduces every per-event
decryption count in it, 0 mismatches):

* **Rows were decrypted twice.** A row in both flip lists was decrypted by the
  first pass, flipped 0→1, and decrypted again by the second. Exactly half of
  node 1's decryptions were this.
* **Optimisation 6 had not been ported.** Once the non-zero cells contract to
  the active one, every row covering it has the *same* homomorphic sum. The
  single-board sketch decrypts each distinct sum once; this engine now does too.

| decryptions, fms, 5 cycles | node 1 | node 2 |
|---|---|---|
| before (measured on the ESP32-S3) | 420 | 3 924 |
| work list built first | 210 | 3 299 |
| + shared row sums (predicted, then measured exactly — host and ESP32-S3) | **100** | **397** |

Cycle 1 then costs 20 + 125 = **145** decryptions across the two nodes — exactly
what the single-board sketch measures for fms REDUCED. That is the check that
matters: distributing the supervisors splits the cryptographic work, it does not
add to it.

lwIP's UDP receive mailbox holds `CONFIG_LWIP_UDP_RECVMBOX_SIZE` datagrams,
**6** by default. (An Arduino build links precompiled ESP-IDF libraries and
cannot change it, so 6 is what actually runs.) A node that stops calling `recvfrom()` for longer than it takes
its peers to send seven frames loses everything after the sixth, silently: UDP
has no flow control and the sender is never told.

Losing a commit is therefore expensive in two ways. The state estimate stops
tracking the plant, which is a correctness problem; and the rows grow wider,
which costs perhaps a third more per decryption. The first matters far more
than the second — a node whose estimate has drifted is answering enablement
queries about a state the plant is not in.

A caution about the on-board check: both nodes can report `oracle PASS` through
a badly desynchronised run. The oracle compares ciphertext against cleartext
**for the events that node applied**; it cannot know the node was applying the
wrong ones. `PASS` certifies the cryptography, not the distributed execution.
Read the skip count and the applied-event count alongside it.

The engine therefore separates *reading* the socket from *acting* on what
arrives:

* `he_yield()` moves datagrams from the kernel into `g_rxq`. It touches no
  supervisor state and sends nothing, so it is safe to call from anywhere —
  including between the scalar multiplications inside `row_decrypt()`.
* `pump()` dispatches from that queue, and refuses to while `g_in_he` is set.
  Handling an `M_COMMIT` mid-step would re-enter `he_step()` and mutate
  `g_sups` under the outer call's own references; answering an `M_REQ` would
  vote from a `cached_en` array that is neither the pre-event nor the
  post-event state.

The queue is the buffer lwIP will not give us. Frames are delayed by at most
one homomorphic step instead of being destroyed, which is what the
acknowledgement timeouts were always assuming.

`rx queue: peak N/64` in the summary reports the high-water mark. If it ever
reports `DROPPED`, raise `DES_RXQ_LEN` — but read it as a symptom, because a
node that cannot drain 64 frames per step is not keeping up with its peers.

Measured on two ESP32-S3 running FMS after the queue was added: node 1 sent
2164 frames and node 2 received **2164**, queue peaks of 3 and 7 out of 64,
zero drops. Frame loss on a quiet LAN is no longer the limiting factor.

### 4b. Shared events are where the nodes meet

Replaying one global trace on several nodes raises a question a single board
never faces: when a node reaches a shared event in the trace, is its *peer*
there yet?

The two-phase commit answers only half of it. A participant's vote says its
**supervisor** allows the event. Whether its part of the **plant** has got there
— whether the machine the event belongs to has finished what precedes it in the
trace — the vote does not say, because a supervisor may well allow an event the
plant is not ready to produce. In the synchronous composition every plant here
is built from, a shared event occurs only when *every* component that has it in
its alphabet is ready for it. That is the missing half.

So each participant announces `M_AT(event, occurrence)` when its own walk
reaches a shared step, and the owner fires only after hearing it from every
participant. Frames carry the **occurrence number** — the third `31` in the
trace is occurrence 3 — so "has occurrence *k* been resolved?" is a yes/no
question. The waits are therefore **level-triggered**: an event that landed
before a node started waiting for it is already resolved and costs nothing.
Every node walks the same trace and only ever waits for positions at or before
its own, so no cycle of waits can form. The time the owner spends waiting for
its peers to arrive is reported separately as `sync-wait` — it is the plant
catching up, not protocol cost.

What this replaced, and why it failed. The first driver waited for a counter to
*change* (edge-triggered), then a start barrier tried to line the nodes up
before step 0. Measured on the two ESP32-S3: 134 and 55 of 220 steps skipped
with **zero frames lost**, then 95 and 34 with the barrier in place. The
desynchronisation was bookkeeping, not the network. Two defects compounded it:
`M_SKIP` was sent but never handled, so a participant waited out a full timeout
for an event its owner had already given up on; and a start barrier cannot
protect against the one thing that happened on the bench — a board rebooting
when its serial monitor was opened, and rejoining mid-run.

### 4c. Vetoes back off; there is no gap check, on purpose

**A veto is a decision, not a dropped packet.** Only a state change on the
vetoing peer can lift it, and that peer learns about state changes from frames
it must have room to receive. Re-asking on a fixed short interval therefore
*prevents the very thing being waited for*: the engine backs off geometrically
to one second, and rate-limits the log to one line plus a rollup. An earlier
fixed 50 ms retry sent ~150 requests per blocked event, which on its own was
enough to overrun a busy peer's mailbox.

**A gap in the sequence numbers proves nothing.** An earlier version treated a
jump in a sender's sequence as a lost commit — first halting on it, then asking
for the missing frame again. Both were wrong. With three or more nodes the owner
may commit *s−1* with node 2 and *s* with node 3, and node 3 then sees a "gap"
that is nothing of the sort. And a genuinely lost commit cannot happen at all:
the owner does not move on until **every** participant has acknowledged, and a
participant only acknowledges what it has accepted. The one real way to miss
commits is a reboot, and the epoch (§2) catches that directly. So the sequence
number does the one thing it can — reject duplicates — and nothing else.

### Controllability

The generated header does **not** record which events are controllable, so the
engine infers it from the labels and **prints what it inferred at boot** — check
that column:

* `a…` = activate/start → controllable, `b…` = finish → uncontrollable
  (`extended_small_factory`)
* otherwise trailing digit **odd** → controllable (Ramadge–Wonham numbering:
  `small_factory` `e1..e4`, and the FMS `11,12,21,22,…` labels)
* anything unrecognised defaults to **controllable**, which is the fail-safe
  direction — the node asks permission rather than acting unilaterally

Set `DES_CONTROLLABLE_MASK` to override. Best practice for a paper: set it
explicitly so the assumption is on the record.

### Partitioning

Default is an even contiguous block partition, which keeps supervisors that
share events together and so minimises the shared set. For FMS over 3 nodes the
derived routing gives **16 of 31 events traffic-free**. Override with
`DES_SUP_NODE_MAP` when a specific machine's actuator lives on a specific board.

---

## 5. Build & run

### ESP32

1. Open `des_distributed.ino`. Board **ESP32 Dev Module** / **ESP32S3 Dev
   Module**, Serial **115200**.
2. Copy `secrets.example.h` to `secrets.h` and fill it in. It holds the
   credentials, and is listed in `.gitignore` so they never reach a repository:
   * `WIFI_SSID` / `WIFI_PASS` — the access point every node joins.
   * `DES_AUTH_KEY`, the cell's shared secret: **identical on every node**, at
     least 32 characters, random (`python -c "import secrets;
     print(secrets.token_hex(32))"`). The build refuses to start without one, or
     with the template's placeholder. A board with a different key is reported
     as `FAILED AUTHENTICATION` and never joins.
3. Flash each board with a different `DES_NODE_ID`. At boot each prints
   `[init] config fingerprint XXXXXXXX`; the values must match (fms / 2 nodes /
   LMOD_RED / lockstep off → `c6a8a0da`). A board with another fingerprint is
   named and ignored rather than silently misrouted. The self-test also prints
   the measured cost of the frame tag.

No `sdkconfig` file is needed, or would have any effect: an Arduino build links
precompiled ESP-IDF libraries, and the mbedTLS acceleration they need (hardware
MPI, NIST fast reduction) is already on in the core's defaults.

On an **ESP32-S3** connected through its native USB port, set `USB CDC On
Boot: Enabled`. A board-package update can reset that option to its default,
*Disabled*, and the symptom is a completely blank Serial Monitor. Opening the
monitor can also reset the S3: mid-run, that correctly makes its peer halt with
`RESTARTED mid-run`. Open both monitors first (one IDE window per board), then
press RESET on both. After a run, type anything in the monitor to reprint the
summary.

### Linux / industrial PC

```bash
g++ -std=c++17 -O2 -DDES_NODE_ID=1 -DDES_NUM_NODES=2 \
    -o des_node1 host_main.cpp -lmbedcrypto -lmbedx509 -lmbedtls
```

Mixed deployments work: an ESP32 beside a machine and a Linux cell controller
are peers in the same multicast group speaking the same 44-byte signed frames
(the key comes from the same `secrets.h`). To run
several nodes on **one** host, add `-DDES_MCAST_LOOP=1` (and `-DDES_MCAST_TTL=0`
to keep the traffic on that machine).

### Verification status

* **ESP32 build.** Compiles with `-Wall -Wextra` and zero warnings against ESP32
  Arduino core 3.3.12 (`xtensa-esp32s3-elf-g++`), across all three problems ×
  2 and 3 nodes × all three families × lockstep on and off.
* **Two ESP32-S3 boards, fms, 5 cycles.** All 220 steps, 0 skipped, 0
  retransmissions, oracle PASS on both, no halt. Decryptions **100 + 397**,
  equal step by step (240 of 240) to the model's prediction made before the
  run. On the owner, a shared controllable event takes **91 ms**, of which
  **12.7 ms** is protocol: less than one round trip (probe: 14.3 ms), because
  `COMMIT` goes out before the owner's own homomorphic step and the `ACK` is
  already waiting when it finishes. The participant applies a shared event in
  229 ms in steady state. By node 1's clock the run takes about **54 s**: 8.6 s
  of its own steps, 25.2 s waiting for node 2 to reach shared steps, and 20 s
  of simulated machine time (`DES_WORK_MS`).

  | same run, before → after the work-list fix and shared row sums | before | after |
  |---|---|---|
  | decryptions, both nodes | 4 344 | **497** |
  | participant, per shared event | 2 411 ms | **300 ms** |
  | owner, per shared controllable event | 437 ms | **91 ms** |
  | waiting for the peer to reach shared steps | 264 s | **25 s** |
  | whole run (node 1's clock) | ≈ 5.3 min | **≈ 54 s** |
* **Frame authentication on the two ESP32-S3.** HMAC-SHA256/128 costs **98.7 and
  102.0 µs per frame** (self-test, SHA peripheral). Same 5-cycle run: 220/220
  steps, 0 frames rejected, 0 replays, one epoch challenge per board, identical
  decryption counts. Added latency, by the median — the mean moved more, with
  the network (round-trip probe max 216 ms that run, against 44 ms before):

  | per shared event, owner's wait | before | signed | change |
  |---|---|---|---|
  | 2PC, controllable (n = 40) | 13.3 ms | 14.2 ms | **+0.8 ms** — the 8 tag operations on its critical path × ~100 µs |
  | NOTIFY with the ACK already waiting (n = 20) | 1.3 ms | 1.9 ms | +0.6 ms |

* **The real engine on Linux** (`host_main.cpp` + g++ 13, several processes over
  real UDP multicast; mbedTLS replaced by a test double that computes the same
  homomorphic zero test over a toy group and a keyed stand-in for HMAC, so the
  cryptography itself is *not* exercised here — the protocol logic around it
  is):

  | scenario | result |
  |---|---|
  | fms, 2 nodes, at the S3's 69 ms per scalar multiplication | 44/44 steps, 0 skips, 0 retransmits |
  | fms, 3 nodes (events with two participants, and non-participants) | complete, 0 skips |
  | extended_small_factory, lockstep + monolithic cross-check | PASS, 18 events |
  | 10 % injected loss | complete, 13 retransmits |
  | 30 % injected loss | SAFE HALT on an unacknowledged COMMIT, propagated to the peer — the designed outcome |
  | peer rebooted after shared events | both halt, naming the restart |
  | two nodes with the same id / a node built with another family | reported on both sides, ignored |
  | decryption counts over 5 fms cycles | 100 + 397, equal step by step to the model's prediction |

  Attacks, by a process on the same network that does **not** hold the key:

  | attack | result |
  |---|---|
  | a node built with a different key | `FAILED AUTHENTICATION` on both sides; never joins |
  | a whole run recorded, then replayed verbatim ×5 (615 frames) into a new run | new run complete, 44/44, no halt, no false "restarted" or "duplicate id"; 20 challenges |
  | every live frame resent with one bit flipped, plus HALTs with random tags — 1.8 M frames in 10 s | all rejected; run complete, 0 skips |

* **Not exercised:** more than two physical boards. The flood above was
  absorbed by a PC. An ESP32 spends
  ~100 µs checking each tag, so ~10 000 frames/s would take its whole CPU —
  authentication stops forgery, not denial of service.

### About the headers

All three `supervisor_data_*.h` in this folder are **hard links** to the ones in
the repo root — the same bytes on disk under two names, so regenerating a header
updates both and they cannot drift.

---

## References

**Decentralised / modular supervisory control**
- K. Rudie, W. M. Wonham, *Think globally, act locally: decentralized supervisory control*, IEEE TAC 37(11), 1992.
- M. H. de Queiroz, J. E. R. Cury, *Modular supervisory control of large scale discrete event systems*, WODES 2000.
- C. G. Cassandras, S. Lafortune, *Introduction to Discrete Event Systems*, Springer.

**Distributing a supervisor over a real network**
- R. H. J. Schouten, L. Moormann, J. M. van de Mortel-Fronczak, J. E. Rooda, *Synthesis and Implementation of Distributed Supervisory Controllers with Communication Delays*, 2021. <https://arxiv.org/abs/2102.09821> — localisation plus **mutex algorithms** for delay robustness, hardware-in-the-loop.
- Y. Hou, Q. Li, *Distributed Nonblocking Supervisory Control of Timed DES with Communication Delays and Losses*, 2023. <https://arxiv.org/abs/2308.16545> — necessary and sufficient conditions: network controllability, network joint observability, language closure.
- *Modular and Distributed Supervisory Control Framework for Intelligent Micro-Manufacturing Systems with Unreliable Events*, 2025. <https://pmc.ncbi.nlm.nih.gov/articles/PMC12566142/> — same conjunctive fusion; notably specifies **no** middleware, confirming transport is an engineering choice.

**Distributed systems**
- J. H. Saltzer, D. P. Reed, D. D. Clark, *End-to-End Arguments in System Design*, ACM TOCS 2(4), 1984.
- D. J. Rosenkrantz, R. E. Stearns, P. M. Lewis, *System level concurrency control for distributed database systems*, ACM TODS 3(2), 1978 — wound-wait.
- J. Gray, *Notes on Data Base Operating Systems*, 1978 — two-phase commit.

**Encrypted control**
- M. Schulze Darup et al., *Encrypted control for networked systems*, 2020. <https://arxiv.org/abs/2010.00268>
- *Comparison of encrypted control approaches*, Annual Reviews in Control, 2022.
- *Privacy-Preserving Supervisory Control of DES via Co-Synthesis*, 2021. <https://arxiv.org/abs/2104.04299> — note the gap this work sits in: opacity enforcement and encrypted control are both active, but combining homomorphic encryption with DES supervision is largely unexplored.

**Standards**
- RFC 1112 (IP multicast), RFC 3376 (IGMPv3), RFC 2365 (administratively scoped multicast).
- ISO/IEC 20922 — MQTT 3.1.1. · IEC 62541-14 — OPC UA PubSub. · OMG DDS.
- open62541 <https://open62541.org> · Eclipse Cyclone DDS <https://cyclonedds.io> · eProsima Fast DDS <https://fast-dds.docs.eprosima.com>
