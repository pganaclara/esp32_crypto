# Distributed Homomorphic DES — generic engine

Runs any supervisor set the UltraDES notebook generates, partitioned over any
number of nodes, with each node's plant state held only as EC-ElGamal
ciphertexts under **its own** keypair. The event routing, the owner election,
the shared/local partition and the participant sets are all **derived at boot**
from the generated header; nothing is specific to a plant or a board.

```
des_generic.h        the engine    — no Arduino, no FreeRTOS, no ESP-IDF
des_transport.h      the transport — UDP/IP multicast
des_distributed.ino  ESP32 entry point   (config + setup/loop)
host_main.cpp        POSIX entry point   (Linux / *BSD / macOS)
secrets.example.h    template for secrets.h — Wi-Fi + cell key (secrets.h is not versioned)
```

Runs every header in this repo: `small_factory` (4 events, 1 supervisor),
`extended_small_factory` (6 events, 2 supervisors) and `fms` (31 events,
7 supervisors, largest 164 states).

---

## 1. Transport

**UDP/IP multicast** (RFC 1112, RFC 3376): open, implemented by every IP stack,
no broker, no library, no vendor. It runs unmodified on ESP32 (lwIP), Linux,
*BSD, macOS, QNX, VxWorks — anything with BSD sockets — and joining the group
*is* the discovery step. It is also the substrate the industrial standards use:
OPC UA PubSub (IEC 62541-14) defines a brokerless UDP mapping over it, alongside
broker-based MQTT and AMQP mappings meant for IT and cloud systems, and DDS/RTPS
runs over UDP too, so moving to either is a transport swap, not an architecture
change.

ESP-NOW was rejected as vendor-specific: it exists only on Espressif silicon and
no standards body specifies it. MQTT (ISO/IEC 20922) is open but was not chosen:
the broker is a third failure domain between two controllers a metre apart;
every message makes an extra trip through it, adding latency and jitter, and
jitter is what hurts an interlock; and the broker sees every frame.

The transport is pluggable **because reliability is end-to-end** (Saltzer, Reed
& Clark 1984): the protocol supplies sequencing, acknowledgement, retransmission
and atomicity, so a transport only has to be best effort — and a transport's own
per-hop reliability, such as MQTT's QoS 1/2, would add nothing. The whole
contract:

```c
struct DesTransport {
    bool (*begin)();
    bool (*send)(const void* frame, int len);   // best effort, to all peers
    bool (*poll)(void* frame, int len);         // non-blocking
    void (*service)();                          // keepalive / reconnect
};
```

| | UDP multicast | MQTT | OPC UA PubSub | DDS | ESP-NOW |
|---|---|---|---|---|---|
| standard | RFC 1112 | ISO/IEC 20922 | IEC 62541-14 | OMG | **vendor** |
| open-source stack | none needed | Mosquitto/EMQX | open62541 (MPL-2.0) | Cyclone (EPL-2.0), Fast DDS (Apache-2.0) | Espressif only |
| broker | no | **yes** | no over UDP/Ethernet; yes over MQTT/AMQP | no | no |
| runs off-ESP32 | **yes** | yes | yes | yes | **no** |
| status here | **implemented** | not chosen | ~100 lines to add | ~80 lines to add | rejected |

Adding OPC UA PubSub (its UDP mapping) or DDS means implementing those four
functions. Neither is
bundled because each pulls in a build system this sketch does not assume.

---

## 2. Protocol

Conjunctive fusion over the nodes that constrain an event. The
controllable/uncontrollable distinction drives two different mechanisms:

| event class | mechanism | frames |
|---|---|---|
| local (one node relevant) | apply locally | **0** |
| shared + **controllable** | `REQ → VOTE* → COMMIT → ACK*` — any participant may veto | 2 + 2p |
| shared + **uncontrollable** | `NOTIFY → ACK*`, retransmitted until acknowledged | 1 + p |

*(p = number of participants)*

An uncontrollable event **cannot be vetoed**: SCT controllability says a
supervisor may not disable one, and by the time a node hears about it the plant
has already done it. It gets a reliable notification instead. Safety is enforced
upstream — the supervisor already disabled the controllable event that would have
led somewhere unsafe.

Only the **participants** of an event — the nodes holding a supervisor that
constrains it or moves on it — vote, apply and acknowledge. Multicast delivers
every frame to every node, so the others ignore it.

**Concurrency.** Participants hold a lock between `VOTE`-yes and
`COMMIT`/`ABORT`, so two initiators can never interleave transactions on the same
supervisor, and a locked node fires none of its own events until the transaction
settles — its YES was a promise about its current state. An initiator collecting
votes answers other requests by **wound-wait** (Rosenkrantz, Stearns & Lewis
1978): an older (lower-numbered) requester wounds it and it aborts its own
attempt; a younger one is told no, so the wait-for graph cannot contain a cycle.
Preemption is safe because nothing has been applied while a lock is held. Once
every vote is in, the initiator sends `COMMIT` first and applies locally second,
so the participants' homomorphic steps run in parallel with its own.

**Loss.** Every `COMMIT`/`NOTIFY` is retransmitted until every participant has
acknowledged it; the per-sender sequence number only rejects duplicates. When the
budget is exhausted a node **SAFE-HALTS** rather than continue on state that may
have diverged from its peers, and tells any peer still talking. This is the Two
Generals trade made explicit: safety preserved, liveness sacrificed — a real cost
of distributing that a single board does not have.

**Identity.** Every frame carries a random per-boot **epoch** and a
**fingerprint** of the configuration (protocol version, node count, lockstep,
event table, derived partition, trace). A peer whose epoch changes after shared
events has rebooted — its supervisors are back in their initial state — and both
sides halt; before any shared event it simply rejoins. A second board with the
same `DES_NODE_ID`, or one built from a different header, family or partition, is
reported by name and ignored.

**Authentication.** Every 44-byte frame is signed, in the same three layers OPC
UA PubSub uses in its *Sign* mode (IEC 62541-14):

1. **Integrity and authenticity.** HMAC-SHA256 over every other byte, under the
   cell's shared key `DES_AUTH_KEY`, truncated to 128 bits (RFC 2104 §5). A frame
   whose tag does not verify is dropped before any field is read; the comparison
   is constant-time.
2. **Freshness within a boot.** A per-sender counter that only increases; a
   frame whose counter has already been passed is dropped.
3. **Freshness across boots.** A recording of an earlier run carries an earlier
   epoch, which would look like "the peer rebooted" and halt the cell. So a new
   epoch is never believed on sight: the receiver sends a random 64-bit nonce
   (`M_CHAL`) and accepts the epoch only when a correctly tagged `M_RESP`
   carrying that nonce comes back. A recording cannot answer a question that did
   not exist when it was made.

Not provided: **confidentiality** — frames are signed, not encrypted, so an
observer sees which shared events happen and how nodes vote (OPC UA's
*SignAndEncrypt* mode adds that) — and **key distribution**: the key is
pre-shared by hand, where OPC UA would use a Security Key Service.

**Checks on every run.** Each node compares every homomorphic bit against a
cleartext oracle of its own supervisors, and every scripted step is gated on
admissibility: a step the supervisors disable is skipped and reported, never
fired. With `DES_BENCH_LOCKSTEP 1` and a header that carries a monolithic
supervisor, the global trace is also replayed against it.

**Plant check.** A synthesised supervisor never disables an uncontrollable event
the plant can produce — that is what controllability means. So when a node's
supervisors disable a reported uncontrollable event, no machine could have
produced it from the current state: a sensor fault, a forged report, or a model
that does not match the plant. The owner rejects it (`IMPOSSIBLE`, then `SKIP`);
a participant that receives it in a `NOTIFY` cannot refuse it, and halts rather
than empty its supervisors' state. How much this catches depends on the family.
The **full local-modular** and the **monolithic** supervisors are synthesised
over the plant, so their state tracks the machines and every impossible
uncontrollable event is caught (for FMS, every machine is in some supervisor's
local plant). A **reduced** supervisor merges states that differ only in
behaviour the plant cannot generate, so it may accept an impossible event: at
the start of FMS, the reduced S0 allows `12` ("C1 finished") although C1 was
never started, and the full S0 does not (the boot line `[init] my enablement`
shows `12=1` with the reduced family and `12=0` with the full one). This is why the sketch now uses
`DES_FAMILY_LMOD`. The summary reports the count of rejected reports.

---

## 3. Running on real hardware

### 3a. Cost, and why the engine keeps reading the socket while it computes

One scalar multiplication on secp192r1 costs **~69 ms** on an ESP32-S3 (the chip
has no ECC accelerator, unlike the C6 and H2). A node owes **one per distinct
enablement-row sum it must re-evaluate**, not one per state: `row_decrypt()` sums
a row homomorphically and performs a single blinded scalar multiplication on the
sum; extra possible states only add `mbedtls_ecp_muladd` calls at ~5 ms each.
Rows whose sums cover the same ciphertexts share one decryption.

| | ms per decryption |
|---|---|
| node holding S0–S3 (rows over 2–4 states) | 75.5 |
| node holding S4–S6 (rows over up to 13 states) | ~100 |

On `fms` over two boards, cycle 1 costs 20 + 125 = **145** decryptions — exactly
what the single-board sketch measures for fms REDUCED. Distributing splits the
cryptographic work; it does not add to it.

A homomorphic step therefore takes hundreds of milliseconds, and lwIP's UDP
receive mailbox holds only `CONFIG_LWIP_UDP_RECVMBOX_SIZE` = **6** datagrams (an
Arduino build links precompiled ESP-IDF libraries and cannot change it). A node
that stops calling `recvfrom()` for longer than it takes its peers to send seven
frames loses everything after the sixth, silently. So the engine separates
*reading* the socket from *acting* on what arrives:

* `he_yield()` moves datagrams from the kernel into `g_rxq`. It touches no
  supervisor state and sends nothing, so it is called between the scalar
  multiplications inside `row_decrypt()`.
* `pump()` dispatches from that queue, and refuses to while `g_in_he` is set:
  handling an `M_COMMIT` mid-step would re-enter `he_step()`, and answering an
  `M_REQ` would vote from a half-updated `cached_en`.

Frames are delayed by at most one homomorphic step instead of being destroyed.
`rx queue: peak N/64` in the summary reports the high-water mark; if it ever
reports `DROPPED`, raise `DES_RXQ_LEN`, but read it as a node that is not keeping
up with its peers.

A caution about the on-board check: both nodes can report `oracle PASS` through a
badly desynchronised run. The oracle compares ciphertext against cleartext **for
the events that node applied**; it cannot know they were the wrong ones. `PASS`
certifies the cryptography, not the distributed execution — read the skip count
alongside it.

### 3b. Shared events are where the nodes meet

A participant's vote says its **supervisor** allows the event, not that its part
of the **plant** has got there — a supervisor may allow an event the plant is not
ready to produce. In the synchronous composition every plant here is built from,
a shared event occurs only when *every* component that has it in its alphabet is
ready for it.

So each participant announces `M_AT(event, occurrence)` when its own walk
reaches a shared step, and the owner fires only after hearing it from every
participant. Frames carry the **occurrence number** — the third `31` in the trace
is occurrence 3 — so the waits are **level-triggered**: an event that landed
before a node started waiting for it is already resolved and costs nothing.
Every node walks the same trace and only waits for positions at or before its
own, so no cycle of waits can form. The owner's wait is reported separately as
`sync-wait`: it is the plant catching up, not protocol cost.

### 3c. Vetoes back off; there is no gap check, on purpose

**A veto is a decision, not a dropped packet.** Only a state change on the
vetoing peer can lift it, and that peer learns of state changes from frames it
must have room to receive. Re-asking on a short fixed interval would prevent the
very thing being waited for, so the engine backs off geometrically to one second
and rate-limits the log.

**A gap in the sequence numbers proves nothing.** With three or more nodes the
owner may commit *s−1* with node 2 and *s* with node 3, and node 3 sees a "gap"
that is nothing of the sort. A genuinely lost commit cannot happen: the owner
does not move on until **every** participant has acknowledged. The one real way
to miss commits is a reboot, and the epoch (§2) catches that directly.

---

## 4. Configuring

Everything is a macro in `des_distributed.ino`; nothing in the engine needs
editing.

| macro | default | meaning |
|---|---|---|
| `DES_DATA_HEADER` | extended_small_factory | any generated header |
| `DES_NODE_ID` / `DES_NUM_NODES` | 1 / 2 | **different `DES_NODE_ID` per board** |
| `DES_FAMILY` | `LMOD_RED` (the sketch sets `LMOD`) | `LMOD` (carries the plant: full plant check), `LMOD_RED` (smallest, but an impossible event may pass), or `MONO` (centralised baseline) |
| `DES_SUP_NODE_MAP` | *(even block partition)* | explicit supervisor→node, e.g. `{1,1,1,2,2,3,3}` |
| `DES_CONTROLLABLE_MASK` | *(inferred)* | override the controllability inference |
| `DES_BENCH_LOCKSTEP` | `0` | 0 = each node walks freely, waiting only on SHARED events (recommended); 1 = every node replays the whole trace — reproducible, but needs the nodes to keep step |
| `DES_WORK_MS` | `250` (the sketch sets `0`) | simulated machine time before each uncontrollable event; `0` times the cryptography and the protocol alone, as the single-board sketch does. Every node prints `-- cycle N/R done at X ms --` on a run clock common to all nodes (it starts when node 1's round-trip probe ends), and repeats the values in its summary; a cycle is over at the latest node's value |
| `DES_SIMULATE_LOSS_PCT` | `0` | inject loss: `30` exercises retransmission, `90` forces a SAFE HALT |
| `DES_RXQ_LEN` | `64` | receive queue depth, power of two — see §3a |
| `DES_SYNC_TIMEOUT_MS` | `60000` | how long an owner waits for its participants to reach a shared step — see §3b |
| `DES_MCAST_LOOP` | `0` | `1` to run several nodes on one host (testing) |
| `DES_INJECT_EVENT` / `DES_INJECT_AT_STEP` | *(off)* / `0` | plant-check demonstration: at that step of cycle 1 the event's owner acts as if a sensor reported it and prints `ACCEPTED` or `REJECTED`; nothing is applied |

**Controllability.** The generated header does not record it, so the engine
infers it from the labels and **prints what it inferred at boot** — check that
column. `a…` = start → controllable and `b…` = finish → uncontrollable
(`extended_small_factory`); otherwise an **odd** trailing digit is controllable
(`small_factory` `e1..e4`, the FMS `11, 12, 21, 22, …` labels); anything
unrecognised defaults to controllable, the fail-safe direction. For a paper, set
`DES_CONTROLLABLE_MASK` explicitly so the assumption is on the record.

**Partitioning.** The default even contiguous block partition keeps supervisors
that share events together and so minimises the shared set; for FMS over 3 nodes
it leaves **16 of 31 events traffic-free**. Override with `DES_SUP_NODE_MAP` when
a machine's actuator lives on a specific board.

---

## 5. Build & run

### ESP32

1. Open `des_distributed.ino`. Board **ESP32 Dev Module** / **ESP32S3 Dev
   Module**, Serial **115200**.
2. Copy `secrets.example.h` to `secrets.h` and fill it in (it is in `.gitignore`):
   * `WIFI_SSID` / `WIFI_PASS` — the access point every node joins.
   * `DES_AUTH_KEY` — the cell's shared secret: **identical on every node**, at
     least 32 random characters (`python -c "import secrets;
     print(secrets.token_hex(32))"`). The build refuses to start without one or
     with the template's placeholder; a board with a different key is reported
     as `FAILED AUTHENTICATION` and never joins.
3. Flash each board with a different `DES_NODE_ID`. At boot each prints
   `[init] config fingerprint XXXXXXXX`; the values must match (fms / 2 nodes /
   lockstep off → `6e52cd12` with `LMOD`, `c6a8a0da` with `LMOD_RED`).

On an **ESP32-S3** on its native USB port, set `USB CDC On Boot: Enabled`; a
board-package update can reset it, and the symptom is a blank Serial Monitor.
Opening the monitor can also reset the S3, which mid-run correctly makes its peer
halt with `RESTARTED mid-run`: open both monitors first, then press RESET on both.
After a run, type anything in the monitor to reprint the summary.

### Linux / industrial PC

```bash
g++ -std=c++17 -O2 -DDES_NODE_ID=1 -DDES_NUM_NODES=2 \
    -o des_node1 host_main.cpp -lmbedcrypto -lmbedx509 -lmbedtls
```

An ESP32 beside a machine and a Linux cell controller are peers in the same
multicast group, speaking the same 44-byte signed frames with the key from the
same `secrets.h`. To run several nodes on **one** host, add `-DDES_MCAST_LOOP=1`
(and `-DDES_MCAST_TTL=0` to keep the traffic on that machine).

### Verification status

* **ESP32 build.** Compiles with `-Wall -Wextra` and zero warnings against ESP32
  Arduino core 3.3.12 (`xtensa-esp32s3-elf-g++`), across all three problems ×
  2 and 3 nodes × all three families × lockstep on and off.
* **Two ESP32-S3 boards, fms, reduced family, 5 cycles.** All 220 steps, 0 skipped, 0
  retransmissions, oracle PASS on both, no halt. Decryptions **100 + 397**,
  equal step by step (240 of 240) to the model's prediction made before the
  run. On the owner, a shared controllable event takes **91 ms**, of which
  **12.7 ms** is protocol: less than one round trip (probe: 14.3 ms), because
  `COMMIT` goes out before the owner's own homomorphic step. The participant
  applies a shared event in 229 ms in steady state. By node 1's clock the run
  takes about **54 s**: 8.6 s of its own steps, 25.2 s waiting for node 2 to
  reach shared steps, and 20 s of simulated machine time (`DES_WORK_MS`).
* **Frame authentication on the two ESP32-S3.** HMAC-SHA256/128 costs **98.7 and
  102.0 µs per frame** (self-test, SHA peripheral). Same 5-cycle run: 220/220
  steps, 0 frames rejected, 0 replays, one epoch challenge per board, identical
  decryption counts. Added latency, by the median:

  | per shared event, owner's wait | unsigned | signed | change |
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

* **Plant check, on Linux** (same test double; decryption counts are exact, as
  the rows above show):

  | scenario | result |
  |---|---|
  | fms, 2 nodes, full local modular, 5 cycles | 220/220 steps, 0 skips, 0 rejected; decryptions **405 + 393** (85 + 105 in cycle 1), equal to the model's prediction |
  | fms, 2 nodes, reduced, 5 cycles | unchanged: 100 + 397, fingerprint `c6a8a0da` |
  | fake report of `12` at step 0 (`DES_INJECT_EVENT`) | full local modular: **REJECTED**; reduced: **ACCEPTED** |
  | trace edited so that `12` comes before `11` | node 1: `IMPOSSIBLE`, `SKIP`; the steps that depended on it are skipped too |
  | extended_small_factory, full local modular, lockstep + monolithic cross-check | PASS |

* **Two ESP32-S3 boards, fms, full local modular, 5 cycles, three runs** (the
  sketch's setting since the plant check): two with `DES_WORK_MS 250`, and a
  third with `DES_WORK_MS 0` to time whole cycles. All three: all 220 steps, 0
  skipped, 0 retransmissions, 0 reports rejected by the plant check, oracle PASS
  on both nodes, no halt. Decryptions **405 + 393** (85 + 105 in cycle 1, then
  80 + 72 per cycle) every time, equal to the model's prediction made before
  the first; the homomorphic time of each step differs by at most 0.1 %
  between runs. Protocol time per controllable shared event: median 17.8 ms
  against an 18.2 ms mean round trip (second run), 13.2 against 13.9 ms
  (third). The first run saw three Wi-Fi delays of 0.16–0.69 s in its last
  cycle, with no loss and no retransmission (mean 44.6 ms, median 14.6 ms); the
  others did not.

  | fms, two ESP32-S3, 5 cycles | reduced | full local modular (2nd run) |
  |---|---|---|
  | encrypted cells, node 1 / node 2 | 11 / 26 | 75 / 252 |
  | decryptions, node 1 / node 2 | 100 / 397 | 405 / 393 |
  | initial enablement of `12` ("C1 finished") on node 1 | **1** — would accept it | **0** — rejects it |

  **One board against two.** The comparison uses the **full local-modular
  family only**: the reduced family cannot complete the plant check, so it is
  not the same system. Both setups are measured the same way: the time to
  complete cycle 1 of the trace, without machine time, divided by its 44 steps.
  The single-board sketch reports it directly (`Total` 15 224.8 ms, `Avg` 346.0
  ms, both cores, 190 decryptions, run the same day). The third two-board run
  (`DES_WORK_MS 0`) prints every cycle's end on a run clock common to both
  nodes; a cycle is over at the later node, node 2 every time (13 065.0,
  20 422.2, 27 808.4, 35 154.2, 42 494.2 ms):

  | fms, full local modular, time per step | one board | two boards |
  |---|---|---|
  | cycle 1 | **346.0 ms** (15.2 s) | **296.9 ms** (13.1 s) |
  | cycles 2–5 | not run | 167.2 ms |

  Two boards finish cycle 1 **14 % sooner**, because the work is balanced (405
  against 393 decryptions), although each node uses one core where the single
  board uses two. Node 2's clock starts at node 1's last probe `PING`, some
  30 ms before node 1's, so these times err on the slow side by that much.
  Before this run, a replay of the second run's logged step times (each node's
  steps in order, a shared step starting once the participant has reached it)
  had predicted 298.3 and 168.3 ms. A node's own `all events` average (201.7 ms
  on node 1 in the second run) is not the system's time per step: it leaves out
  the other node's local events, the applies and the waits.
* **Not exercised:** more than two physical boards. The flood above was absorbed
  by a PC; an ESP32 spends ~100 µs checking each tag, so ~10 000 frames/s would
  take its whole CPU — authentication stops forgery, not denial of service.

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
