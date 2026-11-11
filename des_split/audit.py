"""Audit of a des_split run: did the supervisor board compute what it should?

    python audit.py record RUN.bin [--port 5078] [--group 239.192.7.1] [--iface IP]
    python audit.py check RUN.bin --header supervisor_data_cluster_tool_2.h
                          --seed HEX --supervisor-pub HEX [--curve 256]

record joins the boards' multicast group, on a computer of the same network,
and writes every frame of the run; it stops a few seconds after the plant's
FIN (or with Ctrl-C).

check takes the recording, the supervisor's tables (the header) and its
opening (the seed it printed at boot, given to the auditor only), and its
identity public key (DES_PUB_SUPERVISOR of secrets.h). From the seed and the
events of the run (encrypted in the plant's STEP frames: the seed gives the
supervisor's ephemeral key, and with the plant's share in its KEY, the key of the
event's encryption) it redoes everything the supervisor board computed: its key share, the
initial encryption, and, at every step, the new encrypted state and every
decision with the supervisor's part of its decryption. It compares them with
the frames of the recording, and these with the chain of records that the
supervisor signed after every step. A difference is a deviation of the
supervisor, and its signature makes it undeniable.

--mock checks a host run with the fake mbedTLS of the tests (the group Z_p,
p = 2^61 - 1) instead of a NIST curve. No dependencies.
"""
import argparse
import hashlib
import hmac
import re
import socket
import struct
import sys
import time

from make_keys import CURVES

FRAME, TAG = 1400, 16
HDR = struct.Struct('<IBBHHHIIII')            # magic type role chunk nchunks count epoch peer cfg seq
MAGIC = 0x4C505344
T_KEY, T_READY, T_STEP, T_DECS, T_NACK, T_FIN, T_SIGN = 1, 2, 3, 6, 7, 8, 9
NO_EVENT = 0xFFFF
PLANT, SUPERVISOR = 1, 2


def sha(b):
    return hashlib.sha256(b).digest()


class Nist:                                    # NIST P-192, P-224, P-256 (a = -3)
    def __init__(self, bits):
        self.p, self.b, gx, gy, self.n = CURVES[bits]
        self.G, self.O, self.size = (gx, gy), None, bits // 8

    def add(self, P, Q):
        if P is None: return Q
        if Q is None: return P
        p = self.p
        if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return None
        if P == Q: lam = (3 * P[0] * P[0] - 3) * pow(2 * P[1], -1, p) % p
        else: lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
        x = (lam * lam - P[0] - Q[0]) % p
        return x, (lam * (P[0] - x) - P[1]) % p

    def mul(self, k, P):
        R, k = None, k % self.n
        while k:
            if k & 1: R = self.add(R, P)
            P, k = self.add(P, P), k >> 1
        return R

    def raw(self, P):
        if P is None: return bytes(2 * self.size)
        return P[0].to_bytes(self.size, 'big') + P[1].to_bytes(self.size, 'big')

    def point(self, b):
        if not any(b): return None
        x, y = int.from_bytes(b[:self.size], 'big'), int.from_bytes(b[self.size:], 'big')
        if (y * y - (x ** 3 - 3 * x + self.b)) % self.p: raise ValueError('a point not on the curve')
        return x, y

    def scalar(self, h64): return int.from_bytes(h64, 'big') % (self.n - 1) + 1     # det_scalar
    def mod_n(self, b): return int.from_bytes(b, 'big') % self.n                     # read_binary, mod N
    def read(self, b): return int.from_bytes(b, 'big')                               # read_binary


class Mock(Nist):                               # the fake mbedTLS of the host tests: Z_p, G = 1
    def __init__(self, bits):
        self.p = self.n = (1 << 61) - 1
        self.G, self.O, self.size = 1, 0, bits // 8

    def add(self, P, Q): return (P + Q) % self.p
    def mul(self, k, P): return (k % self.p) * P % self.p

    def raw(self, v):
        b = bytearray(2 * self.size)
        b[self.size - 8:self.size] = v.to_bytes(8, 'big')
        return bytes(b)

    def point(self, b): return int.from_bytes(b[self.size - 8:self.size], 'big')
    def scalar(self, h64): return int.from_bytes(h64[-8:], 'big') % (self.p - 1) + 1
    def mod_n(self, b): return int.from_bytes(b[-8:], 'big') % self.p
    def read(self, b): return int.from_bytes(b[-8:], 'big')


# ── the supervisor's tables, from the header ─────────────────────────────────
def controllable(name):                         # des_split.h derive_controllable
    if name.startswith('a'): return True
    if name.startswith('b'): return False
    digits = [c for c in name if c.isdigit()]
    return int(digits[-1]) % 2 == 1 if digits else True


def read_header(path):
    s = open(path, encoding='utf-8').read()

    def arr(name):
        m = re.search(r'static const \w+ ' + name + r'\[\] PROGMEM = \{(.*?)\};', s, re.S)
        return [int(x) for x in re.findall(r'-?\d+', m.group(1))]
    E = int(re.search(r'#define EVENT_COUNT (\d+)', s).group(1))
    NS = int(re.search(r'#define MONO_NUM_STATES (\d+)', s).group(1))
    names = dict((int(i), n) for i, n in re.findall(r'static const char EV_(\d+)\[\] PROGMEM = "([^"]*)";', s))
    t = dict(NS=NS, E=E, init=arr('mono_init'), enable=arr('mono_enable'),
             tcnt=arr('mono_tcnt'), trans=arr('mono_trans'))
    t['ctrl'] = sum(1 << e for e in range(E) if controllable(names[e]))
    pairs, off = [], 0
    for e in range(E):
        pairs.append([(t['trans'][2 * (off + p)], t['trans'][2 * (off + p) + 1]) for p in range(t['tcnt'][e])])
        off += t['tcnt'][e]
    t['pairs'] = pairs
    # per event, the states that it moves into each state; the decision rows,
    # in the order of build_tables()
    moves = []
    for e in range(E):
        into = {}
        for frm, to in pairs[e]: into.setdefault(to, []).append(frm)
        moves.append(into)
    rows = []
    en = lambda e, q: t['enable'][e * NS + q] != 0
    for e in range(E):
        if not (t['ctrl'] >> e) & 1: continue
        for r in rows:
            if all((q in r[1]) == en(e, q) for q in range(NS)):
                r[0] |= 1 << e
                break
        else:
            rows.append([1 << e, [q for q in range(NS) if en(e, q)]])
    t['moves'], t['rows'] = moves, rows
    return t


def tables_bytes(t):                            # des_split.h tables_bytes()
    b = struct.pack('<IIQ', t['NS'], t['E'], t['ctrl']) + bytes(v & 0xff for v in t['init'])
    for e in range(t['E']):
        b += struct.pack('<H', t['tcnt'][e]) + b''.join(struct.pack('<hh', f, to) for f, to in t['pairs'][e])
        b += bytes(v & 0xff for v in t['enable'][e * t['NS']:(e + 1) * t['NS']])
    return b


# ── record ───────────────────────────────────────────────────────────────────
def record(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', a.port))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                 socket.inet_aton(a.group) + socket.inet_aton(a.iface))
    s.settimeout(1.0)
    n, seen, fin, shown = 0, 0, None, time.time()
    with open(a.run, 'wb') as f:
        print(f'recording {a.group}:{a.port} into {a.run}; Ctrl-C to stop')
        try:
            while fin is None or time.time() - fin < 3:
                try: d = s.recv(4096)
                except socket.timeout: d = b''      # no `continue` here: in Python 3.12 it lets Ctrl-C escape
                seen += bool(d)
                if time.time() - shown >= 5:
                    print(f'  {n} frames ({seen} datagrams received)'); shown = time.time()
                if len(d) != FRAME or HDR.unpack_from(d)[0] != MAGIC: continue
                f.write(d); n += 1
                if HDR.unpack_from(d)[1] == T_FIN and fin is None: fin = time.time()
        except KeyboardInterrupt:
            pass
    print(f'{n} frames')
    if not seen:
        print('nothing received: is this computer on the same Wi-Fi network (SSID) as the boards, '
              'and was the recording started before the boards were reset?')


# ── check ────────────────────────────────────────────────────────────────────
class Audit:
    def __init__(self, g, seed):
        self.g, self.seed = g, seed

    def det(self, tag, a, b, ctr, key=None):
        return hmac.new(key or self.seed, tag.encode() + struct.pack('<II', a, b) + bytes([ctr]),
                        hashlib.sha256).digest()

    def det_scalar(self, tag, a, b, key=None):
        return self.g.scalar(self.det(tag, a, b, 1, key) + self.det(tag, a, b, 2, key))

    def enc(self, m, tag, a, b, key=None):      # cr_enc_det, under the seed or the key given
        g, s = self.g, self.det_scalar(tag, a, b, key)
        V = g.mul(s, self.Y)
        if m: V = g.add(V, g.G)
        return (g.mul(s, g.G), V)

    def raw(self, c): return self.g.raw(c[0]) + self.g.raw(c[1])
    def addc(self, c, d): return (self.g.add(c[0], d[0]), self.g.add(c[1], d[1]))

    def schnorr_ok(self, X, pre, sig):          # zG - cX = R
        g, P = self.g, 2 * self.g.size
        R, z = g.point(sig[:P]), g.read(sig[P:P + g.size])
        c = g.mod_n(sha(pre + sig[:P]))
        return g.add(g.mul(z, g.G), g.mul(g.n - c, X)) == R


def kdf(key, label):                            # cr_kdf
    return hmac.new(key, label, hashlib.sha256).digest()


def check(a):
    g = Mock(a.curve) if a.mock else Nist(a.curve)
    t = read_header(a.header)
    NS, E, P, SC = t['NS'], t['E'], 2 * g.size, g.size
    CELL, SIG = 2 * P, P + SC
    KEY_MSG = P + SIG
    KEY_PAY = KEY_MSG + 32 + P                   # share, proof, commitment, E_S
    DECS_ITEM = 8 + CELL + P
    au = Audit(g, bytes.fromhex(a.seed))
    Xs = g.point(bytes.fromhex(a.supervisor_pub))
    data = open(a.run, 'rb').read()
    frames = []
    for i in range(0, len(data) - FRAME + 1, FRAME):
        f = data[i:i + FRAME]
        magic, typ, role, chunk, nch, count, ep, peer, cfg, seq = HDR.unpack_from(f)
        if magic == MAGIC: frames.append(dict(f=f, p=f[HDR.size:FRAME - TAG], type=typ, role=role, chunk=chunk,
                                              nch=nch, count=count, epoch=ep, peer=peer, seq=seq))
    print(f'{len(frames)} frames recorded')
    problems = []

    # the session: the last supervisor KEY that its identity key signed
    skeys = [x for x in frames if x['type'] == T_KEY and x['role'] == SUPERVISOR
             and au.schnorr_ok(Xs, x['f'][:HDR.size + KEY_PAY], x['p'][KEY_PAY:KEY_PAY + SIG])]
    if not skeys: sys.exit('no KEY signed by the supervisor in the recording')
    es, ep = skeys[-1]['epoch'], skeys[-1]['peer']
    s_pay = skeys[-1]['p'][:KEY_PAY]
    pkeys = [x for x in frames if x['type'] == T_KEY and x['role'] == PLANT and x['epoch'] == ep]
    if not pkeys: sys.exit('no KEY of the plant of this session in the recording')
    p_pay = pkeys[0]['p'][:KEY_PAY]
    print(f'session: plant {ep:08x}, supervisor {es:08x}')

    # the opening: the commitment, the share
    commit = sha(b'des_split commit' + au.seed + tables_bytes(t))
    if commit != s_pay[KEY_MSG:KEY_MSG + 32]:
        sys.exit('the seed and the tables do not open the supervisor\'s commitment')
    print('commitment opened: the seed and the tables are those the supervisor committed to at boot')
    kS = au.det_scalar('share', 0, 0)
    if g.raw(g.mul(kS, g.G)) != s_pay[:P]: sys.exit('the supervisor\'s key share is not derived from its seed')
    Yp = g.point(p_pay[:P])
    au.Y = g.add(Yp, g.point(s_pay[:P]))
    # the key of the event's encryption (cr_session), K_1, from the supervisor's
    # ephemeral key e_S and the plant's share, and the supervisor's seed of the
    # encryptions of zero of the boot, z_0; both move on at every step
    eS = au.det_scalar('event', 0, 0)
    if g.raw(g.mul(eS, g.G)) != s_pay[KEY_MSG + 32:KEY_PAY]:
        sys.exit('the supervisor\'s ephemeral key is not derived from its seed')
    w = g.raw(g.mul(g.n - eS, Yp))[:SC]
    evk = hmac.new(w, b'des_split' + bytes([3]) + struct.pack('<II', ep, es), hashlib.sha256).digest()
    zs = kdf(au.seed, b'des_split zeros')

    # the frames of the session, one copy each
    msg = {}
    for x in frames:
        if (x['role'] == SUPERVISOR and x['epoch'] == es and x['peer'] == ep) or \
           (x['role'] == PLANT and x['epoch'] == ep and x['peer'] == es):
            msg.setdefault((x['type'], x['seq'], x['chunk']), x)

    # A recording over Wi-Fi misses frames: multicast is not acknowledged, and
    # the boards ask each other for the ones they lack, the recorder cannot.
    # What the recording lacks is reported apart, and the rest still checked.
    # The state never travels: the auditor computes it from the seed and the
    # events, so a lost frame costs the check of that frame only.
    def decisions(k, c, z):                     # None for a row with a cell that is not known
        rows = []
        for gi, (mask, cells) in enumerate(t['rows']):
            if any(c[q] is None for q in cells):
                rows.append(None)
                continue
            d = (g.O, g.O)
            for q in cells: d = au.addc(d, c[q])
            d = au.addc(d, au.enc(0, 'dz', k, gi, z))
            D = g.mul(g.n - kS, d[0]) if d[0] != g.O else g.O
            rows.append(struct.pack('<Q', mask) + au.raw(d) + g.raw(D))
        return rows

    # The new state of step k, event ev: the cells move. A state that ev leads
    # into gets the cell of the state it comes from (the sum, if several); the
    # cells of the states that ev does not leave go, in the order of the
    # states, to the states that ev leads nothing into, and if they run out,
    # those get enc(0, 'z0', k, j) under z_k, j = 0, 1, ...
    def move(k, ev, c, z):
        into = t['moves'][ev]
        left = set(s for srcs in into.values() for s in srcs)
        rest = [c[q] for q in range(NS) if q not in left]
        new, j = [], 0
        for q in range(NS):
            if q in into:
                cell = (g.O, g.O)
                for s in into[q]: cell = None if cell is None or c[s] is None else au.addc(cell, c[s])
                new.append(cell)
            elif rest:
                new.append(rest.pop(0))
            else:
                new.append(au.enc(0, 'z0', k, j, z))
                j += 1
        return new

    def record(h, k, evx, rows):                # chain_step: the event encrypted
        return sha(h + struct.pack('<IH', k, evx) + sha(b''.join(sha(r) for r in rows)))

    print('redoing every step', flush=True)
    h = sha(b'des_split record' + p_pay + s_pay + struct.pack('<II', ep, es))
    c = [au.enc(t['init'][q], 'init', 0, q) for q in range(NS)]
    # Up to the last step of the run, which the plant's FIN names: a step whose
    # frames were all lost is reported as such, not taken for the end.
    fin = [key[1] for key in msg if key[0] == T_FIN]
    seen = [key[1] for key in msg if key[0] in (T_STEP, T_DECS, T_SIGN)]
    last = max(fin + seen) if fin + seen else -1
    if not fin: print('no FIN in the recording: it may end before the run did', flush=True)
    k, steps_ok, steps_part = 0, 0, 0
    while k <= last:
        decs_rec = [msg[(T_DECS, k, gi)]['p'][:DECS_ITEM] if (T_DECS, k, gi) in msg else None
                    for gi in range(len(t['rows']))]
        sign = msg.get((T_SIGN, k, 0))
        signed = sign['p'][:32] if sign else None
        bad, miss = [], []
        if sign is None: miss.append('SIGN')
        elif not au.schnorr_ok(Xs, b'des_split signed' + struct.pack('<I', k) + signed, sign['p'][32:32 + SIG]):
            bad.append('the supervisor\'s signature is wrong')
            signed = None
        complete = None not in decs_rec
        ev = evx = NO_EVENT
        z, zs = zs, kdf(zs, b'des_split next')  # z_k, and z_{k+1} for the next step
        if k > 0:
            pad = struct.unpack('<H', kdf(evk, b'des_split event')[:2])[0]
            evk = kdf(evk, b'des_split next')
            step = msg.get((T_STEP, k, 0))
            evx = struct.unpack('<H', step['p'][:2])[0] if step else None
            if evx is None:
                miss.append('STEP')
                if h is not None and complete and signed is not None:   # the event the signature fits
                    fits = [e for e in range(E) if record(h, k, e ^ pad, decs_rec) == signed]
                    evx = fits[0] ^ pad if len(fits) == 1 else None
            ev = None if evx is None else evx ^ pad
            if ev is None or ev >= E:
                if ev is not None: bad.append(f'an unknown event {ev}')
                miss.append('the event, so the state from here on')
                c = [None] * NS
            else:
                c = move(k, ev, c, z)
        unknown = []
        for gi, row in enumerate(decisions(k, c, z)):
            if decs_rec[gi] is None: miss.append(f'decision row {gi}')
            elif row is None: unknown.append(str(gi))
            elif row != decs_rec[gi]: bad.append(f'decision row {gi}')
        if unknown: miss.append('a cell of decision rows ' + ', '.join(unknown))
        if h is not None and complete and evx is not None:
            h = record(h, k, evx, decs_rec)
            if signed is not None and signed != h: bad.append('the recorded frames differ from what the supervisor signed')
        else:                                   # the record cannot be redone: go on from the signed one
            if complete and evx is not None: miss.append('the record of an earlier step')
            h = signed
        whole = sign is None and all(x is None for x in decs_rec) and (k == 0 or (T_STEP, k, 0) not in msg)
        if whole: miss = ['every frame of the step']
        if bad: problems.append(f'step {k}: ' + ', '.join(bad) + ('' if complete else
                                ' (frames of this step are missing: the signature does not cover them)'))
        elif miss: steps_part += 1
        else: steps_ok += 1
        print(f'  step {k}: ' + (', '.join(bad) if bad else 'not checked' if whole else 'ok') +
              (f'; not in the recording: {", ".join(miss)}' if miss else ''), flush=True)
        k += 1
    print(f'steps checked: {k} (boot included): {steps_ok} entirely, {steps_part} except what the recording '
          f'lacks, {len(problems)} with a deviation')
    for p in problems: print('  DEVIATION ' + p)
    gaps = ([f'{steps_part} step{"s" if steps_part > 1 else ""} could be checked only in part, the recording '
             'lacks some of their frames']
            if steps_part else []) + ([] if fin else ['the recording has no FIN, so it may end before the run did'])
    if problems: verdict = 'the supervisor deviated'
    elif k <= 1: verdict = 'the recording holds no step of the run'
    elif gaps: verdict = 'no deviation in what was recorded; ' + '; '.join(gaps)
    else: verdict = 'the supervisor followed the protocol'
    print('verdict: ' + verdict)
    return 0 if not problems and k > 1 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('record')
    r.add_argument('run'); r.add_argument('--port', type=int, default=5078)
    r.add_argument('--group', default='239.192.7.1'); r.add_argument('--iface', default='0.0.0.0')
    c = sub.add_parser('check')
    c.add_argument('run'); c.add_argument('--header', required=True)
    c.add_argument('--seed', required=True); c.add_argument('--supervisor-pub', required=True)
    c.add_argument('--curve', type=int, default=256); c.add_argument('--mock', action='store_true')
    a = ap.parse_args()
    sys.exit(record(a) if a.cmd == 'record' else check(a))


if __name__ == '__main__':
    main()
