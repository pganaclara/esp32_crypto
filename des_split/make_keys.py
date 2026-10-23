"""Identity keys for des_split: one key pair per board.

    python make_keys.py [192|224|256] >> secrets.h

Prints the four #defines des_split.h reads from secrets.h: each board's
private key and public key (x || y, uncompressed), in hex, on the curve of
DES_CURVE (256 by default). A board compiles in only its own private key and
the other board's public key, so a copy of one board's flash does not let
anyone pass for the other board. Run it again when DES_CURVE changes.
No dependencies: the curve arithmetic is below, checked at every run.
"""
import secrets
import sys

CURVES = {  # NIST P-192, P-224, P-256 (FIPS 186-4, D.1.2): p, b, Gx, Gy, n; a = -3
    192: (0xfffffffffffffffffffffffffffffffeffffffffffffffff,
          0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
          0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
          0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811,
          0xffffffffffffffffffffffff99def836146bc9b1b4d22831),
    224: (0xffffffffffffffffffffffffffffffff000000000000000000000001,
          0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
          0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
          0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34,
          0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d),
    256: (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
          0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
          0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
          0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551),
}


def curve(bits):
    p, b, gx, gy, n = CURVES[bits]

    def add(P, Q):                      # affine; None is the point at infinity
        if P is None:
            return Q
        if Q is None:
            return P
        if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
            return None
        if P == Q:
            lam = (3 * P[0] * P[0] - 3) * pow(2 * P[1], -1, p) % p
        else:
            lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
        x = (lam * lam - P[0] - Q[0]) % p
        return x, (lam * (P[0] - x) - P[1]) % p

    def mul(k, P):
        R = None
        while k:
            if k & 1:
                R = add(R, P)
            P, k = add(P, P), k >> 1
        return R

    def on_curve(P):
        return (P[1] * P[1] - (P[0] ** 3 - 3 * P[0] + b)) % p == 0

    G = (gx, gy)
    assert on_curve(G) and mul(n, G) is None, "curve constants"
    return n, G, mul, on_curve


def main():
    bits = int(sys.argv[1]) if len(sys.argv) > 1 else 256
    n, G, mul, on_curve = curve(bits)
    size = bits // 8
    print(f"\n// Identity keys of des_split (NIST P-{bits}), made by make_keys.py.")
    print("// Each board compiles in only its own private key. Keep this file private.")
    for name in ("PLANT", "SUPERVISOR"):
        d = secrets.randbelow(n - 1) + 1
        Q = mul(d, G)
        assert on_curve(Q)
        print(f'#define {"DES_ID_" + name:<18} "{d:0{2 * size}x}"')
        print(f'#define {"DES_PUB_" + name:<18} "{Q[0]:0{2 * size}x}{Q[1]:0{2 * size}x}"')


if __name__ == "__main__":
    main()
