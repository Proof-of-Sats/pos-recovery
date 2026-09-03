#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pos-recover : outil de recuperation sure des satoshis Proof of Sats (Serie 1).

Un balayage classique detruit le satoshi rare des cartes dont le sat se trouve
en derniere position de la sortie de 546 sats. Les frais de minage sont preleves
a la fin de la sequence ordinale : le dernier satoshi part au mineur.

Cet outil construit une transaction qui preserve le sat quelle que soit sa
position, et refuse de signer si la construction ne respecte pas les invariants.

Aucune dependance externe. Bibliotheque standard Python 3.8+ uniquement.
Concu pour tourner sur une machine deconnectee.

Usage :
    python3 pos_recover.py selftest
    python3 pos_recover.py simulate
    python3 pos_recover.py fetch    --card TXID:VOUT --funding TXID:VOUT -o ctx.json   # en ligne
    python3 pos_recover.py build    --context ctx.json --dest bc1p... --feerate 5      # hors ligne
    python3 pos_recover.py verify   --tx tx.hex --context ctx.json                     # hors ligne
    python3 pos_recover.py broadcast --tx tx.hex                                       # en ligne
"""

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import sys
from getpass import getpass

CARD_VALUE = 546
SIGHASH_ALL = 1
SEQUENCE_FINAL = 0xFFFFFFFF
MAX_FEERATE = 1000.0

# ---------------------------------------------------------------------------
# RIPEMD-160 en Python pur.
# hashlib.new('ripemd160') echoue sur la plupart des builds OpenSSL 3.
# ---------------------------------------------------------------------------

_RL = (
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
    [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
    [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
    [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
)
_RR = (
    [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
    [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
    [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
    [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
    [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11],
)
_SL = (
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
    [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
    [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
    [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
)
_SR = (
    [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
    [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
    [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
    [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
    [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11],
)
_KL = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_KR = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def _rol(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _f(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & 0xFFFFFFFF & z)
    if j < 48:
        return (x | (~y & 0xFFFFFFFF)) ^ z
    if j < 64:
        return (x & z) | (y & (~z & 0xFFFFFFFF))
    return x ^ (y | (~z & 0xFFFFFFFF))


def ripemd160(msg):
    """RIPEMD-160 en Python pur. Retourne 20 octets."""
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    ml = len(msg)
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += (ml * 8).to_bytes(8, "little")

    for off in range(0, len(msg), 64):
        blk = msg[off:off + 64]
        X = [int.from_bytes(blk[i * 4:i * 4 + 4], "little") for i in range(16)]
        a, b, c, d, e = h
        A, B, C, D, E = h
        for j in range(80):
            rnd = j // 16
            t = _rol((a + _f(j, b, c, d) + X[_RL[rnd][j % 16]] + _KL[rnd]) & 0xFFFFFFFF,
                     _SL[rnd][j % 16])
            t = (t + e) & 0xFFFFFFFF
            a, e, d, c, b = e, d, _rol(c, 10), b, t
            t = _rol((A + _f(79 - j, B, C, D) + X[_RR[rnd][j % 16]] + _KR[rnd]) & 0xFFFFFFFF,
                     _SR[rnd][j % 16])
            t = (t + E) & 0xFFFFFFFF
            A, E, D, C, B = E, D, _rol(C, 10), B, t
        h = [(h[1] + c + D) & 0xFFFFFFFF,
             (h[2] + d + E) & 0xFFFFFFFF,
             (h[3] + e + A) & 0xFFFFFFFF,
             (h[4] + a + B) & 0xFFFFFFFF,
             (h[0] + b + C) & 0xFFFFFFFF]
    return b"".join(x.to_bytes(4, "little") for x in h)


def sha256(b):
    return hashlib.sha256(b).digest()


def dsha256(b):
    return sha256(sha256(b))


def hash160(b):
    return ripemd160(sha256(b))


# ---------------------------------------------------------------------------
# Reseaux
# ---------------------------------------------------------------------------

NETWORKS = {
    "mainnet": {"hrp": "bc", "wif": 0x80, "p2pkh": 0x00, "p2sh": 0x05,
                "api": "https://mempool.space/api", "ord": "https://ordinals.com"},
    "signet": {"hrp": "tb", "wif": 0xEF, "p2pkh": 0x6F, "p2sh": 0xC4,
               "api": "https://mempool.space/signet/api", "ord": None},
    "testnet4": {"hrp": "tb", "wif": 0xEF, "p2pkh": 0x6F, "p2sh": 0xC4,
                 "api": "https://mempool.space/testnet4/api", "ord": None},
}
_NET = NETWORKS["mainnet"]


def set_network(name):
    global _NET
    if name not in NETWORKS:
        raise ValueError("reseau inconnu: %r" % name)
    _NET = NETWORKS[name]


def net_hrp():
    return _NET["hrp"]


# ---------------------------------------------------------------------------
# Base58Check
# ---------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data):
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    for byte in data:
        if byte != 0:
            break
        out = "1" + out
    return out


def b58decode(s):
    n = 0
    for ch in s:
        idx = _B58.find(ch)
        if idx < 0:
            raise ValueError("caractere base58 invalide: %r" % ch)
        n = n * 58 + idx
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in s:
        if ch != "1":
            break
        pad += 1
    return b"\x00" * pad + body


def b58check_decode(s):
    raw = b58decode(s)
    if len(raw) < 5:
        raise ValueError("chaine base58check trop courte")
    payload, chk = raw[:-4], raw[-4:]
    if dsha256(payload)[:4] != chk:
        raise ValueError("checksum base58 invalide")
    return payload


def b58check_encode(payload):
    return b58encode(payload + dsha256(payload)[:4])


# ---------------------------------------------------------------------------
# Bech32 / Bech32m (BIP-173, BIP-350)
# ---------------------------------------------------------------------------

_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp, data, const):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_decode(addr):
    if any(ord(c) < 33 or ord(c) > 126 for c in addr):
        raise ValueError("caractere hors plage dans l'adresse")
    if addr.lower() != addr and addr.upper() != addr:
        raise ValueError("casse mixte dans l'adresse bech32")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        raise ValueError("structure bech32 invalide")
    hrp, data_part = addr[:pos], addr[pos + 1:]
    data = []
    for c in data_part:
        idx = _BECH32.find(c)
        if idx < 0:
            raise ValueError("caractere bech32 invalide: %r" % c)
        data.append(idx)
    values = _bech32_hrp_expand(hrp) + data
    if _bech32_polymod(values) == 1:
        return hrp, data[:-6], "bech32"
    if _bech32_polymod(values) == _BECH32M_CONST:
        return hrp, data[:-6], "bech32m"
    raise ValueError("checksum bech32/bech32m invalide")


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("valeur hors plage")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("padding invalide")
    return ret


def segwit_decode(addr, hrp=None):
    """Retourne (witness_version, witness_program)."""
    hrp = hrp or net_hrp()
    got_hrp, data, spec = _bech32_decode(addr)
    if got_hrp != hrp:
        raise ValueError("prefixe reseau inattendu: %r (attendu %r)" % (got_hrp, hrp))
    if not data:
        raise ValueError("donnees bech32 vides")
    ver = data[0]
    prog = bytes(_convertbits(data[1:], 5, 8, False))
    if ver == 0 and spec != "bech32":
        raise ValueError("witness v0 doit utiliser bech32, pas bech32m")
    if ver != 0 and spec != "bech32m":
        raise ValueError("witness v1+ doit utiliser bech32m")
    if ver == 0 and len(prog) not in (20, 32):
        raise ValueError("longueur de programme witness v0 invalide")
    if not (2 <= len(prog) <= 40):
        raise ValueError("longueur de programme witness invalide")
    if ver > 16:
        raise ValueError("version witness invalide")
    return ver, prog


def segwit_encode(ver, prog, hrp=None):
    hrp = hrp or net_hrp()
    spec = "bech32" if ver == 0 else "bech32m"
    const = 1 if ver == 0 else _BECH32M_CONST
    data = [ver] + _convertbits(prog, 8, 5)
    chk = _bech32_create_checksum(hrp, data, const)
    return hrp + "1" + "".join(_BECH32[d] for d in data + chk)


# ---------------------------------------------------------------------------
# secp256k1 (coordonnees jacobiennes)
# ---------------------------------------------------------------------------

_P = 2 ** 256 - 2 ** 32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _jac_double(pt):
    x, y, z = pt
    if y == 0 or z == 0:
        return (0, 0, 0)
    ysq = (y * y) % _P
    s = (4 * x * ysq) % _P
    m = (3 * x * x) % _P
    nx = (m * m - 2 * s) % _P
    ny = (m * (s - nx) - 8 * ysq * ysq) % _P
    nz = (2 * y * z) % _P
    return (nx, ny, nz)


def _jac_add(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1z1 = (z1 * z1) % _P
    z2z2 = (z2 * z2) % _P
    u1 = (x1 * z2z2) % _P
    u2 = (x2 * z1z1) % _P
    s1 = (y1 * z2 * z2z2) % _P
    s2 = (y2 * z1 * z1z1) % _P
    if u1 == u2:
        if s1 != s2:
            return (0, 0, 0)
        return _jac_double(p)
    h = (u2 - u1) % _P
    r = (s2 - s1) % _P
    h2 = (h * h) % _P
    h3 = (h2 * h) % _P
    u1h2 = (u1 * h2) % _P
    nx = (r * r - h3 - 2 * u1h2) % _P
    ny = (r * (u1h2 - nx) - s1 * h3) % _P
    nz = (h * z1 * z2) % _P
    return (nx, ny, nz)


def _jac_mul(pt, k):
    k %= _N
    if k == 0 or pt[2] == 0:
        return (0, 0, 0)
    result = (0, 0, 0)
    addend = pt
    while k:
        if k & 1:
            result = _jac_add(result, addend)
        addend = _jac_double(addend)
        k >>= 1
    return result


def _to_affine(pt):
    x, y, z = pt
    if z == 0:
        raise ValueError("point a l'infini")
    zinv = pow(z, _P - 2, _P)
    zinv2 = (zinv * zinv) % _P
    return ((x * zinv2) % _P, (y * zinv2 * zinv) % _P)


def privkey_to_point(k):
    if not (1 <= k < _N):
        raise ValueError("cle privee hors plage")
    return _to_affine(_jac_mul((_GX, _GY, 1), k))


def compress_point(pt):
    x, y = pt
    return (b"\x03" if y & 1 else b"\x02") + x.to_bytes(32, "big")


def decompress_point(pub):
    if len(pub) != 33 or pub[0] not in (2, 3):
        raise ValueError("cle publique compressee attendue")
    x = int.from_bytes(pub[1:], "big")
    ysq = (pow(x, 3, _P) + 7) % _P
    y = pow(ysq, (_P + 1) // 4, _P)
    if (y * y) % _P != ysq:
        raise ValueError("point hors courbe")
    if (y & 1) != (pub[0] & 1):
        y = _P - y
    return (x, y)


# ---------------------------------------------------------------------------
# ECDSA : nonce deterministe RFC-6979, low-S (BIP-62), encodage DER
# ---------------------------------------------------------------------------

def _rfc6979_k(priv, msg32):
    v = b"\x01" * 32
    k = b"\x00" * 32
    x = priv.to_bytes(32, "big")
    k = hmac.new(k, v + b"\x00" + x + msg32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + msg32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < _N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def ecdsa_sign(priv, msg32):
    z = int.from_bytes(msg32, "big")
    counter = 0
    while True:
        k = _rfc6979_k(priv, msg32 if counter == 0 else sha256(msg32 + bytes([counter])))
        try:
            px, _ = privkey_to_point(k)
        except ValueError:
            counter += 1
            continue
        r = px % _N
        if r == 0:
            counter += 1
            continue
        s = (pow(k, _N - 2, _N) * (z + r * priv)) % _N
        if s == 0:
            counter += 1
            continue
        if s > _N // 2:
            s = _N - s
        return r, s


def ecdsa_verify(pub, msg32, r, s):
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    z = int.from_bytes(msg32, "big")
    sinv = pow(s, _N - 2, _N)
    u1 = (z * sinv) % _N
    u2 = (r * sinv) % _N
    pt = _jac_add(_jac_mul((_GX, _GY, 1), u1), _jac_mul(decompress_point(pub) + (1,), u2))
    if pt[2] == 0:
        return False
    x, _ = _to_affine(pt)
    return (x % _N) == r


def _der_int(v):
    b = v.to_bytes((v.bit_length() + 8) // 8, "big") or b"\x00"
    return b"\x02" + bytes([len(b)]) + b


def der_encode(r, s):
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def der_decode(sig):
    if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2:
        raise ValueError("enveloppe DER invalide")
    if sig[2] != 0x02:
        raise ValueError("marqueur DER de r invalide")
    rlen = sig[3]
    r = int.from_bytes(sig[4:4 + rlen], "big")
    off = 4 + rlen
    if sig[off] != 0x02:
        raise ValueError("marqueur DER de s invalide")
    slen = sig[off + 1]
    s = int.from_bytes(sig[off + 2:off + 2 + slen], "big")
    return r, s


# ---------------------------------------------------------------------------
# WIF
# ---------------------------------------------------------------------------

def wif_decode(wif):
    """Retourne (privkey_int, compressed_bool). Mainnet uniquement."""
    payload = b58check_decode(wif.strip())
    if payload[0] != _NET["wif"]:
        raise ValueError("octet de version WIF 0x%02x inattendu, 0x%02x attendu pour ce reseau. "
                         "Verifiez l'option --network."
                         % (payload[0], _NET["wif"]))
    body = payload[1:]
    if len(body) == 33:
        if body[32] != 0x01:
            raise ValueError("suffixe de compression WIF invalide")
        return int.from_bytes(body[:32], "big"), True
    if len(body) == 32:
        return int.from_bytes(body, "big"), False
    raise ValueError("longueur de charge utile WIF invalide")


def wif_encode(priv, compressed=True):
    body = bytes([_NET["wif"]]) + priv.to_bytes(32, "big") + (b"\x01" if compressed else b"")
    return b58check_encode(body)


def p2wpkh_address(pubkey, hrp=None):
    return segwit_encode(0, hash160(pubkey), hrp or net_hrp())


# ---------------------------------------------------------------------------
# scriptPubKey <-> adresse, seuils de poussiere
# ---------------------------------------------------------------------------

def address_to_spk(addr):
    addr = addr.strip()
    if addr.lower().startswith(net_hrp() + "1"):
        ver, prog = segwit_decode(addr)
        if ver == 0:
            return bytes([0x00, len(prog)]) + prog
        return bytes([0x50 + ver, len(prog)]) + prog
    payload = b58check_decode(addr)
    ver, h = payload[0], payload[1:]
    if len(h) != 20:
        raise ValueError("longueur de hash base58 invalide")
    if ver == _NET["p2pkh"]:
        return b"\x76\xa9\x14" + h + b"\x88\xac"
    if ver == _NET["p2sh"]:
        return b"\xa9\x14" + h + b"\x87"
    raise ValueError("octet de version base58 non supporte: 0x%02x" % ver)


def spk_kind(spk):
    if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
        return "P2WPKH"
    if len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
        return "P2WSH"
    if len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
        return "P2TR"
    if len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac":
        return "P2PKH"
    if len(spk) == 23 and spk[:2] == b"\xa9\x14" and spk[22] == 0x87:
        return "P2SH"
    return "INCONNU"


DUST = {"P2PKH": 546, "P2SH": 540, "P2WPKH": 294, "P2WSH": 330, "P2TR": 330}


def dust_limit(spk):
    return DUST.get(spk_kind(spk), 546)


# ---------------------------------------------------------------------------
# Serialisation de transaction
# ---------------------------------------------------------------------------

def varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def pushdata(data):
    return varint(len(data)) + data


class TxIn(object):
    def __init__(self, txid, vout, value, spk, sequence=SEQUENCE_FINAL):
        self.txid = txid              # hex, big-endian d'affichage
        self.vout = vout
        self.value = value
        self.spk = spk                # bytes
        self.sequence = sequence
        self.script_sig = b""
        self.redeem_script = None
        self.witness = []             # liste de bytes

    def outpoint(self):
        return bytes.fromhex(self.txid)[::-1] + self.vout.to_bytes(4, "little")


class TxOut(object):
    def __init__(self, value, spk):
        self.value = value
        self.spk = spk

    def serialize(self):
        return self.value.to_bytes(8, "little") + pushdata(self.spk)


class Tx(object):
    def __init__(self, vin=None, vout=None, version=2, locktime=0):
        self.vin = vin or []
        self.vout = vout or []
        self.version = version
        self.locktime = locktime

    def serialize(self, witness=True):
        has_wit = witness and any(i.witness for i in self.vin)
        out = self.version.to_bytes(4, "little")
        if has_wit:
            out += b"\x00\x01"
        out += varint(len(self.vin))
        for i in self.vin:
            out += (i.outpoint() + pushdata(i.script_sig)
                    + i.sequence.to_bytes(4, "little"))
        out += varint(len(self.vout))
        for o in self.vout:
            out += o.serialize()
        if has_wit:
            for i in self.vin:
                out += varint(len(i.witness))
                for item in i.witness:
                    out += pushdata(item)
        out += self.locktime.to_bytes(4, "little")
        return out

    def txid(self):
        return dsha256(self.serialize(witness=False))[::-1].hex()

    def weight(self):
        base = len(self.serialize(witness=False))
        total = len(self.serialize(witness=True))
        return base * 3 + total

    def vsize(self):
        return (self.weight() + 3) // 4

    def sighash_p2wpkh(self, index):
        """BIP-143, SIGHASH_ALL, entree P2WPKH."""
        i = self.vin[index]
        signing_spk = i.redeem_script or i.spk
        if spk_kind(signing_spk) != "P2WPKH":
            raise ValueError("entree %d n'est pas P2WPKH ou P2SH-P2WPKH" % index)
        hash_prevouts = dsha256(b"".join(x.outpoint() for x in self.vin))
        hash_sequence = dsha256(b"".join(x.sequence.to_bytes(4, "little") for x in self.vin))
        hash_outputs = dsha256(b"".join(o.serialize() for o in self.vout))
        script_code = b"\x19\x76\xa9\x14" + signing_spk[2:] + b"\x88\xac"
        pre = (self.version.to_bytes(4, "little")
               + hash_prevouts + hash_sequence
               + i.outpoint()
               + script_code
               + i.value.to_bytes(8, "little")
               + i.sequence.to_bytes(4, "little")
               + hash_outputs
               + self.locktime.to_bytes(4, "little")
               + SIGHASH_ALL.to_bytes(4, "little"))
        return dsha256(pre)


def parse_tx(raw):
    """Analyseur minimal, suffisant pour re-verifier notre propre transaction."""
    pos = [0]

    def take(n):
        b = raw[pos[0]:pos[0] + n]
        if len(b) != n:
            raise ValueError("transaction tronquee")
        pos[0] += n
        return b

    def rd_varint():
        v = take(1)[0]
        if v < 0xFD:
            return v
        if v == 0xFD:
            n = int.from_bytes(take(2), "little")
            if n < 0xFD:
                raise ValueError("varint non canonique")
            return n
        if v == 0xFE:
            n = int.from_bytes(take(4), "little")
            if n <= 0xFFFF:
                raise ValueError("varint non canonique")
            return n
        n = int.from_bytes(take(8), "little")
        if n <= 0xFFFFFFFF:
            raise ValueError("varint non canonique")
        return n

    version = int.from_bytes(take(4), "little")
    segwit = False
    n_in = rd_varint()
    if n_in == 0:
        flag = take(1)[0]
        if flag != 1:
            raise ValueError("flag segwit inattendu")
        segwit = True
        n_in = rd_varint()
    vin = []
    for _ in range(n_in):
        prev = take(32)[::-1].hex()
        idx = int.from_bytes(take(4), "little")
        slen = rd_varint()
        script_sig = take(slen)
        seq = int.from_bytes(take(4), "little")
        vin.append({"txid": prev, "vout": idx, "scriptSig": script_sig,
                    "sequence": seq, "witness": []})
    n_out = rd_varint()
    vout = []
    for _ in range(n_out):
        val = int.from_bytes(take(8), "little")
        slen = rd_varint()
        vout.append({"value": val, "spk": take(slen)})
    if segwit:
        for i in vin:
            cnt = rd_varint()
            for _ in range(cnt):
                ln = rd_varint()
                i["witness"].append(take(ln))
    locktime = int.from_bytes(take(4), "little")
    if pos[0] != len(raw):
        raise ValueError("octets residuels apres la transaction")
    return {"version": version, "vin": vin, "vout": vout,
            "locktime": locktime, "segwit": segwit}


# ---------------------------------------------------------------------------
# Modele d'attribution ordinale
# ---------------------------------------------------------------------------

def allocate(input_ranges, output_values):
    """
    Applique la regle ordinale.

    input_ranges : liste (par entree, dans l'ordre) de listes de plages
                   [start, end) demi-ouvertes.
    output_values : liste de valeurs de sortie, dans l'ordre.

    Retourne (per_output, fee_ranges) ou per_output[i] est la liste des plages
    attribuees a la sortie i. Les frais recoivent la fin de la sequence.
    """
    flat = []
    for ranges in input_ranges:
        for start, end in ranges:
            if end <= start:
                raise ValueError("plage de sats vide ou inversee")
            flat.append([start, end])

    per_output = []
    cursor = 0
    for value in output_values:
        remaining = value
        assigned = []
        while remaining > 0:
            if cursor >= len(flat):
                raise ValueError("sats insuffisants en entree pour couvrir les sorties")
            start, end = flat[cursor]
            size = end - start
            if size <= remaining:
                assigned.append((start, end))
                remaining -= size
                cursor += 1
            else:
                assigned.append((start, start + remaining))
                flat[cursor] = [start + remaining, end]
                remaining = 0
        per_output.append(assigned)

    fee_ranges = [tuple(r) for r in flat[cursor:]]
    return per_output, fee_ranges


def locate_sat(sat, per_output, fee_ranges):
    """Retourne ('output', index, offset) ou ('fee', None, None) ou (None, None, None)."""
    for oi, ranges in enumerate(per_output):
        offset = 0
        for start, end in ranges:
            if start <= sat < end:
                return "output", oi, offset + (sat - start)
            offset += end - start
    for start, end in fee_ranges:
        if start <= sat < end:
            return "fee", None, None
    return None, None, None


def normalize_ranges(raw_ranges):
    """Accepte [[start, end), ...] ou [[start, size], ...] via detection heuristique."""
    out = []
    for item in raw_ranges:
        if isinstance(item, dict):
            start = int(item["start"])
            if "end" in item:
                end = int(item["end"])
            else:
                end = start + int(item.get("size", 1))
        else:
            start, second = int(item[0]), int(item[1])
            end = second if second > start else start + second
        out.append((start, end))
    return out


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------

def check_invariants(tx, card_txid, card_vout, dest_spk, card_value=None):
    """Retourne la liste des violations. Liste vide = construction sure."""
    fails = []
    if card_value is None:
        card_value = tx.vin[0].value if tx.vin else 0

    if len(tx.vin) != 2:
        fails.append("STRUCTURE : exactement deux entrees requises (%d trouvees)" % len(tx.vin))
    if len(tx.vout) != 2:
        fails.append("STRUCTURE : exactement deux sorties requises (%d trouvees)" % len(tx.vout))
    if not tx.vin:
        return fails + ["aucune entree"]

    # Invariant 1 : l'UTXO de la carte est l'entree d'index 0.
    i0 = tx.vin[0]
    if i0.txid.lower() != card_txid.lower() or i0.vout != card_vout:
        fails.append("INV1 : l'entree 0 n'est pas l'UTXO de la carte "
                     "(trouve %s:%d, attendu %s:%d)" % (i0.txid, i0.vout, card_txid, card_vout))
    if i0.value != card_value:
        fails.append("INV1 : l'entree 0 vaut %d sats au lieu de %d" % (i0.value, card_value))
    for n, i in enumerate(tx.vin[1:], start=1):
        if i.txid.lower() == card_txid.lower() and i.vout == card_vout:
            fails.append("INV1 : l'UTXO de la carte apparait aussi a l'entree %d" % n)

    # Invariant 2 : la sortie 0 reprend exactement la valeur de l'UTXO protege.
    if len(tx.vout) < 2:
        fails.append("INV2 : il faut au moins deux sorties (destination + change)")
    else:
        if tx.vout[0].value != card_value:
            fails.append("INV2 : la sortie 0 vaut %d sats au lieu de %d exactement"
                         % (tx.vout[0].value, card_value))
        if tx.vout[0].spk != dest_spk:
            fails.append("INV2 : la sortie 0 ne paie pas l'adresse de destination attendue")

    # Invariant 3 : les frais sont entierement supportes par le financement.
    total_in = sum(i.value for i in tx.vin)
    total_out = sum(o.value for o in tx.vout)
    fee = total_in - total_out
    if fee < 0:
        fails.append("INV3 : sorties superieures aux entrees (%d > %d)" % (total_out, total_in))
    elif fee == 0:
        fails.append("INV3 : frais nuls, la transaction ne sera pas relayee")
    if len(tx.vin) < 2:
        fails.append("INV3 : entree de financement absente, les frais mordraient sur la carte")
    if len(tx.vout) >= 1 and tx.vout[0].value != tx.vin[0].value:
        fails.append("INV3 : sortie 0 (%d) differente de l'entree 0 (%d), "
                     "une partie des frais serait prelevee sur la carte"
                     % (tx.vout[0].value, tx.vin[0].value))

    # Invariant 4 : pas de reordonnancement lexicographique (BIP-69).
    outpoints = [i.outpoint() for i in tx.vin]
    if len(outpoints) > 1 and outpoints == sorted(outpoints) and outpoints != [outpoints[0]]:
        # Coincidence possible et sans danger, mais on le signale.
        pass
    bip69_out = sorted([(o.value, o.spk) for o in tx.vout])
    if len(tx.vout) > 1 and [(o.value, o.spk) for o in tx.vout] != bip69_out:
        pass  # ordre non lexicographique attendu, rien a signaler

    # Poussiere
    for n, o in enumerate(tx.vout):
        lim = dust_limit(o.spk)
        if o.value < lim:
            fails.append("POUSSIERE : la sortie %d (%d sats) est sous le seuil %s de %d sats"
                         % (n, o.value, spk_kind(o.spk), lim))
        if spk_kind(o.spk) == "INCONNU":
            fails.append("La sortie %d a un scriptPubKey de type inconnu" % n)

    return fails


# ---------------------------------------------------------------------------
# Reseau (optionnel, en ligne uniquement)
# ---------------------------------------------------------------------------



def _http_get(url, timeout=20):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "pos-recover/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _http_post(url, body, timeout=30):
    import urllib.request
    req = urllib.request.Request(url, data=body.encode(), method="POST",
                                headers={"User-Agent": "pos-recover/1.0",
                                         "Content-Type": "text/plain"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def fetch_utxo(api, txid, vout):
    tx = json.loads(_http_get("%s/tx/%s" % (api, txid)))
    outs = tx.get("vout", [])
    if vout >= len(outs):
        raise ValueError("vout %d inexistant sur %s" % (vout, txid))
    o = outs[vout]
    spent = json.loads(_http_get("%s/tx/%s/outspend/%d" % (api, txid, vout)))
    status = tx.get("status", {})
    return {
        "txid": txid,
        "vout": vout,
        "value": int(o["value"]),
        "scriptpubkey": o["scriptpubkey"],
        "address": o.get("scriptpubkey_address"),
        "confirmed": bool(status.get("confirmed")),
        "block_height": status.get("block_height"),
        "spent": bool(spent.get("spent")),
    }


def fetch_sat_ranges(ord_base, txid, vout):
    """Best-effort. Necessite une instance ord avec --index-sats."""
    raw = _http_get("%s/r/output/%s:%d" % (ord_base, txid, vout))
    data = json.loads(raw)
    ranges = data.get("sat_ranges")
    if not ranges:
        raise ValueError("l'indexeur n'a pas renvoye de sat_ranges "
                         "(instance sans --index-sats ?)")
    return normalize_ranges(ranges)


# ---------------------------------------------------------------------------
# Commandes
# ---------------------------------------------------------------------------

def parse_outpoint(s):
    if ":" not in s:
        raise ValueError("format attendu TXID:VOUT, recu %r" % s)
    txid, vout = s.rsplit(":", 1)
    txid = txid.strip().lower()
    if len(txid) != 64 or any(c not in "0123456789abcdef" for c in txid):
        raise ValueError("txid invalide: %r" % txid)
    return txid, int(vout)


def cmd_fetch(args):
    card_txid, card_vout = parse_outpoint(args.card)
    fund_txid, fund_vout = parse_outpoint(args.funding)

    card = fetch_utxo(args.api, card_txid, card_vout)
    fund = fetch_utxo(args.api, fund_txid, fund_vout)

    if not args.no_ord:
        try:
            card["sat_ranges"] = [[a, b] for a, b in fetch_sat_ranges(args.ord, card_txid, card_vout)]
        except Exception as e:
            print("Avertissement : plages de sats non recuperees (%s)" % e, file=sys.stderr)
            print("La construction reste sure sans cette donnee, "
                  "mais la position du sat ne pourra pas etre predite.", file=sys.stderr)

    ctx = {"network": "mainnet", "card": card, "funding": fund}
    if args.sat is not None:
        ctx["card"]["target_sat"] = args.sat

    with open(args.output, "w") as f:
        json.dump(ctx, f, indent=2)
    os.chmod(args.output, 0o600)
    print("Contexte ecrit dans %s" % args.output)
    print("Transferez ce fichier sur la machine hors ligne, puis lancez `build`.")


def load_context(path):
    with open(path) as f:
        ctx = json.load(f)
    for key in ("card", "funding"):
        if key not in ctx:
            raise ValueError("contexte incomplet : cle %r manquante" % key)
        for sub in ("txid", "vout", "value", "scriptpubkey"):
            if sub not in ctx[key]:
                raise ValueError("contexte incomplet : %s.%s manquant" % (key, sub))
    return ctx


def _read_wif(label, env):
    val = os.environ.get(env)
    if val:
        print("(%s lu depuis %s)" % (label, env))
        return val.strip()
    if not sys.stdin.isatty():
        raise SystemExit("Erreur : pas de terminal pour la saisie de %s. "
                         "Definissez %s si vous automatisez des tests." % (label, env))
    return getpass("%s : " % label).strip()


def _fmt_sat(n):
    return "{:,}".format(n).replace(",", " ")


class Refusal(Exception):
    """Levee des qu'une condition de surete n'est pas reunie. Jamais rattrapee
    pour continuer : elle arrete la construction."""


def plan_recovery(ctx, dest, feerate=5.0, fee=None, change_addr=None):
    """Valide le contexte et construit la transaction NON SIGNEE.

    Aucune cle privee n'intervient a cette etape. L'appelant peut donc afficher
    le plan complet a l'utilisateur avant de lui demander d'ouvrir le scelle.
    Leve Refusal si quoi que ce soit ne va pas.
    """
    card, fund = ctx["card"], ctx["funding"]
    card_spk = bytes.fromhex(card["scriptpubkey"])
    fund_spk = bytes.fromhex(fund["scriptpubkey"])

    try:
        card_value = int(card["value"])
    except (TypeError, ValueError):
        raise Refusal("Valeur de l'UTXO de carte illisible.")
    if card_value <= 0:
        raise Refusal("La valeur de l'UTXO de carte doit etre strictement positive.")
    if card.get("spent"):
        raise Refusal("L'UTXO de la carte est deja depense.")
    if fund.get("spent"):
        raise Refusal("L'UTXO de financement est deja depense.")
    if spk_kind(card_spk) != "P2WPKH":
        raise Refusal("L'UTXO de la carte est de type %s. Cet outil ne signe que du P2WPKH."
                      % spk_kind(card_spk))
    if spk_kind(fund_spk) not in ("P2WPKH", "P2SH"):
        raise Refusal("L'UTXO de financement est de type %s. Xverse doit fournir du "
                      "P2WPKH ou P2SH-P2WPKH." % spk_kind(fund_spk))
    if (fund["txid"].lower(), fund["vout"]) == (card["txid"].lower(), card["vout"]):
        raise Refusal("Carte et financement designent le meme UTXO.")

    try:
        dest_spk = address_to_spk(dest)
    except ValueError as e:
        raise Refusal("Adresse de destination invalide : %s" % e)
    if dest_spk == card_spk:
        raise Refusal("La destination est l'adresse de la carte elle-meme.")
    if dest_spk == fund_spk:
        raise Refusal(
            "La destination est l'adresse de financement elle-meme. Le sat rejoindrait "
            "un portefeuille qui vient de depenser depuis cette adresse ; un balayage "
            "ulterieur de ce portefeuille pourrait consolider les deux et detruire le sat. "
            "Utilisez une adresse de destination distincte.")
    if fee is None:
        try:
            feerate = float(feerate)
        except (TypeError, ValueError):
            raise Refusal("Taux de frais illisible.")
        if not math.isfinite(feerate) or feerate <= 0 or feerate > MAX_FEERATE:
            raise Refusal("Taux de frais hors limites : valeur finie entre 0 et %.0f sat/vB requise."
                          % MAX_FEERATE)

    change_addr = change_addr or fund.get("address") or spk_to_address(fund_spk)
    change_spk = address_to_spk(change_addr)
    if change_spk == dest_spk:
        raise Refusal(
            "Le change et le sat iraient a la meme adresse. Utilisez deux adresses "
            "distinctes.\nSinon les deux sorties cohabitent a la meme adresse, et tout "
            "portefeuille qui depense depuis cette adresse peut les consolider, "
            "ce qui detruirait le sat.")

    def make_tx(change_value):
        vin = [TxIn(card["txid"], card["vout"], card_value, card_spk),
               TxIn(fund["txid"], fund["vout"], fund["value"], fund_spk)]
        return Tx(vin, [TxOut(card_value, dest_spk), TxOut(change_value, change_spk)])

    probe = make_tx(max(fund["value"] - 1, 1))
    if spk_kind(fund_spk) == "P2SH":
        pubhex = fund.get("public_key")
        if not pubhex:
            raise Refusal("Cle publique Xverse requise pour un financement P2SH-P2WPKH.")
        try:
            redeem = b"\x00\x14" + hash160(bytes.fromhex(pubhex))
        except ValueError:
            raise Refusal("Cle publique Xverse illisible.")
        if (fund_spk[:2] != b"\xa9\x14" or fund_spk[-1:] != b"\x87"
                or fund_spk[2:-1] != hash160(redeem)):
            raise Refusal("La cle publique Xverse ne correspond pas a l'adresse de paiement.")
        probe.vin[1].script_sig = pushdata(redeem)
        probe.vin[1].redeem_script = redeem
    for i in probe.vin:
        i.witness = [b"\x00" * 72, b"\x00" * 33]
    vsize = probe.vsize()
    fee_sats = int(fee) if fee is not None else -(-int(vsize * feerate * 1000) // 1000)
    change_value = int(fund["value"]) - fee_sats

    if change_value < dust_limit(change_spk):
        raise Refusal(
            "Apres %d sats de frais, le change vaudrait %d sats, sous le seuil de "
            "poussiere (%d). Financez avec un UTXO d'au moins %d sats."
            % (fee_sats, change_value, dust_limit(change_spk),
               fee_sats + dust_limit(change_spk)))

    tx = make_tx(change_value)

    fails = check_invariants(tx, card["txid"], card["vout"], dest_spk, card_value)
    if fails:
        raise Refusal("Invariants non respectes :\n  - " + "\n  - ".join(fails))

    prediction, target = None, None
    ranges = card.get("sat_ranges")
    if ranges:
        card_ranges = normalize_ranges(ranges)
        total = sum(e - s for s, e in card_ranges)
        if total != card_value:
            raise Refusal(
                "Les plages de sats du contexte totalisent %d sats au lieu de la valeur "
                "de l'UTXO (%d).\n"
                "Elles s'ecrivent en intervalles demi-ouverts [debut, fin), comme l'API ord : "
                "une plage de K sats commencant a N se note [N, N+K].\n"
                "Corrigez le contexte, ou retirez sat_ranges : la construction reste sure "
                "sans cette donnee, seule la prediction de position est perdue."
                % (total, card_value))
        target = int(card.get("target_sat", card_ranges[0][0]))
        per_out, fee_ranges = allocate([card_ranges, [(0, fund["value"])]],
                                       [o.value for o in tx.vout])
        where, oi, off = locate_sat(target, per_out, fee_ranges)
        if where == "fee":
            raise Refusal("La prediction ordinale place le sat %d dans les frais." % target)
        if where == "output" and oi != 0:
            raise Refusal("La prediction ordinale place le sat %d sur la sortie %d "
                          "au lieu de la sortie 0." % (target, oi))
        if where is None:
            raise Refusal("Le sat %d est introuvable dans les plages du contexte. "
                          "Verifiez target_sat." % target)
        prediction = {"output": oi, "offset": off}

    return {
        "tx": tx, "vsize": vsize, "fee": fee_sats,
        "card_value": card_value,
        "card_spk": card_spk, "fund_spk": fund_spk,
        "dest_spk": dest_spk, "change_spk": change_spk,
        "card_address": spk_to_address(card_spk),
        "fund_address": spk_to_address(fund_spk),
        "dest_address": dest, "change_address": change_addr,
        "change_value": change_value,
        "target_sat": target, "prediction": prediction,
        "feerate_effective": fee_sats / float(vsize),
        "card_outpoint": "%s:%d" % (card["txid"], card["vout"]),
        "fund_outpoint": "%s:%d" % (fund["txid"], fund["vout"]),
    }


# ---------------------------------------------------------------------------
# PSBT BIP-174 (v0) -- sous-ensemble strict utilise par Xverse
# ---------------------------------------------------------------------------

PSBT_MAGIC = b"psbt\xff"


def _read_compact(data, pos):
    if pos >= len(data):
        raise ValueError("donnees tronquees")
    first = data[pos]
    pos += 1
    if first < 0xfd:
        return first, pos
    size = {0xfd: 2, 0xfe: 4, 0xff: 8}[first]
    if pos + size > len(data):
        raise ValueError("entier compact tronque")
    value = int.from_bytes(data[pos:pos + size], "little")
    minimum = {0xfd: 0xfd, 0xfe: 0x10000, 0xff: 0x100000000}[first]
    if value < minimum:
        raise ValueError("entier compact non canonique")
    return value, pos + size


def _parse_map(data, pos):
    result, seen = [], set()
    while True:
        klen, pos = _read_compact(data, pos)
        if klen == 0:
            return result, pos
        if pos + klen > len(data):
            raise ValueError("cle PSBT tronquee")
        key = data[pos:pos + klen]
        pos += klen
        vlen, pos = _read_compact(data, pos)
        if pos + vlen > len(data):
            raise ValueError("valeur PSBT tronquee")
        value = data[pos:pos + vlen]
        pos += vlen
        if key in seen:
            raise ValueError("cle PSBT dupliquee")
        seen.add(key)
        result.append((key, value))


def _serialize_map(items):
    out = b""
    for key, value in items:
        out += varint(len(key)) + key + varint(len(value)) + value
    return out + b"\x00"


def parse_psbt(encoded):
    """Parse une PSBT base64 ou bytes et rejette encodages non canoniques/inattendus."""
    if isinstance(encoded, str):
        try:
            data = base64.b64decode(encoded, validate=True)
        except Exception:
            raise ValueError("PSBT base64 invalide")
    else:
        data = bytes(encoded)
    if not data.startswith(PSBT_MAGIC):
        raise ValueError("magie PSBT absente")
    pos = len(PSBT_MAGIC)
    global_map, pos = _parse_map(data, pos)
    unsigned = [v for k, v in global_map if k == b"\x00"]
    if len(global_map) != 1 or len(unsigned) != 1:
        raise ValueError("PSBT globale inattendue (transaction non signee seule requise)")
    parsed_tx = parse_tx(unsigned[0])
    if parsed_tx["segwit"] or any(i["scriptSig"] or i["witness"] for i in parsed_tx["vin"]):
        raise ValueError("transaction globale PSBT doit etre non signee")
    inputs = []
    for _ in parsed_tx["vin"]:
        m, pos = _parse_map(data, pos)
        inputs.append(m)
    outputs = []
    for _ in parsed_tx["vout"]:
        m, pos = _parse_map(data, pos)
        outputs.append(m)
    if pos != len(data):
        raise ValueError("octets residuels apres la PSBT")
    return {"raw": data, "unsigned": unsigned[0], "tx": parsed_tx,
            "global": global_map, "inputs": inputs, "outputs": outputs}


def serialize_psbt(unsigned_tx, input_maps, output_maps):
    raw = PSBT_MAGIC + _serialize_map([(b"\x00", unsigned_tx)])
    raw += b"".join(_serialize_map(m) for m in input_maps)
    raw += b"".join(_serialize_map(m) for m in output_maps)
    return base64.b64encode(raw).decode("ascii")


def _witness_utxo(txout):
    return txout.value.to_bytes(8, "little") + pushdata(txout.spk)


def _decode_witness_utxo(raw):
    if len(raw) < 9:
        raise ValueError("witness_utxo tronque")
    value = int.from_bytes(raw[:8], "little")
    ln, pos = _read_compact(raw, 8)
    if pos + ln != len(raw):
        raise ValueError("witness_utxo non canonique")
    return value, raw[pos:]


def _p2wpkh_program_for(pub, spk, redeem=None):
    native = b"\x00\x14" + hash160(pub)
    if spk == native and redeem is None:
        return native
    if (redeem == native and spk_kind(spk) == "P2SH"
            and spk[:2] == b"\xa9\x14" and spk[-1:] == b"\x87"
            and spk[2:-1] == hash160(redeem)):
        return native
    raise Refusal("La cle publique Xverse ne correspond pas au script de financement.")


def create_card_signed_psbt(plan, card_wif, funding_pubkey):
    """Signe uniquement l'entree 0 et produit la PSBT a remettre a Xverse."""
    tx = plan["tx"]
    if len(tx.vin) != 2 or len(tx.vout) != 2:
        raise Refusal("PSBT exige exactement deux entrees et deux sorties.")
    try:
        priv, compressed = wif_decode(card_wif)
        fund_pub = bytes.fromhex(funding_pubkey)
    except (ValueError, TypeError) as e:
        raise Refusal("Cle illisible : %s" % e)
    if not compressed:
        raise Refusal("WIF de carte non compresse.")
    card_pub = compress_point(privkey_to_point(priv))
    if b"\x00\x14" + hash160(card_pub) != plan["card_spk"]:
        raise Refusal("Le WIF ne correspond pas a l'UTXO de la carte.")
    redeem = b"\x00\x14" + hash160(fund_pub) if spk_kind(plan["fund_spk"]) == "P2SH" else None
    _p2wpkh_program_for(fund_pub, plan["fund_spk"], redeem)
    tx.vin[1].redeem_script = redeem
    digest = tx.sighash_p2wpkh(0)
    r, s = ecdsa_sign(priv, digest)
    sig = der_encode(r, s) + bytes([SIGHASH_ALL])
    if not ecdsa_verify(card_pub, digest, r, s):
        raise Refusal("Echec de verification de la signature locale.")
    maps = [
        [(b"\x01", _witness_utxo(TxOut(tx.vin[0].value, tx.vin[0].spk))),
         (b"\x02" + card_pub, sig), (b"\x03", SIGHASH_ALL.to_bytes(4, "little"))],
        [(b"\x01", _witness_utxo(TxOut(tx.vin[1].value, tx.vin[1].spk))),
         (b"\x03", SIGHASH_ALL.to_bytes(4, "little"))] +
        ([(b"\x04", redeem)] if redeem else [])
    ]
    return serialize_psbt(tx.serialize(witness=False), maps, [[], []])


def _map_dict(items):
    return {k: v for k, v in items}


def verify_xverse_psbt(original_b64, returned_b64, plan, funding_pubkey):
    """Traite la reponse wallet comme hostile, finalise et reverifie les deux signatures."""
    original, returned = parse_psbt(original_b64), parse_psbt(returned_b64)
    if returned["unsigned"] != original["unsigned"]:
        raise Refusal("Xverse a modifie la transaction non signee.")
    if returned["outputs"] != original["outputs"]:
        raise Refusal("Xverse a modifie les metadonnees de sortie.")
    allowed_types = {1, 2, 3, 4}
    for idx, items in enumerate(returned["inputs"]):
        if any(not k or k[0] not in allowed_types for k, _ in items):
            raise Refusal("Metadonnee PSBT inattendue a l'entree %d." % idx)
    om0, rm0 = _map_dict(original["inputs"][0]), _map_dict(returned["inputs"][0])
    if set(rm0) != set(om0):
        raise Refusal("Xverse a ajouté ou retiré une métadonnée à l'entrée carte.")
    for key, value in om0.items():
        if rm0.get(key) != value:
            raise Refusal("Signature ou metadonnee de la carte modifiee.")
    tx = plan["tx"]
    for idx in (0, 1):
        rm = _map_dict(returned["inputs"][idx])
        if rm.get(b"\x03") != SIGHASH_ALL.to_bytes(4, "little"):
            raise Refusal("SIGHASH_ALL absent a l'entree %d." % idx)
        if rm.get(b"\x01") != _witness_utxo(TxOut(tx.vin[idx].value, tx.vin[idx].spk)):
            raise Refusal("witness_utxo modifie a l'entree %d." % idx)
    partial0 = [(k[1:], v) for k, v in returned["inputs"][0] if k[:1] == b"\x02"]
    fund_pub = bytes.fromhex(funding_pubkey)
    partial1 = [(k[1:], v) for k, v in returned["inputs"][1] if k[:1] == b"\x02"]
    if len(partial0) != 1 or len(partial1) != 1 or partial1[0][0] != fund_pub:
        raise Refusal("Signatures partielles absentes, multiples ou appliquees a la mauvaise cle.")
    expected1 = set(_map_dict(original["inputs"][1])) | {b"\x02" + fund_pub}
    if set(_map_dict(returned["inputs"][1])) != expected1:
        raise Refusal("Xverse a ajouté, retiré ou remplacé une métadonnée de financement.")
    redeem = _map_dict(returned["inputs"][1]).get(b"\x04")
    _p2wpkh_program_for(fund_pub, plan["fund_spk"], redeem)
    tx.vin[1].redeem_script = redeem
    for idx, (pub, sig) in enumerate((partial0[0], partial1[0])):
        if not sig or sig[-1] != SIGHASH_ALL:
            raise Refusal("Signature %d sans SIGHASH_ALL." % idx)
        try:
            rr, ss = der_decode(sig[:-1])
        except ValueError as e:
            raise Refusal("Signature DER invalide a l'entree %d : %s" % (idx, e))
        if not ecdsa_verify(pub, tx.sighash_p2wpkh(idx), rr, ss):
            raise Refusal("Signature cryptographique invalide a l'entree %d." % idx)
        tx.vin[idx].witness = [sig, pub]
    if redeem:
        # P2SH-P2WPKH: scriptSig pousse le redeemScript witness.
        tx.vin[1].script_sig = pushdata(redeem)
    raw = tx.serialize()
    parsed = parse_tx(raw)
    if parsed["version"] != 2 or parsed["locktime"] != 0:
        raise Refusal("Version ou locktime inattendu apres finalisation.")
    fails = check_invariants(tx, tx.vin[0].txid, tx.vin[0].vout, plan["dest_spk"],
                             plan["card_value"])
    if fails:
        raise Refusal("Transaction finalisee non sure :\n - " + "\n - ".join(fails))
    return {"hex": raw.hex(), "txid": tx.txid(), "weight": tx.weight(),
            "vsize": tx.vsize(), "fee": plan["fee"],
            "feerate": plan["fee"] / float(tx.vsize())}


def sign_plan(plan, card_wif, fund_wif):
    """Signe le plan produit par plan_recovery, puis revalide a partir des octets
    serialises. Retourne (hex, txid, vsize). Leve Refusal en cas de probleme."""
    tx = plan["tx"]

    try:
        card_priv, card_comp = wif_decode(card_wif)
    except ValueError as e:
        raise Refusal("WIF de la carte illisible : %s" % e)
    if not card_comp:
        raise Refusal("WIF non compresse. Les cartes utilisent des cles compressees.")
    card_pub = compress_point(privkey_to_point(card_priv))
    if hash160(card_pub) != plan["card_spk"][2:]:
        raise Refusal("Le WIF fourni ne correspond pas a l'adresse de la carte.\n"
                      "  adresse de ce WIF : %s\n  adresse attendue  : %s"
                      % (p2wpkh_address(card_pub), plan["card_address"]))

    try:
        fund_priv, _ = wif_decode(fund_wif)
    except ValueError as e:
        raise Refusal("WIF de financement illisible : %s" % e)
    fund_pub = compress_point(privkey_to_point(fund_priv))
    if hash160(fund_pub) != plan["fund_spk"][2:]:
        raise Refusal("Le WIF de financement ne correspond pas a son UTXO.")

    for idx, priv, pub in ((0, card_priv, card_pub), (1, fund_priv, fund_pub)):
        h = tx.sighash_p2wpkh(idx)
        r, s = ecdsa_sign(priv, h)
        if not ecdsa_verify(pub, h, r, s):
            raise Refusal("Erreur interne : signature invalide a l'entree %d." % idx)
        tx.vin[idx].witness = [der_encode(r, s) + bytes([SIGHASH_ALL]), pub]

    raw = tx.serialize()

    # Revalidation a partir des octets signes, pas de la structure en memoire.
    parsed = parse_tx(raw)
    values = [plan["tx"].vin[0].value, plan["tx"].vin[1].value]
    spks = [plan["card_spk"], plan["fund_spk"]]
    reparsed = Tx([TxIn(i["txid"], i["vout"], values[n], spks[n])
                   for n, i in enumerate(parsed["vin"])],
                  [TxOut(o["value"], o["spk"]) for o in parsed["vout"]])
    card_txid, card_vout = plan["card_outpoint"].rsplit(":", 1)
    fails = check_invariants(reparsed, card_txid, int(card_vout), plan["dest_spk"],
                             plan.get("card_value", plan["tx"].vin[0].value))
    if fails:
        raise Refusal("La transaction signee viole un invariant, rien n'est ecrit :\n  - "
                      + "\n  - ".join(fails))

    return raw.hex(), tx.txid(), tx.vsize()


def cmd_build(args):
    ctx = load_context(args.context)
    if "confirmed" in ctx["card"] and ctx["card"]["confirmed"] is False:
        print("Avertissement : l'UTXO de la carte n'est pas confirme.")

    try:
        plan = plan_recovery(ctx, args.dest, feerate=args.feerate,
                             fee=args.fee, change_addr=args.change)
    except Refusal as e:
        raise SystemExit("REFUS : %s" % e)

    tx = plan["tx"]
    print("")
    print("=" * 72)
    print("RECAPITULATIF AVANT SIGNATURE")
    print("=" * 72)
    print("Entree 0  (CARTE)       %s" % plan["card_outpoint"])
    print("                        %s" % plan["card_address"])
    print("                        %s sats" % _fmt_sat(tx.vin[0].value))
    print("Entree 1  (FINANCEMENT) %s" % plan["fund_outpoint"])
    print("                        %s sats" % _fmt_sat(tx.vin[1].value))
    print("")
    print("Sortie 0  (DESTINATION) %s" % plan["dest_address"])
    print("                        %s sats  [%s]"
          % (_fmt_sat(tx.vout[0].value), spk_kind(plan["dest_spk"])))
    print("Sortie 1  (CHANGE)      %s" % plan["change_address"])
    print("                        %s sats" % _fmt_sat(tx.vout[1].value))
    print("")
    print("Frais                   %s sats" % _fmt_sat(plan["fee"]))
    print("Taille estimee          %d vB (%.2f sat/vB)"
          % (plan["vsize"], plan["feerate_effective"]))
    print("Frais preleves sur      l'entree de financement uniquement")
    print("")
    if plan["prediction"]:
        print("Sat %s : sortie 0, offset %d  -> PRESERVE"
              % (_fmt_sat(plan["target_sat"]), plan["prediction"]["offset"]))
    else:
        print("Plages de sats absentes du contexte : position non predite.")
        print("La construction preserve le sat quelle que soit sa position, "
              "mais verifiez le resultat sur un indexeur apres diffusion.")
    print("=" * 72)

    if not args.yes:
        if not sys.stdin.isatty():
            raise SystemExit("Confirmation impossible sans terminal. Utilisez --yes.")
        if input("\nTaper SIGNER pour signer, autre chose pour abandonner : ").strip() != "SIGNER":
            raise SystemExit("Abandon.")

    card_wif = _read_wif("WIF de la carte", "POS_CARD_WIF")
    fund_wif = _read_wif("WIF de financement", "POS_FUND_WIF")
    try:
        hexstr, txid, vsize = sign_plan(plan, card_wif, fund_wif)
    except Refusal as e:
        raise SystemExit("REFUS : %s" % e)

    with open(args.output, "w") as f:
        f.write(hexstr + "\n")
    os.chmod(args.output, 0o600)

    print("")
    print("Signature effectuee. Aucune diffusion.")
    print("txid : %s" % txid)
    print("vsize reel : %d vB (%.2f sat/vB)" % (vsize, plan["fee"] / float(vsize)))
    print("hex ecrit dans : %s" % args.output)
    print("")
    print("Etapes suivantes :")
    print("  1. python3 pos_recover.py verify --tx %s --context %s"
          % (args.output, args.context))
    print("  2. Controle croise : bitcoin-cli decoderawtransaction <hex>")
    print("  3. Diffusion : python3 pos_recover.py broadcast --tx %s" % args.output)



def cmd_verify(args):
    with open(args.tx) as f:
        raw = bytes.fromhex(f.read().strip())
    parsed = parse_tx(raw)
    ctx = load_context(args.context)
    card, fund = ctx["card"], ctx["funding"]
    card_spk = bytes.fromhex(card["scriptpubkey"])
    fund_spk = bytes.fromhex(fund["scriptpubkey"])

    values = {(card["txid"].lower(), card["vout"]): (card["value"], card_spk),
              (fund["txid"].lower(), fund["vout"]): (fund["value"], fund_spk)}

    vin = []
    for i in parsed["vin"]:
        key = (i["txid"].lower(), i["vout"])
        if key not in values:
            raise SystemExit("Entree %s:%d absente du contexte. Transaction inattendue."
                             % (i["txid"], i["vout"]))
        val, spk = values[key]
        t = TxIn(i["txid"], i["vout"], val, spk, i["sequence"])
        t.witness = i["witness"]
        vin.append(t)
    vout = [TxOut(o["value"], o["spk"]) for o in parsed["vout"]]
    tx = Tx(vin, vout, parsed["version"], parsed["locktime"])

    dest_spk = vout[0].spk if vout else b""
    print("txid : %s" % tx.txid())
    print("version %d, locktime %d, vsize %d vB" % (tx.version, tx.locktime, tx.vsize()))
    for n, i in enumerate(tx.vin):
        print("  entree %d : %s:%d  %s sats  %s"
              % (n, i.txid, i.vout, _fmt_sat(i.value), spk_kind(i.spk)))
    for n, o in enumerate(tx.vout):
        try:
            addr = spk_to_address(o.spk)
        except Exception:
            addr = "?"
        print("  sortie %d : %s sats  %s  %s" % (n, _fmt_sat(o.value), spk_kind(o.spk), addr))
    fee = sum(i.value for i in tx.vin) - sum(o.value for o in tx.vout)
    print("  frais : %s sats" % _fmt_sat(fee))

    # Signatures.
    sig_ok = True
    for n, i in enumerate(tx.vin):
        if len(i.witness) != 2:
            print("  entree %d : witness inattendu" % n)
            sig_ok = False
            continue
        sig, pub = i.witness
        try:
            r, s = der_decode(sig[:-1])
            if not ecdsa_verify(pub, tx.sighash_p2wpkh(n), r, s):
                print("  entree %d : SIGNATURE INVALIDE" % n)
                sig_ok = False
            elif s > _N // 2:
                print("  entree %d : signature high-S, non standard" % n)
                sig_ok = False
            elif hash160(pub) != i.spk[2:]:
                print("  entree %d : la cle publique ne correspond pas au scriptPubKey" % n)
                sig_ok = False
        except Exception as e:
            print("  entree %d : signature illisible (%s)" % (n, e))
            sig_ok = False

    fails = check_invariants(tx, card["txid"], card["vout"], dest_spk,
                             int(card["value"]))
    print("")
    if fails or not sig_ok:
        print("VERIFICATION ECHOUEE. NE PAS DIFFUSER.")
        for f in fails:
            print("  - " + f)
        raise SystemExit(2)
    print("Invariants respectes. Signatures valides.")

    ranges = card.get("sat_ranges")
    if ranges:
        card_ranges = normalize_ranges(ranges)
        target = int(card.get("target_sat", card_ranges[0][0]))
        per_out, fee_ranges = allocate([card_ranges, [(0, fund["value"])]],
                                       [o.value for o in tx.vout])
        where, oi, off = locate_sat(target, per_out, fee_ranges)
        if where == "output" and oi == 0:
            print("Sat %s : sortie 0, offset %d. Preserve." % (_fmt_sat(target), off))
        else:
            print("Sat %s : %s. PROBLEME." % (_fmt_sat(target), where))
            raise SystemExit(2)


def spk_to_address(spk):
    kind = spk_kind(spk)
    if kind in ("P2WPKH", "P2WSH"):
        return segwit_encode(0, spk[2:])
    if kind == "P2TR":
        return segwit_encode(1, spk[2:])
    if kind == "P2PKH":
        return b58check_encode(bytes([_NET["p2pkh"]]) + spk[3:23])
    if kind == "P2SH":
        return b58check_encode(bytes([_NET["p2sh"]]) + spk[2:22])
    raise ValueError("type inconnu")


def cmd_broadcast(args):
    with open(args.tx) as f:
        hexstr = f.read().strip()
    parse_tx(bytes.fromhex(hexstr))  # refus de diffuser un hex illisible
    if not args.yes:
        ans = input("Diffuser cette transaction sur le reseau ? Taper DIFFUSER : ").strip()
        if ans != "DIFFUSER":
            raise SystemExit("Abandon.")
    txid = _http_post("%s/tx" % args.api, hexstr)
    print("Diffuse. txid : %s" % txid.strip())
    print("Verifiez la position du sat sur un indexeur ordinal avant de considerer "
          "l'operation terminee.")


# Premier bitcoin du bloc 9 : sats 45 000 000 000 a 45 099 999 999, prefixe "450".
BLOCK9_FIRST_BTC = (45_000_000_000, 45_100_000_000)
BLOCK9_ALL = (45_000_000_000, 50_000_000_000)


def cmd_audit(args):
    """Audit des cartes : position exacte du sat rare dans chaque sortie."""
    with open(args.cards) as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    rows = []
    for line in lines:
        parts = line.split()
        label = parts[0] if len(parts) > 1 else None
        outpoint = parts[-1]
        row = {"card": label, "outpoint": outpoint}
        try:
            txid, vout = parse_outpoint(outpoint)
            utxo = fetch_utxo(args.api, txid, vout)
            row.update({"value": utxo["value"], "scriptpubkey": utxo["scriptpubkey"],
                        "address": utxo["address"], "spent": utxo["spent"]})
            ranges = fetch_sat_ranges(args.ord, txid, vout)
            row["sat_ranges"] = [[a, b] for a, b in ranges]
            total = sum(b - a for a, b in ranges)
            row["ranges_total"] = total

            offset = 0
            found = None
            for start, end in ranges:
                for candidate in (start,):
                    if BLOCK9_ALL[0] <= candidate < BLOCK9_ALL[1]:
                        found = (candidate, offset, end - start)
                offset += end - start
            if found is None:
                row["status"] = "AUCUN SAT BLOC 9 TROUVE"
            else:
                sat, off, size = found
                row.update({"target_sat": sat, "offset": off, "range_size": size,
                            "first_btc_of_block9": BLOCK9_FIRST_BTC[0] <= sat < BLOCK9_FIRST_BTC[1]})
                problems = []
                if total != CARD_VALUE:
                    problems.append("total %d != 546" % total)
                if size != 1:
                    problems.append("plage de %d sats au lieu de 1" % size)
                if not row["first_btc_of_block9"]:
                    problems.append("hors du premier bitcoin du bloc 9")
                if utxo["value"] != CARD_VALUE:
                    problems.append("sortie de %d sats" % utxo["value"])
                if utxo["spent"]:
                    problems.append("DEJA DEPENSE")
                if off == CARD_VALUE - 1:
                    problems.append("position haute, balayage naif destructeur")
                row["status"] = "OK" if not problems else " | ".join(problems)
        except Exception as e:
            row["status"] = "ERREUR : %s" % e
        rows.append(row)
        print("%-8s %-6s offset %-5s %s" % (
            row.get("card") or "?",
            row.get("value", "?"),
            row.get("offset", "?"),
            row["status"]))

    with open(args.output, "w") as f:
        json.dump(rows, f, indent=2)

    high = sum(1 for r in rows if r.get("offset") == CARD_VALUE - 1)
    low = sum(1 for r in rows if r.get("offset") == 0)
    other = sum(1 for r in rows if r.get("offset") not in (0, CARD_VALUE - 1, None))
    print("")
    print("%d cartes auditees" % len(rows))
    print("  offset 0 (robuste)          : %d" % low)
    print("  offset 545 (destructible)   : %d" % high)
    print("  autre position              : %d" % other)
    print("  erreurs / introuvables      : %d"
          % sum(1 for r in rows if r["status"].startswith("ERREUR")))
    print("Audit ecrit dans %s" % args.output)


def cmd_simulate(args):
    """Demonstration executable du probleme et de la solution."""
    sat = 45020123482
    pad = 1033044476994685
    card_ranges = [(sat, sat + 1), (pad, pad + 545)]
    card_ranges_last = [(pad, pad + 545), (sat, sat + 1)]
    for r in (card_ranges, card_ranges_last):
        assert sum(e - s for s, e in r) == CARD_VALUE

    print("Plages d'une carte, sat rare en offset 0 :")
    print("  %s" % (card_ranges,))
    print("Plages d'une carte, sat rare en offset 545 :")
    print("  %s" % (card_ranges_last,))
    print("")

    scenarios = [
        ("Balayage naif (1 entree de 546, 1 sortie de 400, 146 de frais)",
         lambda r: allocate([r], [400])),
        ("Construction pos-recover (carte + financement, sortie 0 = 546)",
         lambda r: allocate([r, [(9 * 10 ** 15, 9 * 10 ** 15 + 50000)]], [546, 49000])),
    ]

    for label, fn in scenarios:
        print(label)
        for name, ranges in (("offset 0  ", card_ranges), ("offset 545", card_ranges_last)):
            per_out, fee_ranges = fn(ranges)
            where, oi, off = locate_sat(sat, per_out, fee_ranges)
            if where == "fee":
                verdict = "DETRUIT, part au mineur"
            elif where == "output":
                verdict = "preserve, sortie %d offset %d" % (oi, off)
            else:
                verdict = "introuvable"
            print("  carte avec sat en %s : %s" % (name, verdict))
        print("")


# ---------------------------------------------------------------------------
# Autotests
# ---------------------------------------------------------------------------

def cmd_selftest(args):
    failures = []

    def check(label, got, want):
        ok = got == want
        print("  [%s] %s" % ("OK " if ok else "ECHEC", label))
        if not ok:
            failures.append("%s\n      obtenu : %r\n      attendu: %r" % (label, got, want))

    print("RIPEMD-160")
    check("hash de la chaine vide", ripemd160(b"").hex(),
          "9c1185a5c5e9fc54612808977ee8f548b2258d31")
    check("hash de 'abc'", ripemd160(b"abc").hex(),
          "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
    check("hash de 'message digest'", ripemd160(b"message digest").hex(),
          "5d0689ef49d2fae572b881b123a85ffa21595f36")
    check("hash de a..z", ripemd160(b"abcdefghijklmnopqrstuvwxyz").hex(),
          "f71c27109c692c1b56bbdceb5b9d2865b3708dbc")
    check("bloc de 1000000 x 'a'", ripemd160(b"a" * 1000000).hex(),
          "52783243c1697bdbe16d37f97f68f08325dc1528")

    print("secp256k1")
    check("G", compress_point(privkey_to_point(1)).hex(),
          "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    check("2G", compress_point(privkey_to_point(2)).hex(),
          "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
    check("3G", compress_point(privkey_to_point(3)).hex(),
          "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
    pt = privkey_to_point(0x1234567890ABCDEF)
    check("compression puis decompression", decompress_point(compress_point(pt)), pt)

    print("Bech32 / adresses (vecteurs BIP-173)")
    check("hash160 de G", hash160(compress_point(privkey_to_point(1))).hex(),
          "751e76e8199196d454941c45d1b3a323f1433bd6")
    check("P2WPKH de G", p2wpkh_address(compress_point(privkey_to_point(1))),
          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    check("decodage aller-retour", segwit_decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
          (0, bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")))
    p2tr = segwit_encode(1, bytes(range(32)))
    check("P2TR aller-retour", segwit_decode(p2tr), (1, bytes(range(32))))
    bad = 0
    for addr in ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",   # checksum casse
                 "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",   # mauvais hrp
                 "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3T4"):  # casse mixte
        try:
            segwit_decode(addr)
        except ValueError:
            bad += 1
    check("rejet de 3 adresses invalides", bad, 3)

    print("WIF")
    check("WIF de la cle 1 (vecteur connu)", wif_encode(1, True),
          "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
    check("decodage WIF", wif_decode("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
          (1, True))
    try:
        wif_decode("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWm")
        check("rejet d'un WIF au checksum casse", "accepte", "rejete")
    except ValueError:
        check("rejet d'un WIF au checksum casse", "rejete", "rejete")

    print("ECDSA")
    msg = sha256(b"proof of sats")
    r, s = ecdsa_sign(0xC0FFEE, msg)
    pub = compress_point(privkey_to_point(0xC0FFEE))
    check("signature verifiee", ecdsa_verify(pub, msg, r, s), True)
    check("low-S applique", s <= _N // 2, True)
    check("signature deterministe", ecdsa_sign(0xC0FFEE, msg), (r, s))
    check("rejet sur message different", ecdsa_verify(pub, sha256(b"autre"), r, s), False)
    check("DER aller-retour", der_decode(der_encode(r, s)), (r, s))

    print("Attribution ordinale")
    sat = 45020123482
    first = [(sat, sat + 1), (10 ** 15, 10 ** 15 + 545)]
    last = [(10 ** 15, 10 ** 15 + 545), (sat, sat + 1)]
    po, fr = allocate([first], [400])
    check("balayage naif, sat en offset 0 : preserve", locate_sat(sat, po, fr)[0], "output")
    po, fr = allocate([last], [400])
    check("balayage naif, sat en offset 545 : detruit", locate_sat(sat, po, fr)[0], "fee")
    fund = [(9 * 10 ** 15, 9 * 10 ** 15 + 50000)]
    for name, rg, want_off in (("offset 0", first, 0), ("offset 545", last, 545)):
        po, fr = allocate([rg, fund], [546, 49000])
        check("construction pos-recover, %s : sortie 0 offset %d" % (name, want_off),
              locate_sat(sat, po, fr), ("output", 0, want_off))
    po, fr = allocate([last, fund], [545, 49001])
    check("sortie 0 a 545 sats : sat perdu vers la sortie 1",
          locate_sat(sat, po, fr)[1], 1)
    po, fr = allocate([fund, last], [546, 49000])
    check("carte en entree 1 : sat detruit", locate_sat(sat, po, fr)[0], "fee")

    print("Invariants")
    card_priv = 0xA11CE
    fund_priv = 0xB0B
    card_spk = address_to_spk(p2wpkh_address(compress_point(privkey_to_point(card_priv))))
    fund_spk = address_to_spk(p2wpkh_address(compress_point(privkey_to_point(fund_priv))))
    dest_spk = address_to_spk(segwit_encode(1, sha256(b"dest")))
    ctxid = "11" * 32
    ftxid = "22" * 32

    def build(vin_order=(0, 1), out0=546, out1=49000, drop_fund=False, dest=None):
        ci = TxIn(ctxid, 0, 546, card_spk)
        fi = TxIn(ftxid, 1, 50000, fund_spk)
        ins = [ci] if drop_fund else [[ci, fi][i] for i in vin_order]
        outs = [TxOut(out0, dest or dest_spk), TxOut(out1, fund_spk)]
        return Tx(ins, outs)

    check("construction correcte : aucune violation",
          check_invariants(build(), ctxid, 0, dest_spk), [])
    check("carte en entree 1 : violation INV1",
          any("INV1" in f for f in check_invariants(build(vin_order=(1, 0)), ctxid, 0, dest_spk)),
          True)
    check("sortie 0 a 545 : violation INV2",
          any("INV2" in f for f in check_invariants(build(out0=545), ctxid, 0, dest_spk)), True)
    check("financement absent : violation INV3",
          any("INV3" in f for f in check_invariants(build(drop_fund=True), ctxid, 0, dest_spk)),
          True)
    check("change sous le seuil de poussiere : violation",
          any("POUSSIERE" in f for f in check_invariants(build(out1=200), ctxid, 0, dest_spk)),
          True)
    check("sorties superieures aux entrees : violation",
          any("INV3" in f for f in check_invariants(build(out1=60000), ctxid, 0, dest_spk)), True)

    print("Refus au niveau plan_recovery (collisions d'adresses)")
    fund_addr = spk_to_address(fund_spk)
    card_addr = spk_to_address(card_spk)
    other_addr = segwit_encode(0, hash160(b"autre destination"))

    def plan_ctx(dest_addr):
        ctx = {
            "card": {"txid": ctxid, "vout": 0, "value": 546,
                     "scriptpubkey": card_spk.hex(), "address": card_addr, "spent": False},
            "funding": {"txid": ftxid, "vout": 1, "value": 50000,
                        "scriptpubkey": fund_spk.hex(), "address": fund_addr, "spent": False},
        }
        return plan_recovery(ctx, dest_addr, feerate=2.0)

    try:
        plan_ctx(other_addr)
        check("destination distincte : acceptee", "accepte", "accepte")
    except Refusal:
        check("destination distincte : acceptee", "refusee", "accepte")

    try:
        plan_ctx(card_addr)
        check("destination = adresse de la carte : refusee", "acceptee", "refusee")
    except Refusal:
        check("destination = adresse de la carte : refusee", "refusee", "refusee")

    try:
        plan_ctx(fund_addr)
        check("destination = adresse de financement : refusee", "acceptee", "refusee")
    except Refusal:
        check("destination = adresse de financement : refusee", "refusee", "refusee")

    print("Serialisation et signature de bout en bout")
    tx = build()
    for idx, priv in ((0, card_priv), (1, fund_priv)):
        h = tx.sighash_p2wpkh(idx)
        rr, ss = ecdsa_sign(priv, h)
        pubk = compress_point(privkey_to_point(priv))
        tx.vin[idx].witness = [der_encode(rr, ss) + b"\x01", pubk]
    raw = tx.serialize()
    parsed = parse_tx(raw)
    check("analyse : nombre d'entrees", len(parsed["vin"]), 2)
    check("analyse : nombre de sorties", len(parsed["vout"]), 2)
    check("analyse : marqueur segwit", parsed["segwit"], True)
    check("analyse : ordre des entrees preserve",
          [(i["txid"], i["vout"]) for i in parsed["vin"]], [(ctxid, 0), (ftxid, 1)])
    check("analyse : valeurs de sortie preservees",
          [o["value"] for o in parsed["vout"]], [546, 49000])
    ok_sigs = True
    for n, i in enumerate(tx.vin):
        rr, ss = der_decode(i.witness[0][:-1])
        if not ecdsa_verify(i.witness[1], tx.sighash_p2wpkh(n), rr, ss):
            ok_sigs = False
    check("signatures des deux entrees valides", ok_sigs, True)
    check("vsize plausible pour 2 entrees P2WPKH et 2 sorties (%d vB)" % tx.vsize(),
          200 <= tx.vsize() <= 235, True)
    check("adresse reconstruite depuis le scriptPubKey",
          spk_to_address(fund_spk), p2wpkh_address(compress_point(privkey_to_point(fund_priv))))

    print("Cloisonnement des reseaux")
    main_wif = wif_encode(1, True)
    main_addr = p2wpkh_address(compress_point(privkey_to_point(1)))
    set_network("signet")
    sig_wif = wif_encode(1, True)
    check("WIF signet : octet de version 0xEF", b58check_decode(sig_wif)[0], 0xEF)
    check("WIF signet : aller-retour", wif_decode(sig_wif), (1, True))
    check("WIF signet : distinct du WIF mainnet", sig_wif != main_wif, True)
    check("adresse signet de la cle 1 (vecteur BIP-173)",
          p2wpkh_address(compress_point(privkey_to_point(1))),
          "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
    check("scriptPubKey identique sur les deux reseaux",
          address_to_spk("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").hex(),
          "0014751e76e8199196d454941c45d1b3a323f1433bd6")
    rejected = 0
    for fn, arg in ((wif_decode, main_wif), (address_to_spk, main_addr)):
        try:
            fn(arg)
        except ValueError:
            rejected += 1
    check("rejet du WIF et de l'adresse mainnet en mode signet", rejected, 2)
    set_network("mainnet")
    check("retour en mainnet", p2wpkh_address(compress_point(privkey_to_point(1))), main_addr)

    print("")
    if failures:
        print("%d ECHEC(S) :" % len(failures))
        for f in failures:
            print("  - " + f)
        return 1
    print("Tous les tests passent.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        prog="pos_recover.py",
        description="Recuperation sure des satoshis Proof of Sats. "
                    "Refuse de signer toute transaction destructrice.")
    p.add_argument("--network", default="mainnet", choices=sorted(NETWORKS),
                   help="mainnet par defaut. signet et testnet4 servent aux repetitions.")
    sub = p.add_subparsers(dest="cmd")

    f = sub.add_parser("fetch", help="recuperer les donnees on-chain (EN LIGNE)")
    f.add_argument("--card", required=True, metavar="TXID:VOUT")
    f.add_argument("--funding", required=True, metavar="TXID:VOUT")
    f.add_argument("--sat", type=int, help="numero du sat rare attendu")
    f.add_argument("--api")
    f.add_argument("--ord", help="instance ord avec --index-sats")
    f.add_argument("--no-ord", action="store_true", help="ne pas interroger d'indexeur ordinal")
    f.add_argument("-o", "--output", default="context.json")
    f.set_defaults(func=cmd_fetch)

    b = sub.add_parser("build", help="construire, verifier et signer (HORS LIGNE)")
    b.add_argument("--context", required=True)
    b.add_argument("--dest", required=True, help="adresse de destination du sat")
    b.add_argument("--change", help="adresse de change (defaut : adresse de financement)")
    b.add_argument("--feerate", type=float, default=5.0, help="sat/vB")
    b.add_argument("--fee", type=int, help="frais absolus en sats, prioritaire sur --feerate")
    b.add_argument("-o", "--output", default="tx.hex")
    b.add_argument("--yes", action="store_true", help="sauter la confirmation interactive")
    b.set_defaults(func=cmd_build)

    v = sub.add_parser("verify", help="re-verifier une transaction signee (HORS LIGNE)")
    v.add_argument("--tx", required=True)
    v.add_argument("--context", required=True)
    v.set_defaults(func=cmd_verify)

    br = sub.add_parser("broadcast", help="diffuser (EN LIGNE, etape separee)")
    br.add_argument("--tx", required=True)
    br.add_argument("--api")
    br.add_argument("--yes", action="store_true")
    br.set_defaults(func=cmd_broadcast)

    a = sub.add_parser("audit", help="auditer la position du sat sur un lot de cartes (EN LIGNE)")
    a.add_argument("--cards", required=True,
                   help="fichier texte, une carte par ligne : 'NUMERO TXID:VOUT'")
    a.add_argument("--api")
    a.add_argument("--ord")
    a.add_argument("-o", "--output", default="audit.json")
    a.set_defaults(func=cmd_audit)

    s = sub.add_parser("simulate", help="demonstration du probleme et de la solution")
    s.set_defaults(func=cmd_simulate)

    t = sub.add_parser("selftest", help="autotests cryptographiques et logiques")
    t.set_defaults(func=cmd_selftest)

    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        p.print_help()
        return 1

    set_network(args.network)
    if getattr(args, "api", None) is None and hasattr(args, "api"):
        args.api = _NET["api"]
    if getattr(args, "ord", None) is None and hasattr(args, "ord"):
        args.ord = _NET["ord"]
        if args.ord is None and not getattr(args, "no_ord", False):
            print("Note : aucun indexeur ordinal public connu pour %s. "
                  "Passez --ord URL vers votre propre instance ord --index-sats, "
                  "ou --no-ord." % args.network, file=sys.stderr)
    if args.network != "mainnet" and args.cmd in ("fetch", "build", "audit"):
        print("Reseau : %s. Repetition, pas de valeur reelle en jeu.\n" % args.network)

    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
