#!/usr/bin/env python3
"""Synthetic IPsec dataset generator (IKEv1/IKEv2 handshakes, ESP, AH, NAT-T, IPv4/IPv6).
ESP payloads are random bytes with realistic sizes/IV/ICV/padding; IKE cleartext
payloads (SA proposals, KE, nonce, NAT-D) are structurally valid. Ground truth in manifest.json.
"""
import os, sys, struct, random, json, hashlib, socket, bisect

OUT = sys.argv[1] if len(sys.argv) > 1 else 'out'
os.makedirs(OUT, exist_ok=True)
T0 = 1790000000.0
RB = os.urandom(1 << 23)
_rr = random.Random(7)


def rnd(n):
    o = _rr.randrange(0, len(RB) - n)
    return RB[o:o + n]


def rb(r, n):
    return bytes(r.getrandbits(8) for _ in range(n))


MAC_A = bytes.fromhex('02aa00000001')
MAC_B = bytes.fromhex('02bb00000002')
ADDR = {
    False: (socket.inet_aton('203.0.113.10'), socket.inet_aton('198.51.100.20')),
    True: (socket.inet_pton(socket.AF_INET6, '2001:db8:a::10'), socket.inet_pton(socket.AF_INET6, '2001:db8:b::20')),
}
INNER = (socket.inet_aton('10.1.0.5'), socket.inet_aton('10.2.0.9'))


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


_id = [1000]


def ip4(src, dst, proto, payload, ttl=64):
    _id[0] = (_id[0] + 1) & 0xffff
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), _id[0], 0x4000, ttl, proto, 0, src, dst)
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload


def ip6(src, dst, nh, payload, hl=64):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), nh, hl, src, dst) + payload


def udp(sport, dport, payload, src=None, dst=None, v6=False):
    l = 8 + len(payload)
    if v6:
        ph = src + dst + struct.pack('!I3xB', l, 17)
        c = csum(ph + struct.pack('!HHHH', sport, dport, l, 0) + payload) or 0xffff
        return struct.pack('!HHHH', sport, dport, l, c) + payload
    return struct.pack('!HHHH', sport, dport, l, 0) + payload


def eth(d, et, pl):
    return (MAC_B + MAC_A if d == 0 else MAC_A + MAC_B) + struct.pack('!H', et) + pl


def outer(d, v6, proto, payload):
    a, b = ADDR[v6]
    s, t = (a, b) if d == 0 else (b, a)
    pkt = ip6(s, t, proto, payload) if v6 else ip4(s, t, proto, payload)
    return eth(d, 0x86DD if v6 else 0x0800, pkt)


def udp_frame(d, v6, sp, dp, payload):
    a, b = ADDR[v6]
    s, t = (a, b) if d == 0 else (b, a)
    return outer(d, v6, 17, udp(sp, dp, payload, s, t, v6))


# ---------------------------------------------------------------- tables
DH = {'modp768': 1, 'modp1024': 2, 'modp1536': 5, 'modp2048': 14, 'modp3072': 15, 'modp4096': 16,
      'ecp256': 19, 'ecp384': 20, 'ecp521': 21, 'curve25519': 31}
KS = {1: 96, 2: 128, 5: 192, 14: 256, 15: 384, 16: 512, 19: 64, 20: 96, 21: 132, 31: 32}
V2ENC = {'3des': 3, 'aes-cbc': 12, 'aes-gcm': 20}
V2INT = {'md5': 1, 'sha1': 2, 'sha256': 12, 'sha384': 13, 'sha512': 14}
V2PRF = {'md5': 1, 'sha1': 2, 'sha256': 5, 'sha384': 6, 'sha512': 7}
ENC1 = {'3des': 5, 'aes-cbc': 7}
HASH1 = {'md5': 1, 'sha1': 2, 'sha256': 4, 'sha384': 5, 'sha512': 6}
AUTH1 = {'psk': 1, 'rsa': 3}
HLEN = {'md5': 16, 'sha1': 20, 'sha256': 32, 'sha384': 48, 'sha512': 64}
CIPH = {'aes-cbc': (16, 16), '3des': (8, 8), 'aes-gcm': (8, 4)}  # iv, block
ICVL = {'md5': 12, 'sha1': 12, 'sha256': 16, 'sha384': 24, 'sha512': 32}
STRONG = dict(encr='aes-cbc', bits=256, integ='sha256', prf='sha256', dh='modp2048')
WEAK = dict(encr='3des', bits=None, integ='md5', prf='md5', dh='modp768')
VID_NATT = bytes.fromhex('4a131c81070358455c5728f20e95452f')
VID_DPD = bytes.fromhex('afcad71368a1f1c96b8696fc77570100')


def chain(pls):
    out = b''
    for i, (t, b) in enumerate(pls):
        nx = pls[i + 1][0] if i + 1 < len(pls) else 0
        out += struct.pack('!BBH', nx, 0, 4 + len(b)) + b
    return pls[0][0], out


def ceil_to(n, b):
    return ((n + b - 1) // b) * b


# ---------------------------------------------------------------- IKEv2
def v2_sa(offers):
    props = b''
    for i, o in enumerate(offers):
        tf = [(1, V2ENC[o['encr']], o.get('bits'))]
        tf.append((2, V2PRF[o['prf']], None))
        if o['encr'] != 'aes-gcm':
            tf.append((3, V2INT[o['integ']], None))
        tf.append((4, DH[o['dh']], None))
        tb = b''
        for j, (tt, tid, kl) in enumerate(tf):
            at = struct.pack('!HH', 0x800E, kl) if kl else b''
            tb += struct.pack('!BBHBBH', 0 if j == len(tf) - 1 else 3, 0, 8 + len(at), tt, 0, tid) + at
        props += struct.pack('!BBHBBBB', 0 if i == len(offers) - 1 else 2, 0, 8 + len(tb), i + 1, 1, 0, len(tf)) + tb
    return props


class IKE2:
    first_child_in_init = True

    def __init__(s, cfg, r, pk):
        s.c, s.r, s.pk = cfg, r, pk
        s.ispi, s.rspi, s.mid = rb(r, 8), rb(r, 8), 0

    def rtt(s):
        return s.r.uniform(0.008, 0.03)

    def emit(s, t, d, msg, init=False):
        c = s.c
        if c['natt'] and not init:
            pl, port = b'\0' * 4 + msg, 4500
        else:
            pl, port = msg, 500
        s.pk.append((t, udp_frame(d, c['v6'], port, port, pl), 'ike'))

    def hdr(s, nxt, exch, sender, resp, mid, body, zero_r=False):
        fl = (0x08 if sender == 0 else 0) | (0x20 if resp else 0)
        return struct.pack('!8s8sBBBBII', s.ispi, b'\0' * 8 if zero_r else s.rspi, nxt, 0x20, exch, fl, mid, 28 + len(body)) + body

    def sk(s, plain, inner):
        ike = s.c['ikec']
        iv, blk = CIPH[ike['encr']]
        ct = ceil_to(plain + 1, blk)
        icv = 16 if ike['encr'] == 'aes-gcm' else ICVL[ike['integ']]
        body = rnd(iv + ct + icv)
        return struct.pack('!BBH', inner, 0, 4 + len(body)) + body

    def exch(s, t, exch_type, plain, inner, d=0, plain_r=None):
        mid = s.mid
        s.mid += 1
        s.emit(t, d, s.hdr(46, exch_type, d, False, mid, s.sk(plain, inner)))
        t2 = t + s.rtt()
        s.emit(t2, 1 - d, s.hdr(46, exch_type, d, True, mid, s.sk(plain_r or plain, inner)))
        return t2

    def init(s, t):
        c, r = s.c, s.r
        ike = c['ikec']
        dh = DH[ike['dh']]
        offers = [ike] + [o for o in c.get('extra_offers', [STRONG]) if o != ike]
        natd = [(41, struct.pack('!BBH', 0, 0, 16388) + rb(r, 20)), (41, struct.pack('!BBH', 0, 0, 16389) + rb(r, 20))]
        frag = (41, struct.pack('!BBH', 0, 0, 16430))
        ke = (34, struct.pack('!HH', dh, 0) + rb(r, KS[dh]))
        nx, body = chain([(33, v2_sa(offers)), ke, (40, rb(r, 32))] + natd + [frag])
        s.emit(t, 0, s.hdr(nx, 34, 0, False, 0, body, zero_r=True), init=True)
        t += s.rtt()
        nx, body = chain([(33, v2_sa([ike])), ke, (40, rb(r, 32))] + natd + [frag])
        s.emit(t, 1, s.hdr(nx, 34, 0, True, 0, body), init=True)
        s.mid = 1
        t += s.rtt()
        base = 230 if c['auth'] == 'psk' else 1150
        t = s.exch(t, 35, base + r.randint(0, 60), 35, plain_r=base + r.randint(0, 60))
        return t

    def child(s, t, rekey=False):
        c = s.c
        plain = 170 + (4 + KS[DH[c['pfs']]] if c.get('pfs') else 0)
        return s.exch(t, 36, plain, 33)

    def dpd(s, t, d):
        return s.exch(t, 37, 0, 0, d=d)

    def delete(s, t):
        return s.exch(t, 37, 12, 42)


# ---------------------------------------------------------------- IKEv1
def v1a(t, v):
    return struct.pack('!HH', 0x8000 | t, v)


class IKE1:
    first_child_in_init = False

    def __init__(s, cfg, r, pk):
        s.c, s.r, s.pk = cfg, r, pk
        s.ispi, s.rspi = rb(r, 8), rb(r, 8)

    def rtt(s):
        return s.r.uniform(0.008, 0.03)

    def emit(s, t, d, msg, init=False):
        c = s.c
        if c['natt'] and not init:
            pl, port = b'\0' * 4 + msg, 4500
        else:
            pl, port = msg, 500
        s.pk.append((t, udp_frame(d, c['v6'], port, port, pl), 'ike'))

    def hdr(s, nxt, exch, flags, mid, body, zero_r=False):
        return struct.pack('!8s8sBBBBII', s.ispi, b'\0' * 8 if zero_r else s.rspi, nxt, 0x10, exch, flags, mid, 28 + len(body)) + body

    def sa(s, trs):
        c = s.c
        tb = b''
        for i, tr in enumerate(trs):
            at = v1a(1, ENC1[tr['encr']]) + v1a(2, HASH1[tr['prf']]) + v1a(3, AUTH1[c['auth']]) + v1a(4, DH[tr['dh']]) \
                + v1a(11, 1) + struct.pack('!HHI', 12, 4, c.get('ikelife', 86400))
            if tr['encr'] == 'aes-cbc':
                at += v1a(14, tr['bits'])
            tb += struct.pack('!BBHBBH', 0 if i == len(trs) - 1 else 3, 0, 8 + len(at), i + 1, 1, 0) + at
        prop = struct.pack('!BBHBBBB', 0, 0, 8 + len(tb), 1, 1, 0, len(trs)) + tb
        return struct.pack('!II', 1, 1) + prop

    def encb(s, n):
        blk = CIPH[s.c['ikec']['encr']][1]
        return rnd(ceil_to(n, blk))

    def init(s, t):
        c, r = s.c, s.r
        ike = c['ikec']
        ks = KS[DH[ike['dh']]]
        offers = [ike] + [o for o in c.get('extra_offers', [STRONG]) if o != ike]
        vids = [(13, VID_DPD)] + ([(13, VID_NATT)] if c['natt'] else [])
        hl = HLEN[ike['prf']]
        idp = (5, struct.pack('!BBH', 1, 0, 0) + socket.inet_aton('203.0.113.10'))
        if c['mode1'] == 'main':
            nx, b = chain([(1, s.sa(offers))] + vids)
            s.emit(t, 0, s.hdr(nx, 2, 0, 0, b, zero_r=True), init=True); t += s.rtt()
            nx, b = chain([(1, s.sa([ike])), vids[0]])
            s.emit(t, 1, s.hdr(nx, 2, 0, 0, b), init=True); t += s.rtt()
            nat = [(20, rb(r, 20)), (20, rb(r, 20))] if c['natt'] else []
            for d in (0, 1):
                nx, b = chain([(4, rb(r, ks)), (10, rb(r, 20))] + nat)
                s.emit(t, d, s.hdr(nx, 2, 0, 0, b), init=True); t += s.rtt()
            n5 = 12 + 4 + hl + 4 if c['auth'] == 'psk' else 1250
            for d in (0, 1):
                s.emit(t, d, s.hdr(5, 2, 1, 0, s.encb(n5 + r.randint(0, 40)))); t += s.rtt()
        else:  # aggressive mode
            nx, b = chain([(1, s.sa(offers)), (4, rb(r, ks)), (10, rb(r, 20)), idp] + vids)
            s.emit(t, 0, s.hdr(nx, 4, 0, 0, b, zero_r=True), init=True); t += s.rtt()
            nx, b = chain([(1, s.sa([ike])), (4, rb(r, ks)), (10, rb(r, 20)), idp, (8, rb(r, hl)), vids[0]])
            s.emit(t, 1, s.hdr(nx, 4, 0, 0, b), init=True); t += s.rtt()
            nx, b = chain([(8, rb(r, hl))])
            s.emit(t, 0, s.hdr(nx, 4, 0, 0, b)); t += s.rtt()
        return t

    def child(s, t, rekey=False):
        c, r = s.c, s.r
        mid = r.getrandbits(32) or 1
        ks = KS[DH[c['pfs']]] if c.get('pfs') else 0
        n1 = 24 + 60 + 24 + 2 * 16 + (4 + ks if ks else 0)
        for d, n in ((0, n1), (1, n1 - 8), (0, 24)):
            s.emit(t, d, s.hdr(8, 32, 1, mid, s.encb(n))); t += s.rtt()
        return t

    def dpd(s, t, d):
        mid = s.r.getrandbits(32) or 1
        s.emit(t, d, s.hdr(8, 5, 1, mid, s.encb(84)))
        t += s.rtt()
        s.emit(t, 1 - d, s.hdr(8, 5, 1, mid, s.encb(84)))
        return t

    def delete(s, t):
        mid = s.r.getrandbits(32) or 1
        s.emit(t, 0, s.hdr(8, 5, 1, mid, s.encb(64)))
        return t


# ---------------------------------------------------------------- traffic profiles (dt, dir, ip_len); dir 0 = A->B
def ackl(v6):
    return 72 if v6 else 52


def p_voip(r, v6):
    s = 160 + 12 + 8 + (40 if v6 else 20)
    while True:
        yield (0.02 + r.uniform(-0.002, 0.002), 0, s)
        yield (r.uniform(0.0005, 0.004), 1, s)
        if r.random() < 0.005:
            yield (0.0, 0, (40 if v6 else 20) + 8 + r.randint(60, 100))


def p_web(r, v6):
    while True:
        yield (r.expovariate(1 / 1.5), 0, r.randint(350, 900))
        for i in range(min(int(r.paretovariate(1.2) * 10), 500)):
            yield (r.uniform(0.0003, 0.004), 1, 1400 if r.random() < 0.85 else r.randint(120, 1400))
            if i % 2:
                yield (0.0002, 0, ackl(v6))


def p_email(r, v6):
    while True:
        yield (r.expovariate(1 / 6), 0, r.randint(70, 200))
        for _ in range(r.randint(4, 10)):
            yield (r.uniform(0.01, 0.05), r.randint(0, 1), r.randint(70, 300))
        d = r.randint(0, 1)
        for i in range(r.randint(20, 600)):
            yield (r.uniform(0.0005, 0.003), d, 1400 if r.random() < 0.9 else r.randint(100, 1400))
            if i % 2:
                yield (0.0002, 1 - d, ackl(v6))


def p_video(r, v6):
    while True:
        yield (r.uniform(2, 6), 0, r.randint(380, 520))
        for i in range(r.randint(300, 900)):
            yield (r.uniform(0.0004, 0.002), 1, 1400)
            if i % 2:
                yield (0.0001, 0, ackl(v6))


def p_icmp(r, v6):
    h = 40 if v6 else 20
    while True:
        sz = r.choice([56, 56, 56, 120, 248, 504, 1000, 1372]) + 8 + h
        yield (0.2, 0, sz)
        yield (r.uniform(0.0003, 0.003), 1, sz)


def p_wa(r, v6):
    h = 40 if v6 else 20
    while True:
        m = r.random()
        yield (r.expovariate(1 / 6), r.randint(0, 1), r.randint(90, 220))
        if m < 0.55:
            for _ in range(r.randint(1, 4)):
                yield (r.uniform(0.05, 0.6), r.randint(0, 1), r.randint(90, 240))
        elif m < 0.8:
            d = r.randint(0, 1)
            for _ in range(r.randint(25, 80)):
                yield (r.uniform(0.02, 0.06), d, r.randint(100, 140) + h)
        elif m < 0.95:
            d = r.randint(0, 1)
            for _ in range(r.randint(30, 250)):
                yield (r.uniform(0.0005, 0.003), d, 1400 if r.random() < 0.9 else r.randint(100, 1400))
        else:
            yield (r.uniform(20, 30), 0, 50 + h)
            yield (0.03, 1, 50 + h)


PROF = {'voip': p_voip, 'web': p_web, 'email': p_email, 'video': p_video, 'icmp': p_icmp, 'whatsapp': p_wa}


# ---------------------------------------------------------------- framing
def hl_of(c):
    return 40 if c['v6'] else 20


def icv_len(c):
    return 16 if c['encr'] == 'aes-gcm' else ICVL[c['integ']]


def esp_len(c, ip_len):
    inner = ip_len if c['mode'] == 'tunnel' else ip_len - hl_of(c)
    iv, blk = CIPH[c['encr']]
    return 8 + iv + ceil_to(inner + 2, blk) + icv_len(c)


def flen(c, ip_len, label=None):
    p = c.get('proto', 'esp')
    if p == 'plain':
        return 14 + ip_len
    if p == 'ah':
        return 14 + 20 + 24 + (ip_len if c['modes'][label] == 'tunnel' else ip_len - 20)
    return 14 + hl_of(c) + (8 if c['natt'] else 0) + esp_len(c, ip_len)


def gen_events(c, r):
    ev = []
    for label, mb in c['traffic'].items():
        k = c.get('streams', 3)
        per = mb * 1e6 / k
        for _ in range(k):
            t, used = r.uniform(3, 40), 0
            for dt, d, ipl in PROF[label](r, c['v6']):
                t += dt
                while flen(c, ipl, label) > 1514:
                    ipl -= 8
                used += flen(c, ipl, label)
                ev.append((t, label, d, ipl))
                if used >= per:
                    break
    ev.sort()
    return ev


def esp_frame(c, d, spi, seq, ip_len):
    body = struct.pack('!II', spi, seq) + rnd(esp_len(c, ip_len) - 8)
    if c['natt']:
        return udp_frame(d, False, 4500, 4500, body)
    return outer(d, c['v6'], 50, body)


def ah_frame(c, d, label, spi, seq, ip_len):
    tunnel = c['modes'][label] == 'tunnel'
    sp, dp = (16384 + 2 * (d), 16384) if label == 'voip' else (443, 50000)
    sa_, da_ = (INNER if d == 0 else INNER[::-1])
    if tunnel:
        inner, nxt = ip4(sa_, da_, 17, udp(sp, dp, rnd(ip_len - 28))), 4
    else:
        inner, nxt = udp(sp, dp, rnd(ip_len - 28)), 17
    ah = struct.pack('!BBHII', nxt, 4, 0, spi, seq) + rnd(12)
    return outer(d, False, 51, ah + inner)


def write_pcap(path, pk):
    pk.sort(key=lambda x: x[0])
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for t, fr, _ in pk:
            s = int(t)
            f.write(struct.pack('<IIII', s, int((t - s) * 1e6), len(fr), len(fr)))
            f.write(fr)


def finalize(c):
    if 'ikec' not in c and c.get('proto') != 'plain':
        g = c['encr'] == 'aes-gcm'
        c['ikec'] = dict(encr=c['encr'], bits=c.get('bits'), integ=c.get('integ', 'sha256'),
                         prf=c.get('prf', 'sha256'), dh=c['dh'])
        if g:
            c['ikec']['integ'] = 'sha256'
    c.setdefault('natt', False)
    c.setdefault('encr', None)
    c.setdefault('auth', 'psk')
    c.setdefault('mode1', 'main')
    return c


# ---------------------------------------------------------------- builders
def build_ipsec(c):
    r = random.Random(c['seed'])
    pk = []
    labels = list(c['traffic'])
    ev = gen_events(c, r)
    tmin, tmax = ev[0][0], ev[-1][0]
    nr = c.get('rekeys', 0)
    rk = [tmin + (tmax - tmin) * (i + 1) / (nr + 1) for i in range(nr)]
    ike = IKE2(c, r, pk) if c['ike'] == 2 else IKE1(c, r, pk)
    t = ike.init(0.5)
    start = 1 if ike.first_child_in_init else 0
    for _ in labels[start:]:
        t = ike.child(t + 0.01)
    for tr in rk:
        for j, _ in enumerate(labels):
            tt = tr + 0.05 * j
            ike.child(tt, rekey=True)
            ike.delete(tt + 0.2)
    n = 0
    tt = tmin + 30
    while tt < tmax and n < 300:
        ike.dpd(tt, n % 2)
        tt += 30
        n += 1
    if c['natt']:
        tt = 1.0
        while tt < tmax and n < 900:
            pk.append((tt, udp_frame(0, False, 4500, 4500, b'\xff'), 'keepalive'))
            tt += 20
            n += 1
    spis, seqs, spi_map = {}, {}, []

    def spi(label, ep, d):
        k = (label, ep, d)
        if k not in spis:
            spis[k] = r.randint(0x100, 0xfffffff0)
            spi_map.append(dict(spi='0x%08x' % spis[k], traffic=label, direction='A->B' if d == 0 else 'B->A', epoch=ep))
        return spis[k]

    dup = c.get('replay_dup', 0)
    for t, label, d, ipl in ev:
        ep = bisect.bisect_right(rk, t)
        k = (label, ep, d)
        s_ = spi(label, ep, d)
        seqs[k] = seqs.get(k, 0) + 1
        fr = esp_frame(c, d, s_, seqs[k], ipl)
        pk.append((T0 + t, fr, 'esp'))
        if dup and r.random() < dup:
            pk.append((T0 + t + r.uniform(0.001, 0.3), fr, 'esp'))
    pk = [(T0 + x[0], x[1], x[2]) if x[2] in ('ike', 'keepalive') else x for x in pk]
    return pk, spi_map, dict(rekey_events=nr, observed_duration_s=round(tmax - tmin, 1))


def build_ah(c):
    r = random.Random(c['seed'])
    pk = []
    ev = gen_events(c, r)
    ike = IKE2(c, r, pk)
    t = ike.init(0.5)
    ike.child(t + 0.01)
    spis, seqs, spi_map = {}, {}, []
    out = []
    for t, label, d, ipl in ev:
        k = (label, d)
        if k not in spis:
            spis[k] = r.randint(0x100, 0xfffffff0)
            spi_map.append(dict(spi='0x%08x' % spis[k], traffic=label, direction='A->B' if d == 0 else 'B->A',
                                mode=c['modes'][label]))
        seqs[k] = seqs.get(k, 0) + 1
        out.append((T0 + t, ah_frame(c, d, label, spis[k], seqs[k], ipl), 'ah'))
    pk = [(T0 + x[0], x[1], x[2]) for x in pk] + out
    return pk, spi_map, {}


def build_plain(c):
    r = random.Random(c['seed'])
    ev = gen_events(c, r)
    pk = []
    a, b = ADDR[c['v6']]
    for t, label, d, ipl in ev:
        s, dd = (a, b) if d == 0 else (b, a)
        hl = hl_of(c)
        if label == 'icmp' and not c['v6']:
            ic = struct.pack('!BBHHH', 8 if d == 0 else 0, 0, 0, 1, 1) + rnd(ipl - 28)
            ic = ic[:2] + struct.pack('!H', csum(ic)) + ic[4:]
            fr = eth(d, 0x0800, ip4(s, dd, 1, ic))
        else:
            sp, dp = {'voip': (16384, 16384), 'web': (443, 51000), 'video': (443, 52000)}.get(label, (5222, 50100))
            if d:
                sp, dp = dp, sp
            u = udp(sp, dp, rnd(ipl - hl - 8), s, dd, c['v6'])
            fr = eth(d, 0x86DD if c['v6'] else 0x0800, ip6(s, dd, 17, u) if c['v6'] else ip4(s, dd, 17, u))
        pk.append((T0 + t, fr, 'other'))
    tmax = ev[-1][0]
    for _ in range(300):  # decoys: random data on UDP 500/4500 (not IKE)
        dp = r.choice([500, 4500])
        pk.append((T0 + r.uniform(3, tmax), udp_frame(r.randint(0, 1), False, dp, dp, rnd(r.randint(40, 300))), 'decoy'))
    return pk, [], {'decoy_packets': 300}


# ---------------------------------------------------------------- scenarios
def S(**k):
    return k


SCEN = [
    S(id='01', slug='tunnel_ikev2_aes128cbc_sha256_modp2048_pfs_ipv4_voip', ike=2, mode='tunnel', v6=False,
      encr='aes-cbc', bits=128, integ='sha256', dh='modp2048', pfs='modp2048', traffic={'voip': 25}, seed=1,
      ikelife=86400, childlife=3600,
      expect='Good: AES-128-CBC+HMAC-SHA256, DH14, PFS on. Note: 2048-bit MODP acceptable, ECP preferable.'),
    S(id='02', slug='tunnel_ikev2_aes256gcm_ecp256_pfs_ipv4_web_cert', ike=2, mode='tunnel', v6=False,
      encr='aes-gcm', bits=256, dh='ecp256', pfs='ecp256', auth='cert', traffic={'web': 60}, seed=2,
      expect='Strong: AES-256-GCM, ECP-256, PFS, cert auth.'),
    S(id='03', slug='transport_ikev2_aes256gcm_modp2048_nopfs_ipv4_email', ike=2, mode='transport', v6=False,
      encr='aes-gcm', bits=256, dh='modp2048', pfs=None, traffic={'email': 25}, seed=3,
      expect='Transport mode host-to-host; PFS disabled -> forward secrecy finding.'),
    S(id='04', slug='tunnel_ikev2_aes128gcm_curve25519_pfs_ipv6_video', ike=2, mode='tunnel', v6=True,
      encr='aes-gcm', bits=128, dh='curve25519', pfs='curve25519', traffic={'video': 110}, seed=4,
      expect='Strong modern suite over IPv6; streaming-video traffic.'),
    S(id='05', slug='transport_ikev1_main_aes128cbc_sha1_modp1024_nopfs_ipv4_icmp', ike=1, mode='transport', v6=False,
      encr='aes-cbc', bits=128, integ='sha1', prf='sha1', dh='modp1024', pfs=None, traffic={'icmp': 8}, seed=5,
      mode1='main', auth='psk', ikelife=28800, childlife=3600, streams=4,
      expect='IKEv1 main mode, DH group 2 (1024-bit) weak, SHA1, no PFS -> medium/high risk.'),
    S(id='06', slug='tunnel_ikev2_aes256cbc_sha384_ecp384_pfs_ipv6_whatsapp', ike=2, mode='tunnel', v6=True,
      encr='aes-cbc', bits=256, integ='sha384', prf='sha384', dh='ecp384', pfs='ecp384', traffic={'whatsapp': 35}, seed=6,
      expect='Strong (Suite-B-like). Messaging-app traffic pattern.'),
    S(id='07', slug='tunnel_ikev2_natt_aes256cbc_sha256_modp3072_pfs_ipv4_web', ike=2, mode='tunnel', v6=False, natt=True,
      encr='aes-cbc', bits=256, integ='sha256', dh='modp3072', pfs='modp3072', traffic={'web': 40}, seed=7,
      expect='ESP-in-UDP/4500 NAT-T, keepalives, IKE moves 500->4500 with non-ESP marker.'),
    S(id='08', slug='tunnel_ikev1_aggressive_3des_md5_modp768_nopfs_ipv4_web_weak', ike=1, mode='tunnel', v6=False,
      encr='3des', bits=None, integ='md5', prf='md5', dh='modp768', pfs=None, traffic={'web': 20}, seed=8,
      mode1='aggr', auth='psk', ikelife=3600, childlife=600, replay_dup=0.003, extra_offers=[WEAK],
      expect='CRITICAL: 3DES, MD5, 768-bit DH, aggressive mode PSK (offline crack), no PFS, short lifetimes, duplicate ESP seq (replay) injected ~0.3%.'),
    S(id='09', slug='tunnel_ikev2_aes256gcm_ecp384_pfs_ipv4_mixed_multiSA_rekey', ike=2, mode='tunnel', v6=False,
      encr='aes-gcm', bits=256, dh='ecp384', pfs='ecp384',
      traffic={'voip': 8, 'web': 20, 'video': 30, 'whatsapp': 10, 'email': 8, 'icmp': 4}, seed=9, rekeys=3, streams=2,
      expect='6 child SAs (one per traffic class), 3 rekey rounds w/ new SPIs; use spi_map for traffic-type accuracy.'),
    S(id='10', slug='ah_ikev2_tunnel_voip_transport_web_ipv4', proto='ah', ike=2, v6=False, natt=False,
      encr='aes-cbc', bits=256, integ='sha256', dh='modp2048', pfs=None, modes={'voip': 'tunnel', 'web': 'transport'},
      traffic={'voip': 8, 'web': 7}, seed=10,
      expect='AH (proto 51, HMAC-SHA1-96 ICV 12B): no confidentiality, payload/metadata fully exposed.'),
    S(id='11', slug='non_ipsec_baseline_with_decoys', proto='plain', v6=False, mode='plain',
      traffic={'voip': 4, 'web': 5, 'icmp': 2, 'whatsapp': 4}, seed=11, streams=2,
      expect='NO IPsec. Negative control: plain UDP/ICMP + 300 random-payload decoys on UDP 500/4500. Should yield 0 IPsec detections.'),
    S(id='12', slug='transport_ikev1_main_aes256cbc_sha256_modp2048_pfs_rsasig_ipv6_voip', ike=1, mode='transport', v6=True,
      encr='aes-cbc', bits=256, integ='sha256', prf='sha256', dh='modp2048', pfs='modp2048', auth='rsa', mode1='main',
      traffic={'voip': 20}, seed=12, ikelife=28800, childlife=3600,
      expect='IKEv1 main mode RSA-sig over IPv6, transport mode, PFS on. Acceptable/legacy.'),
]


def main():
    manifest = []
    for c in SCEN:
        finalize(c)
        proto = c.get('proto', 'esp')
        pk, spi_map, extra = (build_ah if proto == 'ah' else build_plain if proto == 'plain' else build_ipsec)(c)
        fn = 'ipsec_%s_%s.pcap' % (c['id'], c['slug']) if proto != 'plain' else 'ipsec_%s_%s.pcap' % (c['id'], c['slug'])
        path = os.path.join(OUT, fn)
        write_pcap(path, pk)
        kinds = {}
        for _, _, k in pk:
            kinds[k] = kinds.get(k, 0) + 1
        h = hashlib.sha256(open(path, 'rb').read()).hexdigest()
        ike = c.get('ikec')
        entry = dict(
            file=fn, size_mb=round(os.path.getsize(path) / 1e6, 1), packets=len(pk), packet_kinds=kinds, sha256=h,
            ground_truth=dict(
                ipsec=proto != 'plain',
                protocol={'esp': 'ESP', 'ah': 'AH', 'plain': None}[proto] if proto != 'esp' or True else None,
                ike_version=None if proto == 'plain' else ('IKEv%d' % c['ike']),
                ikev1_mode=c['mode1'] if c.get('ike') == 1 else None,
                ipsec_mode=None if proto == 'plain' else (c['mode'] if proto == 'esp' else c['modes']),
                ip_version=6 if c['v6'] else 4,
                nat_t=c['natt'],
                ike_sa=None if proto == 'plain' else dict(ike, dh_group=DH[ike['dh']]),
                esp_encryption=None if proto != 'esp' else dict(alg=c['encr'], key_bits=c.get('bits')),
                esp_integrity='aead' if (proto == 'esp' and c['encr'] == 'aes-gcm') else (c.get('integ') if proto == 'esp' else 'hmac-sha1-96 (AH)' if proto == 'ah' else None),
                pfs=None if proto == 'plain' else (c.get('pfs') or 'disabled'),
                auth_method=None if proto == 'plain' else c['auth'],
                ike_sa_lifetime_s=c.get('ikelife') if c.get('ike') == 1 else 'n/a (IKEv2 not negotiated in clear)',
                traffic_types=list(c['traffic']),
                spi_map=spi_map, **extra),
            expected_assessment=c['expect'])
        manifest.append(entry)
        print(fn, entry['size_mb'], 'MB', len(pk), 'pkts', kinds, flush=True)
    json.dump(dict(generated_by='gen_ipsec_pcaps.py', note='Synthetic data: ESP ciphertext is random; IKE structure is valid. Mode/cipher/traffic type must be inferred from sizes, IV/ICV/padding, timing, and IKE cleartext.',
                   captures=manifest), open(os.path.join(OUT, 'ground_truth_manifest.json'), 'w'), indent=1)
    print('total MB', round(sum(m['size_mb'] for m in manifest), 1))


main()
