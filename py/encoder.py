import numpy as np

from utils import lit2i, big2i, i2big, i2lit, ip2str, b2str
from const import EtherType, IpType
from collections import defaultdict, Counter


class Context:
    def __init__(self):
        self.ts = 0

        self.ip_len = defaultdict(lambda: 0)
        self.ip_id = defaultdict(lambda: 0)
        self.ip_ttl = defaultdict(lambda: 0)
        self.ip_cs = defaultdict(lambda: 0)

        self.tcp_seq = defaultdict(lambda: 0)
        self.tcp_ack = defaultdict(lambda: 0)
        self.tcp_win = defaultdict(lambda: 0)
        self.tcp_ts = defaultdict(lambda: 0)


class Rules:
    PCAP_TS_DIFF = True
    PCAP_TS_INV = True

    IP_LEN_DIFF = False
    IP_ID_DIFF = True
    IP_TTL_DIFF = False
    IP_CS_DIFF = False
    IP_CS_CALC = True

    TCP_SEQACK_DIFF = True
    TCP_WIN_DIFF = True
    TCP_TS_DIFF = True

    COMBINE_ADDR = True


class Encoder:
    def __init__(self):
        self.ctx = Context()
        self.p = None
        self.n_packets = 0

    def process(self, p):
        self.n_packets += 1
        self.p = bytearray(p)
        ts = lit2i(p[0:4]) * 2**32 + lit2i(p[4:8])
        cpl = lit2i(p[8:12])
        opl = lit2i(p[12:16])

        # Pcap
        if Rules.PCAP_TS_DIFF:
            d = ts - self.ctx.ts
            self.ctx.ts = ts
            self.p[:8] = i2big(d, 8)

        if Rules.PCAP_TS_INV:
            self.p[:8] = self.p[:8][::-1]

        eth_off = 16

        # Eth
        eth_dst = p[eth_off+0:eth_off+6]
        eth_src = p[eth_off+6:eth_off+12]
        ip_off = eth_off + 14
        ether_type = p[ip_off-2:ip_off]
        if ether_type == EtherType.VLAN:
            ip_off += 4
            ether_type = p[ip_off-2:ip_off]
        ether_type = big2i(ether_type)

        # IP
        if ether_type == EtherType.IPv4:
            ip_ihl = p[ip_off] % 16
            tl_off = ip_off + 4 * ip_ihl
            ip_proto = p[ip_off+9]

            ip_len = big2i(p[ip_off+2:ip_off+4])
            ip_id = big2i(p[ip_off+4:ip_off+6])
            ip_ttl = p[ip_off+8]
            ip_cs = big2i(p[ip_off+10:ip_off+12])

            ip_src = p[ip_off+12:ip_off+16]
            ip_dst = p[ip_off+16:ip_off+20]

            if Rules.IP_LEN_DIFF:
                d = ip_len - self.ctx.ip_len[ip_src]
                self.ctx.ip_len[ip_src] = ip_len
                self.p[ip_off+2:ip_off+4] = i2big(d, 2)

            if Rules.IP_ID_DIFF:
                d = ip_id - self.ctx.ip_id[ip_src]
                self.ctx.ip_id[ip_src] = ip_id
                self.p[ip_off+4:ip_off+6] = i2big(d, 2)

            if Rules.IP_TTL_DIFF:
                d = ip_ttl - self.ctx.ip_ttl[ip_src]
                self.ctx.ip_ttl[ip_src] = ip_ttl
                self.p[ip_off+8:ip_off+9] = i2big(d, 1)

            if Rules.IP_CS_DIFF:
                d = ip_cs - self.ctx.ip_cs[ip_src]
                self.ctx.ip_cs[ip_src] = ip_cs
                self.p[ip_off+10:ip_off+12] = i2big(d, 2)

            if Rules.IP_CS_CALC:
                cs = 0
                for i in range(ip_off, tl_off, 2):
                    if i == ip_off + 10:
                        continue
                    cs += big2i(p[i:i+2])
                while cs > 0xffff:
                    cs = (cs // 2**16) + (cs % 2**16)

                self.p[ip_off+10:ip_off+12] = i2big(ip_cs + cs, 2)

            if ip_proto == IpType.TCP:
                payload_off = tl_off + 4 * (p[tl_off+12] // 16)
                tcp_src = p[tl_off:tl_off+2]
                tcp_dst = p[tl_off+2:tl_off+4]
                tcp_seq = big2i(p[tl_off+4:tl_off+8])
                tcp_ack = big2i(p[tl_off+8:tl_off+12])
                tcp_win = big2i(p[tl_off+14:tl_off+16])
                tcp_opt = p[tl_off+20:payload_off]

                session = (ip_src, ip_dst, ip_proto,
                           tcp_src, tcp_dst)

                if Rules.TCP_SEQACK_DIFF:
                    d = tcp_seq - self.ctx.tcp_seq[session]
                    self.ctx.tcp_seq[session] = tcp_seq
                    self.p[tl_off+4:tl_off+8] = i2big(d, 4)

                    d = tcp_ack - self.ctx.tcp_ack[session]
                    self.ctx.tcp_ack[session] = tcp_ack
                    self.p[tl_off+8:tl_off+12] = i2big(d, 4)

                if Rules.TCP_WIN_DIFF:
                    d = tcp_win - self.ctx.tcp_win[session]
                    self.ctx.tcp_win[session] = tcp_win
                    self.p[tl_off+14:tl_off+16] = i2big(d, 2)

                if Rules.TCP_TS_DIFF:
                    i = tl_off + 20
                    while i < payload_off:
                        opt_kind = p[i]
                        match opt_kind:
                            case 0: i += 1
                            case 1: i += 1
                            case 2: i += 4
                            case 3: i += 3
                            case 4: i += 2
                            case 5: i += p[i+1]
                            case 8:
                                tcp_ts = big2i(p[i+2:i+10])
                                d = tcp_ts - self.ctx.tcp_ts[session]
                                self.ctx.tcp_ts[session] = tcp_ts
                                self.p[i+2:i+10] = i2big(d, 8)
                                i += 10
                            case _:
                                assert False, f'unknown case {opt_kind}'

                if Rules.COMBINE_ADDR:
                    self.p[eth_off+0:eth_off+6] = eth_src
                    self.p[eth_off+6:eth_off+10] = ip_src
                    self.p[eth_off+10:eth_off+12] = tcp_src
                    self.p[ip_off+12:ip_off+18] = eth_dst
                    self.p[ip_off+18:tl_off+2] = ip_dst
                    self.p[tl_off+2:tl_off+4] = tcp_dst

        return self.p
