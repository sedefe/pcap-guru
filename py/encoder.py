from utils import lit2i, big2i, i2big, i2lit, ip2str, b2str
from const import EtherType, IpType
from collections import defaultdict, Counter


class Context:
    def __init__(self):
        self.ts1 = 0
        self.ts2 = 0

        self.ip_len = defaultdict(lambda: 0)
        self.ip_id = defaultdict(lambda: 0)
        self.ip_ttl = defaultdict(lambda: 0)
        self.ip_cs = defaultdict(lambda: 0)

        self.tcp_seq = defaultdict(lambda: 0)
        self.tcp_ack = defaultdict(lambda: 0)
        self.tcp_win = defaultdict(lambda: 0)
        self.tcp_ts = defaultdict(lambda: 0)


class Rules:
    PCAP_TS1_DIFF = True
    PCAP_TS2_DIFF = True

    IP_LEN_DIFF = True
    IP_ID_DIFF = True
    IP_TTL_DIFF = True
    IP_CS_DIFF = True

    TCP_SEQACK_DIFF = True
    TCP_WIN_DIFF = True
    TCP_TS_DIFF = True


class Encoder:
    def __init__(self):
        self.ctx = Context()
        self.p = None

    def process(self, p):
        self.p = bytearray(p)
        ts1 = lit2i(p[0:4])
        ts2 = lit2i(p[4:8])
        cpl = lit2i(p[8:12])
        opl = lit2i(p[12:16])

        # Pcap
        if Rules.PCAP_TS1_DIFF:
            d1 = ts1 - self.ctx.ts1
            self.ctx.ts1 = ts1
            self.p[0:4] = i2lit(d1, 4)

        if Rules.PCAP_TS2_DIFF:
            d2 = ts2 - self.ctx.ts2
            self.ctx.ts2 = ts2
            self.p[4:8] = i2lit(d2, 4)

        eth_off = 16

        # Eth
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

            ip_srcaddr = p[ip_off+12:ip_off+16]
            ip_dstaddr = p[ip_off+16:ip_off+20]

            if Rules.IP_LEN_DIFF:
                d = ip_len - self.ctx.ip_len[ip_srcaddr]
                self.ctx.ip_len[ip_srcaddr] = ip_len
                self.p[ip_off+2:ip_off+4] = i2big(d, 2)

            if Rules.IP_ID_DIFF:
                d = ip_id - self.ctx.ip_id[ip_srcaddr]
                self.ctx.ip_id[ip_srcaddr] = ip_id
                self.p[ip_off+4:ip_off+6] = i2big(d, 2)

            if Rules.IP_TTL_DIFF:
                d = ip_ttl - self.ctx.ip_ttl[ip_srcaddr]
                self.ctx.ip_ttl[ip_srcaddr] = ip_ttl
                self.p[ip_off+8:ip_off+9] = i2big(d, 1)

            if Rules.IP_CS_DIFF:
                d = ip_cs - self.ctx.ip_cs[ip_srcaddr]
                self.ctx.ip_cs[ip_srcaddr] = ip_cs
                self.p[ip_off+10:ip_off+12] = i2big(d, 2)

            if ip_proto == IpType.TCP:
                payload_off = tl_off + 4 * (p[tl_off+12] // 16)
                tcp_srcport = p[tl_off:tl_off+2]
                tcp_drcport = p[tl_off+2:tl_off+4]
                tcp_seq = big2i(p[tl_off+4:tl_off+8])
                tcp_ack = big2i(p[tl_off+8:tl_off+12])
                tcp_win = big2i(p[tl_off+14:tl_off+16])
                tcp_opt = p[tl_off+20:payload_off]

                session = (ip_srcaddr, ip_dstaddr, ip_proto,
                           tcp_srcport, tcp_drcport)

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

        return self.p
