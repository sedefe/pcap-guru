import numpy as np

from utils import lit2i, big2i, i2big, i2lit, ip2str, b2str, shuffle
from const import EtherType, IpType
from collections import defaultdict, Counter


class Context:
    def __init__(self):
        self.n_total = 0
        self.s_total = 0
        self.n_ipv4 = 0
        self.s_ipv4 = 0
        self.n_tcp = 0
        self.s_tcp = 0
        self.s_tcp_pl = 0
        self.n_udp = 0
        self.s_udp = 0

        self.ts = 0

        self.ip_len = defaultdict(lambda: 0)
        self.ip_id = defaultdict(lambda: 0)
        self.ip_ttl = defaultdict(lambda: 0)
        self.ip_cs = defaultdict(lambda: 0)

        self.tcp_sessions = set()
        self.tcp_seq = defaultdict(lambda: 0)
        self.tcp_nseq = defaultdict(lambda: 0)
        self.tcp_ack = defaultdict(lambda: 0)
        self.tcp_win = defaultdict(lambda: 0)
        self.tcp_ts_val = defaultdict(lambda: 0)
        self.tcp_ts_ecr = defaultdict(lambda: 0)
        self.tcp_mss = defaultdict(lambda: 0)

        self.udp_sessions = set()

    def print_stat(self):
        print(f'Total {self.n_total} packets')
        print(f'=== IPv4 ===')
        print(
            f'packets: {self.n_ipv4 / self.n_total:7.2%}, size: {self.s_ipv4 / self.s_total:7.2%}')

        print(f'=== TCP ===')
        print(
            f'packets: {self.n_tcp / self.n_total:7.2%}, size: {self.s_tcp / self.s_total:7.2%}')
        print(f'payload: {self.s_tcp_pl / self.s_total:7.2%}')
        n_tcp_sessions = len(self.tcp_sessions)
        print(f'{n_tcp_sessions} sessions')
        print(
            f'avg: {self.s_tcp/n_tcp_sessions/1e3:.2f} KB in {self.n_tcp/n_tcp_sessions:.2f} packets')

        print(f'=== UDP ===')
        print(
            f'packets: {self.n_udp / self.n_total:7.2%}, size: {self.s_udp / self.s_total:7.2%}')
        n_udp_sessions = len(self.udp_sessions)
        print(f'{n_udp_sessions} sessions')
        print(
            f'avg: {self.s_udp/n_udp_sessions/1e3:.2f} KB in {self.n_udp/n_udp_sessions:.2f} packets')


class Rules:
    PCAP_TS_DIFF = True
    PCAP_TS_INV = True
    PCAP_OPL_DIFF = False

    IP_LEN_DIFF = False
    IP_LEN_PCAP_LEN = True
    IP_ID_DIFF = True
    IP_TTL_DIFF = False
    IP_CS_DIFF = False
    IP_CS_CALC = True

    TCP_SEQ_DIFF = False
    TCP_NSEQ_DIFF = True
    TCP_ACK_DIFF = True
    TCP_SEQACK_SHUFFLE = False
    TCP_WIN_DIFF = True
    TCP_OPT_TS_DIFF = True
    TCP_OPT_TS_DIFF_SHUFFLE = True
    TCP_OPT_SACK_DIFF = True
    TCP_OPT_MSS_DIFF = True
    TCP_COMBINE_ADDR = True
    TCP_CS_CALC = True
    TCP_CS_CALC_THD = 64

    UDP_LEN_PCAP_LEN = True
    UDP_COMBINE_ADDR = False
    UDP_CS_CALC = True
    UDP_CS_CALC_THD = 64


class Encoder:
    def __init__(self):
        self.ctx = Context()

    def process(self, p):
        p = bytearray(p)
        ts = lit2i(p[0:4]) * 2**32 + lit2i(p[4:8])
        cpl = lit2i(p[8:12])
        opl = lit2i(p[12:16])

        self.ctx.n_total += 1
        self.ctx.s_total += cpl

        # Pcap
        if Rules.PCAP_TS_DIFF:
            d = ts - self.ctx.ts
            self.ctx.ts = ts
            p[:8] = i2big(d, 8)

        if Rules.PCAP_TS_INV:
            p[:8] = p[:8][::-1]

        if Rules.PCAP_OPL_DIFF:
            p[12:16] = i2big(opl - cpl, 4)
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
            self.ctx.n_ipv4 += 1
            self.ctx.s_ipv4 += cpl

            ip_ihl = p[ip_off] % 16
            tl_off = ip_off + 4 * ip_ihl
            ip_proto = p[ip_off+9]

            ip_len = big2i(p[ip_off+2:ip_off+4])
            ip_id = big2i(p[ip_off+4:ip_off+6])
            ip_ttl = p[ip_off+8]
            ip_cs = big2i(p[ip_off+10:ip_off+12])

            ip_src = bytes(p[ip_off+12:ip_off+16])
            ip_dst = bytes(p[ip_off+16:ip_off+20])

            ip_pseudo_cs = sum([big2i(p[i:i+2])
                               for i in range(ip_off+12, ip_off+20, 2)])
            ip_pseudo_cs += ip_proto
            ip_pseudo_cs += ip_len - 4*ip_ihl

            def calc_tl_cs(start, end):
                cs_calc = ip_pseudo_cs
                for i in range(start, end-2, 2):
                    cs_calc += big2i(p[i:i+2])
                if (end % 2) == 0:
                    cs_calc += big2i(p[end-2:end])
                else:
                    cs_calc += p[end-1] * 256
                while cs_calc > 0xffff:
                    cs_calc = (cs_calc // 2 ** 16) + (cs_calc % 2**16)
                return cs_calc

            if Rules.IP_CS_CALC:  # must come first
                ip_cs_calc = 0
                for i in range(ip_off, tl_off, 2):
                    ip_cs_calc += big2i(p[i:i+2])
                while ip_cs_calc > 0xffff:
                    ip_cs_calc = (ip_cs_calc // 2**16) + (ip_cs_calc % 2**16)

                p[ip_off+10:ip_off+12] = i2big(ip_cs_calc, 2)

            if Rules.IP_LEN_DIFF:
                d = ip_len - self.ctx.ip_len[ip_src]
                self.ctx.ip_len[ip_src] = ip_len
                p[ip_off+2:ip_off+4] = i2big(d, 2)

            if Rules.IP_LEN_PCAP_LEN:
                d = cpl - ip_len
                p[ip_off+2:ip_off+4] = i2big(d, 2)

            if Rules.IP_ID_DIFF:
                d = ip_id - self.ctx.ip_id[ip_src]
                self.ctx.ip_id[ip_src] = ip_id
                p[ip_off+4:ip_off+6] = i2big(d, 2)

            if Rules.IP_TTL_DIFF:
                d = ip_ttl - self.ctx.ip_ttl[ip_src]
                self.ctx.ip_ttl[ip_src] = ip_ttl
                p[ip_off+8:ip_off+9] = i2big(d, 1)

            if Rules.IP_CS_DIFF:
                d = ip_cs - self.ctx.ip_cs[ip_src]
                self.ctx.ip_cs[ip_src] = ip_cs
                p[ip_off+10:ip_off+12] = i2big(d, 2)

            match ip_proto:
                case IpType.TCP:
                    self.ctx.n_tcp += 1
                    self.ctx.s_tcp += cpl

                    payload_off = tl_off + 4 * (p[tl_off+12] // 16)
                    padding_off = ip_off + ip_len

                    self.ctx.s_tcp_pl += padding_off - payload_off

                    tcp_src = bytes(p[tl_off:tl_off+2])
                    tcp_dst = bytes(p[tl_off+2:tl_off+4])
                    tcp_seq = big2i(p[tl_off+4:tl_off+8])
                    tcp_ack = big2i(p[tl_off+8:tl_off+12])
                    tcp_win = big2i(p[tl_off+14:tl_off+16])
                    tcp_flags = p[tl_off+13]
                    tcp_flag_syn = tcp_flags & 0x02
                    tcp_payload_len = padding_off - payload_off
                    if tcp_flag_syn:
                        tcp_payload_len = 1
                    # tcp_cs = big2i(p[tl_off+16:tl_off+18])
                    # tcp_opt = p[tl_off+20:payload_off]

                    session = (ip_src, ip_dst, ip_proto,
                               tcp_src, tcp_dst)
                    self.ctx.tcp_sessions.add(session)

                    if Rules.TCP_CS_CALC:  # must come first
                        if padding_off - payload_off <= Rules.TCP_CS_CALC_THD:
                            tcp_cs_calc = calc_tl_cs(tl_off, padding_off)
                            p[tl_off+16:tl_off+18] = i2big(tcp_cs_calc, 2)

                    if Rules.TCP_SEQ_DIFF:
                        d = tcp_seq - self.ctx.tcp_seq[session]
                        self.ctx.tcp_seq[session] = tcp_seq
                        p[tl_off+4:tl_off+8] = i2big(d, 4)

                    if Rules.TCP_NSEQ_DIFF:
                        d = tcp_seq - self.ctx.tcp_nseq[session]
                        self.ctx.tcp_nseq[session] = tcp_seq + tcp_payload_len
                        p[tl_off+4:tl_off+8] = i2big(d, 4)

                    if Rules.TCP_ACK_DIFF:
                        d = tcp_ack - self.ctx.tcp_ack[session]
                        self.ctx.tcp_ack[session] = tcp_ack
                        p[tl_off+8:tl_off+12] = i2big(d, 4)

                    if Rules.TCP_SEQACK_SHUFFLE:
                        p[tl_off+4:tl_off+12] = shuffle(p[tl_off+4:tl_off+12])

                    if Rules.TCP_WIN_DIFF:
                        d = tcp_win - self.ctx.tcp_win[session]
                        self.ctx.tcp_win[session] = tcp_win
                        p[tl_off+14:tl_off+16] = i2big(d, 2)

                    i = tl_off + 20
                    while i < payload_off:
                        opt_kind = p[i]
                        match opt_kind:
                            case 0: i += 1
                            case 1: i += 1
                            case 2:
                                if Rules.TCP_OPT_MSS_DIFF:
                                    mss = big2i(p[i+2:i+4])
                                    d = mss - self.ctx.tcp_mss[ip_src]
                                    self.ctx.tcp_mss[ip_src] = mss
                                    p[i+2:i+4] = i2big(d, 2)
                                i += 4
                            case 3: i += 3
                            case 4: i += 2
                            case 5:
                                if Rules.TCP_OPT_SACK_DIFF:
                                    for j in range(i+2, i+p[i+1], 8):
                                        sack_b = big2i(p[j+0:j+4])
                                        sack_e = big2i(p[j+4:j+8])
                                        p[j+0:j+4] = i2big(sack_b - tcp_ack, 4)
                                        p[j+4:j+8] = i2big(sack_e - sack_b, 4)
                                i += p[i+1]
                            case 8:
                                if Rules.TCP_OPT_TS_DIFF:
                                    tcp_ts_val = big2i(p[i+2:i+6])
                                    d = tcp_ts_val - \
                                        self.ctx.tcp_ts_val[session]
                                    self.ctx.tcp_ts_val[session] = tcp_ts_val
                                    p[i+2:i+6] = i2big(d, 4)

                                    tcp_ts_ecr = big2i(p[i+6:i+10])
                                    d = tcp_ts_ecr - \
                                        self.ctx.tcp_ts_ecr[session]
                                    self.ctx.tcp_ts_ecr[session] = tcp_ts_ecr
                                    p[i+6:i+10] = i2big(d, 4)

                                    if Rules.TCP_OPT_TS_DIFF_SHUFFLE:
                                        p[i+2:i+10] = shuffle(p[i+2:i+10])
                                i += 10
                            case _:
                                assert False, f'unknown case {opt_kind}'

                    if Rules.TCP_COMBINE_ADDR:
                        p[eth_off+0:eth_off+6] = eth_src
                        p[eth_off+6:eth_off+10] = ip_src
                        p[eth_off+10:eth_off+12] = tcp_src
                        p[ip_off+12:ip_off+18] = eth_dst
                        p[ip_off+18:tl_off+2] = ip_dst
                        p[tl_off+2:tl_off+4] = tcp_dst

                    # if tcp_flag_syn:
                    #     print(  # f'{b2str(p[16:ip_off])}|{b2str(p[ip_off:tl_off])}|'
                    #         f'{b2str(p[tl_off:tl_off+20])}|{b2str(p[tl_off+20:payload_off])}')

                case IpType.UDP:
                    self.ctx.n_udp += 1
                    self.ctx.s_udp += cpl

                    udp_src = bytes(p[tl_off:tl_off+2])
                    udp_dst = bytes(p[tl_off+2:tl_off+4])
                    udp_len = big2i(p[tl_off+4:tl_off+6])
                    # udp_cs = bytes(p[tl_off+6:tl_off+8])
                    payload_off = tl_off + 8
                    padding_off = ip_off + ip_len

                    session = (ip_src, ip_dst, ip_proto,
                               udp_src, udp_dst)
                    self.ctx.udp_sessions.add(session)

                    if Rules.UDP_CS_CALC:  # must come first
                        if padding_off - payload_off <= Rules.UDP_CS_CALC_THD:
                            udp_cs_calc = calc_tl_cs(tl_off, padding_off)
                            p[tl_off+6:tl_off+8] = i2big(udp_cs_calc, 2)

                    if Rules.UDP_LEN_PCAP_LEN:
                        p[tl_off+4:tl_off+6] = i2big(ip_len - udp_len - 20, 2)

                    if Rules.UDP_COMBINE_ADDR:
                        p[eth_off+0:eth_off+6] = eth_src
                        p[eth_off+6:eth_off+10] = ip_src
                        p[eth_off+10:eth_off+12] = udp_src
                        p[ip_off+12:ip_off+18] = eth_dst
                        p[ip_off+18:tl_off+2] = ip_dst
                        p[tl_off+2:tl_off+4] = udp_dst
                    # print(f'{b2str(p[8:16])}|{b2str(p[16:30])}|{b2str(p[30:50])}|{b2str(p[50:58])}')
                case _:
                    ...

        return p
