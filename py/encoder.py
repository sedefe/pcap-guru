from utils import lit2i, big2i, i2lit, ip2str
from const import EtherType, IpType
from collections import defaultdict


class Context:
    def __init__(self):
        self.ts1 = 0
        self.ts2 = 0

        self.ip_id = defaultdict(lambda: 0)
        self.ip_cs = defaultdict(lambda: 0)


class Rules:
    PCAP_TS1_DIFF = True
    PCAP_TS2_DIFF = True
    IP_ID_DIFF = True
    IP_CS_DIFF = True


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

            ip_id = big2i(p[ip_off+4:ip_off+6])
            ip_cs = big2i(p[ip_off+10:ip_off+12])

            ip_srcaddr = p[ip_off+12:ip_off+16]
            ip_dstaddr = p[ip_off+16:ip_off+20]

            if Rules.IP_ID_DIFF:
                d = ip_id - self.ctx.ip_id[ip_srcaddr]
                self.ctx.ip_id[ip_srcaddr] = ip_id
                self.p[ip_off+4:ip_off+6] = i2lit(d, 2)

            if Rules.IP_CS_DIFF:
                d = ip_cs - self.ctx.ip_cs[ip_srcaddr]
                self.ctx.ip_cs[ip_srcaddr] = ip_cs
                self.p[ip_off+10:ip_off+12] = i2lit(d, 2)

            if ip_proto == IpType.TCP:
                tcp_d_off = 4 * (p[tl_off+12] // 16)
                tcp_srcport = p[tl_off:tl_off+2]
                tcp_drcport = p[tl_off+2:tl_off+4]

        return self.p
