import sys
import zstandard as zstd
from pathlib import Path
from collections import Counter

from utils import lit2i, b2str, ip2str
from const import PCAP_FILE_HEADER_LEN, PCAP_PACKET_HEADER_LEN
from encoder import Encoder

ZSTD_LEVEL = 1


def main(argv):
    if len(argv) < 2:
        print(f"Usage: {argv[0]} PCAP_FILE")

    fpath_in = Path(argv[1])
    with open(fpath_in, 'rb') as f:
        data = f.read()
        n_bytes = len(data)

    n_compressed_0 = len(zstd.ZstdCompressor(level=ZSTD_LEVEL).compress(data))
    cr0 = n_bytes / n_compressed_0
    print(
        f"CR0: {cr0:.3f} ({n_bytes / 1e6:.2f} -> {n_compressed_0 / 1e6:.2f} MB)")

    file_header = data[:PCAP_FILE_HEADER_LEN]

    i = PCAP_FILE_HEADER_LEN
    n_packets = 0
    res = [file_header]
    encoder = Encoder()

    while i < n_bytes:
        n_packets += 1
        cpl = lit2i(data[i+8:i+12])

        p = encoder.process(data[i:i + PCAP_PACKET_HEADER_LEN + cpl])
        res.append(p)

        i += PCAP_PACKET_HEADER_LEN + cpl

    print(f"{n_packets} packets")

    data_processed = b''.join(res)
    n_compressed_1 = len(zstd.ZstdCompressor(
        level=ZSTD_LEVEL).compress(data_processed))
    cr1 = n_bytes / n_compressed_1
    print(f"CR1: {cr1:.3f} ({len(data_processed) / 1e6:.2f} -> {n_compressed_1 / 1e6:.2f} MB), "
          f"{cr1/cr0 - 1:+.2%}")

    encoder.stat.print()


if __name__ == "__main__":
    main(sys.argv)
