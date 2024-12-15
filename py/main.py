import sys
import zstandard as zstd
from pathlib import Path

from utils import big2i, lit2i, i2lit


ZSTD_LEVEL = 1


class Context:
    def __init__(self):
        self.ts1 = 0
        self.ts2 = 0

    def upd_ts(self, ts1, ts2):
        d1 = ts1 - self.ts1
        d2 = ts2 - self.ts2
        self.ts1 = ts1
        self.ts2 = ts2
        return d1, d2


def main(argv):
    if len(argv) < 2:
        print(f"Usage: {argv[0]} FILE")

    fpath_in = Path(argv[1])
    with open(fpath_in, 'rb') as f:
        data = f.read()
        n_bytes = len(data)
    print(f"{n_bytes / 1e6:.3f} MB")

    n_compressed_0 = len(zstd.ZstdCompressor(level=ZSTD_LEVEL).compress(data))
    cr0 = n_bytes / n_compressed_0
    print(f"CR0: {cr0:.3f}")

    file_header = data[:24]

    i = 24
    n_packets = 0
    res = [file_header]
    context = Context()
    while i < n_bytes:
        n_packets += 1
        ts1 = lit2i(data[i:i+4])
        ts2 = lit2i(data[i+4:i+8])
        cpl = lit2i(data[i+8:i+12])
        opl = lit2i(data[i+12:i+16])

        ts1, ts2 = context.upd_ts(ts1, ts2)

        res.append(b''.join([
            i2lit(ts1, 4),
            i2lit(ts2, 4),
            i2lit(cpl, 4),
            i2lit(opl, 4),
        ]))
        i += 16

        # process packet
        res.append(data[i:i+cpl])

        i += cpl

    print(f"{n_packets} packets")

    data_processed = b''.join(res)
    n_compressed_1 = len(zstd.ZstdCompressor(
        level=ZSTD_LEVEL).compress(data_processed))
    cr1 = n_bytes / n_compressed_1
    print(f"CR1: {cr1:.3f} ({cr1/cr0 - 1:+.2%})")


if __name__ == "__main__":
    main(sys.argv)
