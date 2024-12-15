def big2i(bs):
    s = 0
    for b in bs:
        s = s*256 + int(b)
    return s


def lit2i(bs):
    s = 0
    for b in bs[::-1]:
        s = s*256 + int(b)
    return s


def i2lit(n, n_bytes):
    return (n % 2**n_bytes).to_bytes(n_bytes, byteorder='little')
