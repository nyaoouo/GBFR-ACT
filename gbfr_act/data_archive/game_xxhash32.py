import struct

to_int = lambda v: v if (v := v & 0xFFFFFFFF) < 0x80000000 else v - 0x100000000
to_uint = lambda v: v & 0xFFFFFFFF
urshift = lambda x, n: (x % (1 << 32)) >> n
xxh32_rotl = lambda x, r: to_int((x << r) | urshift(x, 32 - r))


def xxhash32(raw: bytes):
    input_length = len(raw)
    off = 0
    h32 = 0x178A54A4
    if input_length >= 16:
        status = [0x2557311B, 0x871FB76A, 0x0133ECF3, 0x62FC7342]
        while off <= input_length - 16:
            status = [to_int(xxh32_rotl(s + to_int(v * 0x85EBCA77), 13) * 0x9E3779B1) for s, v in zip(status, struct.unpack_from('<4I', raw, off))]
            off += 16
        h32 = to_int(xxh32_rotl(status[0], 1) + xxh32_rotl(status[1], 7) + xxh32_rotl(status[2], 12) + xxh32_rotl(status[3], 18))
    h32 += input_length
    while off <= input_length - 4:
        h32 = to_int(xxh32_rotl(h32 + to_int(struct.unpack_from('<I', raw, off)[0] * 0xC2B2AE3D), 17) * 0x27D4EB2F)
        off += 4
    for byte in raw[off:]:
        h32 = to_int(xxh32_rotl(h32 + (to_int(byte * 0x165667B1)), 11) * 0x9E3779B1)
    h32 = to_int((h32 ^ urshift(h32, 15)) * 0x85EBCA77)
    h32 = to_int((h32 ^ urshift(h32, 13)) * 0xC2B2AE3D)
    return to_uint(h32 ^ urshift(h32, 16))
