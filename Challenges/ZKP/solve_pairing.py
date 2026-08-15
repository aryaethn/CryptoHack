from py_ecc.optimized_bn128 import FQ, FQ2, FQ12, pairing

lines = open("output_pairing.txt").read().splitlines()

bits = ""
for line in lines:
    xG_raw, yG_raw, zG_raw = eval(line)

    xG = tuple(FQ(v) for v in xG_raw)
    yG = tuple(FQ2(list(v)) for v in yG_raw)
    zG = FQ12(list(zG_raw))

    # generate.py set bias=1 (bit=1) or a random bias (bit=0) before pairing;
    # e(yG, xG) == zG only holds when bias was 1.
    test = pairing(yG, xG)
    bits += "1" if test == zG else "0"

flag = int(bits, 2).to_bytes((len(bits) + 7) // 8, "big")
print(flag)
