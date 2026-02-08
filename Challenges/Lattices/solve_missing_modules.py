#!/usr/bin/env python3
import socket, json, ast
import numpy as np

HOST = "socket.cryptohack.org"
PORT = 13412

n = 512
p = 257
q = 6007
delta = int(round(q / p))  # same as server

def recvline(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data.decode()

def sendjson(sock, obj):
    sock.sendall(json.dumps(obj).encode() + b"\n")

def recvjson(sock):
    line = recvline(sock)
    return json.loads(line)

def get_encrypt(sock, m: int):
    sendjson(sock, {"option": "encrypt", "message": str(m)})
    r = recvjson(sock)
    if "error" in r:
        raise ValueError(r["error"])
    A = np.array(ast.literal_eval(r["A"]), dtype=np.int64)
    b = int(r["b"])
    return A, b

def get_flag_ct(sock, idx: int):
    sendjson(sock, {"option": "get_flag", "index": str(idx)})
    r = recvjson(sock)
    if "error" in r:
        raise ValueError(r["error"])
    A = np.array(ast.literal_eval(r["A"]), dtype=np.int64)
    b = int(r["b"])
    return A, b

def recover_secret(sock, samples=800):
    # Collect equations b_i = A_i @ S + small_noise
    M = np.zeros((samples, n), dtype=np.float64)
    bv = np.zeros(samples, dtype=np.float64)

    for i in range(samples):
        A, b = get_encrypt(sock, 0)
        M[i, :] = A.astype(np.float64)
        bv[i] = float(b)

    # Least squares solve M * S ~= b
    S_hat, residuals, rank, svals = np.linalg.lstsq(M, bv, rcond=None)
    S_int = np.rint(S_hat).astype(np.int64)

    # Quick sanity check: residuals should be small-ish
    approx_err = bv - M @ S_int.astype(np.float64)
    print("[*] rank:", rank)
    print("[*] residual rms:", float(np.sqrt(np.mean(approx_err**2))))
    print("[*] residual max abs:", float(np.max(np.abs(approx_err))))

    return S_int

def decrypt_char(A, b, S):
    # b - A@S = m*delta + e
    t = int(b - int(A @ S))
    m = int(np.rint(t / delta))
    # clamp into byte range
    m %= p
    if not (0 <= m <= 255):
        # usually not needed, but helps debugging if something goes weird
        raise ValueError(f"decoded out of byte range: {m}")
    return m

def main():
    with socket.create_connection((HOST, PORT)) as sock:
        # server prints a banner line first
        banner = recvline(sock)
        print(banner.strip())

        print("[*] recovering secret S ...")
        S = recover_secret(sock, samples=900)

        # We don't know FLAG length locally, but we do know it starts with crypto{ and ends with }.
        # We'll just try indices until it errors.
        out = bytearray()
        idx = 0
        while True:
            try:
                A, b = get_flag_ct(sock, idx)
            except ValueError as e:
                # index out of range -> done
                print("[*] done at idx", idx, ":", e)
                break

            ch = decrypt_char(A, b, S)
            out.append(ch)
            print(f"\r[*] idx={idx} -> {chr(ch)!r}", end="")
            idx += 1

        print("\n[+] flag:", out.decode(errors="replace"))

if __name__ == "__main__":
    main()
