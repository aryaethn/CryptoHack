from sage.all import *
from pwn import *
import json
import sys
import requests


def query_factordb(n):
    """
    Queries FactorDB for the factorization of a given number n.
    Returns a dictionary containing the factorization data, or None if an error occurs.
    """
    url = f"http://factordb.com/api?query={n}"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        print(f"Error querying FactorDB: {e}")
        return None

modulus = 13407807929942597099574024998205846127479365820592393377723561443721764030029777567070168776296793595356747829017949996650141749605031603191442486002224009
a = -3
b = 152961
order = 115792089237316195423570985008687907853233080465625507841270369819257950283813

q = 115792089237316195423570985008687907853269984665640564039457584007913129639747 #derived from the modulus = new_modulus ^ 2

# This is the LIMIT for the private key (from the file), not the curve order!
privkey_limit = 115792089237316195423570985008687907853233080465625507841270369819257950283813

def solve():
    # connect = remote('localhost', 13417)
    connect = remote('socket.cryptohack.org', 13417)
    connect.recvuntil(b"decimal format.\n")

    # 1. Calculate the ACTUAL curve order over GF(q)
    log.info("Calculating real curve order...")
    E_finite = EllipticCurve(GF(q), [a, b])
    real_order = E_finite.order()
    log.info(f"Real Curve Order: {real_order}")

    # 2. Setup the Curve in Q_p (p-adic numbers)
    # Precision 2 is enough (modulo q^2)
    K = Qp(q, 2) 
    E = EllipticCurve(K, [a, b])
    
    # 3. Find a valid base point P
    log.info("Finding base point...")
    x0 = Integer(1)
    P = None
    while P is None:
        try:
            P = E.lift_x(x0)
        except ValueError:
            x0 += 1
            
    log.info(f"Selected Base Point x: {x0}")

    # 4. Send x0 to server
    req = {"option": "get_pubkey", "x0": str(x0)}
    connect.sendline(json.dumps(req).encode())
    
    resp = json.loads(connect.recvline().decode())
    if "error" in resp:
        log.error(resp["error"])
        return
        
    x_pub = Integer(resp["pubkey"])
    log.info(f"Received Pubkey x: {x_pub}")

    # 5. Recover Q (Lifting)
    try:
        Q = E.lift_x(x_pub)
    except ValueError:
        log.error("Failed to lift Q.")
        return

    # 6. The Attack
    # Multiply by the REAL order to project into the kernel
    log.info("Computing N * P and N * Q...")
    P_prime = real_order * P
    Q_prime = real_order * Q

    # 7. Compute p-adic logarithms (slope method)
    # Log(P) = -x/y
    def elliptic_log(point):
        # Cast to generic ring to avoid precision issues
        x_val = point[0]
        y_val = point[1]
        return -x_val / y_val

    log_P = elliptic_log(P_prime)
    log_Q = elliptic_log(Q_prime)
    
    # d = log_Q / log_P mod q
    d_padic = log_Q / log_P
    d_recovered = Integer(d_padic) % q
    
    log.success(f"Recovered d candidate: {d_recovered}")

    # 8. Submit
    # The private key must be < privkey_limit. 
    # It might be d, or (privkey_limit - d) is NOT the check.
    # The code says: self.privkey = min(privkey % order, (order - privkey) % order)
    # So the key is definitely < privkey_limit.
    # We check d and (limit - d) just in case, but usually it's just d if d < limit.
    
    candidates = [d_recovered]
    # Also check the mirrored key relative to the LIMIT, not the curve order
    if d_recovered < privkey_limit:
        candidates.append(privkey_limit - d_recovered)
        
    for cand in candidates:
        log.info(f"Trying key: {cand}")
        req_flag = {"option": "get_flag", "privkey": int(cand)}
        connect.sendline(json.dumps(req_flag).encode())
        
        flag_resp = connect.recvline().decode()
        if "crypto{" in flag_resp:
            log.success(f"FLAG FOUND: {flag_resp}")
            break
        else:
            log.info(f"Response: {flag_resp}")

if __name__ == "__main__":
    solve()