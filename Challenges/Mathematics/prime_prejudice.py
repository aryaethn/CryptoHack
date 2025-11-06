from Crypto.Util.number import *
from sympy.ntheory.modular import crt
import libnum, itertools, operator, functools, json
from pwn import remote


def check_quadratic_residue(a, p):
    """Check if a is a quadratic residue modulo p"""
    return pow(a, (p - 1) // 2, p) == 1


def miller_rabin_test(n, prime_basis):
    """
    Miller Rabin primality test using the provided prime basis
    """
    if n == 2 or n == 3:
        return True
    
    if n % 2 == 0:
        return False
    
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    
    for b in prime_basis:
        x = pow(b, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def build_Sa_sets(prime_basis):
    """Build Sa sets for each prime in the basis"""
    Sa_sets = []
    for p in prime_basis:
        forbidden_set = set()
        for i in range(3, 200 * p):
            if isPrime(i) and not check_quadratic_residue(p, i):
                forbidden_set.add(i % (4 * p))
        if p in forbidden_set:
            forbidden_set.remove(p)
        Sa_sets.append(list(forbidden_set))
    return Sa_sets


def build_Sb_sets(Sa_sets, prime_basis, k_values):
    """Build Sb sets from Sa sets using k values"""
    Sb_sets = []
    for idx, forbidden_vals in enumerate(Sa_sets):
        p = prime_basis[idx]
        current_set = set(forbidden_vals)
        for i in range(1, len(k_values)):
            new_set = set()
            for num in forbidden_vals:
                res = (num + k_values[i] - 1) * inverse(k_values[i], p * 4)
                if res % 4 == 3:
                    new_set.add(res % (p * 4))
            current_set = current_set.intersection(new_set)
        Sb_sets.append(list(current_set))
    return Sb_sets


def compute_p_values(p1, k_values):
    """Generate p values from p1 and k values"""
    return [i * (p1 - 1) + 1 for i in k_values]


def compute_p_product(p1, k_values):
    """Compute the product of all p values"""
    return functools.reduce(operator.mul, compute_p_values(p1, k_values))


def find_strong_pseudoprime(prime_basis, k_values, lower_bound, upper_bound):
    """
    Search for strong pseudoprimes in the given range
    Returns tuple: (success, pseudoprime, factors)
    """
    # Validate inputs
    unique_basis = sorted(list(set(prime_basis)))
    for num in unique_basis:
        if not isPrime(num):
            raise ValueError('basis should be prime list')
    if len(k_values) < 3:
        raise ValueError('len(k) should >= 3')
    if k_values[0] != 1:
        raise ValueError('k[0] should be 1')
    if len(k_values) != len(set(k_values)):
        raise ValueError('k should not contains same number')
    
    # Initialize Sa and Sb sets
    Sa_sets = build_Sa_sets(unique_basis)
    Sb_sets = build_Sb_sets(Sa_sets, unique_basis, k_values)

    print(Sa_sets)
    print(Sb_sets)
    
    # Search for pseudoprime
    for chosen_combination in itertools.product(*Sb_sets):
        residues = [k_values[1] - inverse(k_values[2], k_values[1]), 
                   k_values[2] - inverse(k_values[1], k_values[2])]
        modules = [k_values[1], k_values[2]]
        
        for i, t in enumerate(chosen_combination):
            residues.append(t)
            modules.append(4 * unique_basis[i])
        
        crt_result = crt(modules, residues)
        if not crt_result:
            continue
        
        solution, modulus = crt_result
        
        # Binary search for starting point
        range_start = solution
        left, right = 1, lower_bound
        while left <= right:
            mid = (left + right) // 2
            if compute_p_product(mid * modulus + solution, k_values) < lower_bound:
                left = mid + 1
            else:
                right = mid - 1
                range_start = mid * modulus + solution
        
        # Search for valid pseudoprime
        for i, current_t in enumerate(range(range_start, min(range_start + 100000 * modulus, upper_bound), modulus)):
            if i % 1000 == 0:
                print(f"Trying {i}th time")
            if isPrime(current_t):
                pseudo_prime = compute_p_product(current_t, k_values)
                factor_list = compute_p_values(current_t, k_values)
                if miller_rabin_test(pseudo_prime, unique_basis):
                    if lower_bound <= pseudo_prime <= upper_bound:
                        return True, pseudo_prime, factor_list
    
    return False, -1, []


def sieve_primes(n):
    """Generate all primes up to n using sieve of Eratosthenes"""
    is_prime = [True] * n
    for i in range(3, int(n**0.5) + 1, 2):
        if is_prime[i]:
            is_prime[i*i::2*i] = [False] * ((n - i*i - 1) // (2*i) + 1)
    return [2] + [i for i in range(3, n, 2) if is_prime[i]]


# Main execution
prime_basis = sieve_primes(64)
print(prime_basis)
k_vals = [1, 101, 181]
success, pseudoprime, factors = find_strong_pseudoprime(prime_basis, k_vals, 2**600, 2**900)

if success:
    print('Success')
    payload = {'prime': pseudoprime, 'base': factors[0]}
    connection = remote('socket.cryptohack.org', 13385)
    connection.recvline()
    connection.send(json.dumps(payload).encode() + b'\n')
    print(json.loads(connection.recvline().decode())['Response'])
else:
    print('Fail')
