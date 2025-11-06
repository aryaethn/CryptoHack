from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD

DATA = bytes.fromhex("372f0e88f6f7189da7c06ed49e87e0664b988ecbee583586dfd1c6af99bf20345ae7442012c6807b3493d8936f5b48e553f614754deb3da6230fa1e16a8d5953a94c886699fc2bf409556264d5dced76a1780a90fd22f3701fdbcb183ddab4046affdc4dc6379090f79f4cd50673b24d0b08458cdbe509d60a4ad88a7b4e2921")
FLAG = b'crypto{??????????????????????????????????????}'

def gen_keypair():
    p = getPrime(512)
    q = getPrime(512)
    N = p*q
    e = 65537
    phi = (p-1)*(q-1)
    d = inverse(e,phi)
    return N,e,d


def encrypt(m,e,N):
    m_int = bytes_to_long(m)
    c_int = pow(m_int,e,N)
    if m_int == c_int:
        print('RSA broken!?')
        return None
    else:
        return c_int

# N,e,d = gen_keypair()
N = 89820998365358013473897522178239129504456795742012047145284663770709932773990122507570315308220128739656230032209252739482850153821841585443253284474483254217510876146854423759901130591536438014306597399390867386257374956301247066160070998068007088716177575177441106230294270738703222381930945708365089958721
e = 65537 

# encrypted_data = encrypt(DATA,e,N)
# encrypted_flag = encrypt(FLAG,e,N)

# print(f'N = {hex(N)}')
# print(f'e = {hex(e)}')
# print(f'c = {hex(encrypted_flag)}')

# n = '7fe8cafec59886e9318830f33747cafd200588406e7c42741859e15994ab62410438991ab5d9fc94f386219e3c27d6ffc73754f791e7b2c565611f8fe5054dd132b8c4f3eadcf1180cd8f2a3cc756b06996f2d5b67c390adcba9d444697b13d12b2badfc3c7d5459df16a047ca25f4d18570cd6fa727aed46394576cfdb56b41'
# E = '10001'
C = '5233da71cc1dc1c5f21039f51eb51c80657e1af217d563aa25a8104a4e84a42379040ecdfdd5afa191156ccb40b6f188f4ad96c58922428c4c0bc17fd5384456853e139afde40c3f95988879629297f48d0efa6b335716a4c24bfee36f714d34a4e810a9689e93a0af8502528844ae578100b0188a2790518c695c095c9d677b'

m_int = bytes_to_long(DATA)
# e-1 = 65536 = 2 ^ 16
num_factors = [m_int]
p = None
for i in range(1, 16):
    if GCD(num_factors[i-1] - 1, N) not in [1,N]:
        p = GCD(num_factors[i-1] - 1, N)
        break
    num_factors.append(pow(num_factors[i-1], 2, N))

num = pow(m_int, 2 ** 15, N) + 1
if GCD(num, N) not in [1, N]:
    p = GCD(num, N)
if p:
    q = N // p
    flag = pow(int(C, 16), inverse(e, (p - 1) * (q - 1)), N)
    print(long_to_bytes(flag).decode())
else:
    print('Nope')