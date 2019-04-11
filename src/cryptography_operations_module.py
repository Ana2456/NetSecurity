import base64
import hashlib
import random
import datetime

from cryptography.fernet import Fernet

def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b

def miillerTest(d, n):
    # Pick a random number in [2..n-2]
    # Corner cases make sure that n > 4
    a = 2 + random.randint(1, n - 4);

    # Compute a^d % n
    x = power(a, d, n);

    if (x == 1 or x == n - 1):
        return True;

        # Keep squaring x while one
    # of the following doesn't
    # happen
    # (i) d does not reach n-1
    # (ii) (x^2) % n is not 1
    # (iii) (x^2) % n is not n-1
    while (d != n - 1):
        x = (x * x) % n;
        d *= 2;

        if (x == 1):
            return False;
        if (x == n - 1):
            return True;

def isPrime(n):
    k=4
    # Corner cases
    if (n <= 1 or n == 4):
        return False;
    if (n <= 3):
        return True;

        # Find r such that n =
    # 2^d * r + 1 for some r >= 1
    d = n - 1;
    while (d % 2 == 0):
        d //= 2;

        # Iterate given nber of 'k' times
    for i in range(k):
        if (miillerTest(d, n) == False):
            return False;

    return True;

def power(x, y, p):
    res = 1  # Initialize result

    # Update x if it is more
    # than or equal to p
    x = x % p

    while (y > 0):

        # If y is odd, multiply
        # x with result
        if ((y & 1) == 1):
            res = (res * x) % p

            # y must be even now
        y = y >> 1  # y = y/2
        x = (x * x) % p

    return res

def modInverse(a, m) :
    a = a % m;
    for x in range(1, m) :
        if ((a * x) % m == 1) :
            return x
    return 1

def findModInverse(a, m):
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m

    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3

    return u1 % m

def generateLargePrime(keysize=1024):
    while True:
        num = random.randrange(2 ** (keysize - 1), 2 ** (keysize))
        if isPrime(num):
            return num

def generateKeyPair(keySize):
    #print('Generating p prime...')
    p = generateLargePrime(keySize)

    #print('Generating g such that 1<=g<p and g is relatively prime to p...')
    while True:
        g = random.randrange(1, p)
        if gcd(g, p) == 1:
            break

    #print('Generating private key x such that 1<=x<=p-1')
    x = random.randrange(1, p)

    #print('Generating public key y')
    y = power(g, x, p)

    return (p, g, x, y)

def save_key_pair_components(p,g,x,y):
    fp = open("key_component_p.txt", "w+")
    fp.write(str(p))
    fp.close()

    fg = open("key_component_g.txt", "w+")
    fg.write(str(g))
    fg.close()

    fx = open("key_component_x.txt", "w+")
    fx.write(str(x))
    fx.close()

    fy = open("key_component_y.txt", "w+")
    fy.write(str(y))
    fy.close()

def load_key_pair_components():
    fp = open("key_component_p.txt", "r+")
    content = fp.read()
    p = int(content)
    fp.close()

    fg = open("key_component_g.txt", "r+")
    content = fg.read()
    g = int(content)
    fg.close()

    fx = open("key_component_x.txt", "r+")
    content = fx.read()
    x = int(content)
    fx.close()

    fy = open("key_component_y.txt", "r+")
    content = fy.read()
    y = int(content)
    fy.close()

    return p, g, x, y

def get_secret_parameter(p):
    while True:
        k = random.randrange(1, p-1)
        if gcd(k, (p - 1)) == 1:
            break
    return k

def generate_secret_key(message,k):
    value = message + str(k)
    h = hashlib.sha256(value.encode('ascii')).digest()
    return base64.urlsafe_b64encode(h).decode('ascii')

def symmetric_encryption(plainText, key):
    plainTextBytes = plainText.encode('utf-8')
    f = Fernet(key)
    cipherTextBytes = f.encrypt(plainTextBytes)
    cipherText = cipherTextBytes.decode("utf-8")
    return cipherText

def symmetric_decryption(cipherText, key):
    cipherTextBytes = cipherText.encode('utf-8')
    f = Fernet(key)
    plainTextBytes = f.decrypt(cipherTextBytes)
    plainText = plainTextBytes.decode('utf-8')
    return plainText

def create_digitalSignature(message, g, k, x, p):
    r = power(g, k, p)
    m = int(hashlib.sha1(message.encode('utf-8')).hexdigest(),16)
    val_1 = x*(r+m)
    val_2 = k %(p-1)
    s = val_1 - val_2
    return r, s

def retrieve_secret_parameter(message, r, s, x, p):
    m = int(hashlib.sha1(message.encode('utf-8')).hexdigest(), 16)
    val_1 = x * (r + m)
    val_2 = s % (p - 1)
    k = val_1 - val_2
    return k

if __name__ == '__main__':
    # p1, g1, x1, y1 = generateKeyPair(2048)
    # save_key_pair_components(p1, g1, x1, y1)

    p, g, x, y = load_key_pair_components()

    start_time1 = datetime.datetime.now()
    k = get_secret_parameter(p)
    elapsedTime1 = datetime.datetime.now()-start_time1
    print('secret parameter selection: %d' %elapsedTime1.microseconds)

    c_i1 = 'aserrytigtyufgh'
    c_i2 = 'fhietbpnssnshuevbe'

    start_time2 = datetime.datetime.now()
    secret_key = generate_secret_key(c_i1, k)
    elapsedTime2 = datetime.datetime.now() - start_time2
    print('secret key generation: %d' % elapsedTime2.microseconds)

    start_time3 = datetime.datetime.now()
    t_i1 = symmetric_encryption(c_i2, secret_key)
    elapsedTime3 = datetime.datetime.now() - start_time3
    print('cookie data encryption: %d' % elapsedTime3.microseconds)

    message = c_i1 + t_i1

    start_time4 = datetime.datetime.now()
    r,s = create_digitalSignature(message, g, k, x, p)
    elapsedTime4 = datetime.datetime.now() - start_time4
    print('digital signature creation: %d' % elapsedTime4.microseconds)

    start_time5 = datetime.datetime.now()
    k = retrieve_secret_parameter(message, r, s, x, p)
    elapsedTime5 = datetime.datetime.now() - start_time5
    print('secret parameter extraction: %d' % elapsedTime5.microseconds)

    start_time6 = datetime.datetime.now()
    c_i2_new = symmetric_decryption(t_i1, secret_key)
    elapsedTime6 = datetime.datetime.now() - start_time6
    print('cookie data decryption: %d' % elapsedTime6.microseconds)