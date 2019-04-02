import base64
import hashlib
import random
import os
import logging
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import padding, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

db = sqlite3.connect('secret_parameters.sqlite3')
db.execute('CREATE TABLE IF NOT EXISTS secret_parameters\n'
           '(id TEXT PRIMARY KEY, secret_parameter TEXT)')

def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b

def findModInverse(a, m):
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m

    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3

    return u1 % m

def rabinMiller(num):
    s = num - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1
    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
        return True

def isPrime(num):
    if (num< 2):
        return False
    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
                 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
                 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
                 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
                 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449,
                 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569,
                 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
                 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
                 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907,
                 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    if num in lowPrimes:
        return True
    for prime in lowPrimes:
        if (num % prime == 0):
            return False
    return rabinMiller(num)

def generateLargePrime(keysize=1024):
    while True:
        num = random.randrange(2 ** (keysize - 1), 2 ** (keysize))
        if isPrime(num):
            return num

def generateKeyPair(keySize):
    p = generateLargePrime(keySize)
    print('Generating q prime...')
    q = generateLargePrime(keySize)
    n = p * q

    # Step 2: Create a number e that is relatively prime to (p-1)*(q-1).
    print('Generating e that is relatively prime to (p-1)*(q-1)...')
    while True:
        e = random.randrange(2 ** (keySize - 1), 2 ** (keySize))
        if gcd(e, (p - 1) * (q - 1)) == 1:
            break

    # Step 3: Calculate d, the mod inverse of e.
    print('Calculating d that is mod inverse of e...')
    d = findModInverse(e, (p - 1) * (q - 1))
    iqmp = rsa.rsa_crt_iqmp(p, q)
    dmp1 = rsa.rsa_crt_dmp1(d,p)
    dmq1 = rsa.rsa_crt_dmq1(d, q)
    public_key_numbers = rsa.RSAPublicNumbers(e,n)
    publicKey = public_key_numbers.public_key(default_backend());
    private_key_numbers = rsa.RSAPrivateNumbers(
        p,
        q,
        d,
        dmp1,
        dmq1,
        iqmp,
        public_key_numbers
    )
    privateKey = private_key_numbers.private_key(default_backend())
    print('Public key:', publicKey)
    print('Private key:', privateKey)
    return (publicKey, privateKey, str(p))

def save_private_key(pk, filename):
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

def save_public_key(pk, filename):
    pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

def load_private_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    return private_key

def load_public_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    public_key = load_pem_public_key(pemlines, default_backend())
    return public_key




def get_key_pair():
    if os.path.isfile('private_key.pem') and os.path.isfile('public_key.pem') and os.path.isfile('key_component.txt'):
        privateKey = load_private_key("private_key.pem")
        publicKey = load_public_key("public_key.pem")
        f = open("key_component.txt", "r+")
        p = f.read()
        f.close()
        return (publicKey, privateKey, p)
    else:
        publicKey, privateKey, p = generateKeyPair(4096)
        save_private_key(privateKey,"private_key.pem")
        save_public_key(publicKey,"public_key.pem")
        f = open("key_component.txt", "w+")
        f.write(str(p))
        f.close()
        return (publicKey, privateKey, p)


def get_secret_parameter(p):
    while True:
        k = random.randrange(1, p-1)
        if gcd(k, (p - 1)) == 1:
            break
    return str(k)

def generate_secret_key(message,k):
    value = message + k
    h = hashlib.sha256(value.encode('ascii')).digest()
    return base64.urlsafe_b64encode(h).decode('ascii')

def symmetric_encryption(plainText, key):
    log = logging.getLogger('symmetricEncryption')
    log.info("Plain text: %s" % plainText)
    plainTextBytes = plainText.encode('utf-8')
    f = Fernet(key)
    cipherTextBytes = f.encrypt(plainTextBytes)
    cipherText = base64.urlsafe_b64encode(cipherTextBytes)
    log.info("Cipher text: %s" % cipherText)
    return cipherText

def symmetric_decryption(cipherText, key):
    log = logging.getLogger('symmetricDecryption')
    log.info("Cipher text: %s" % cipherText)
    f = Fernet(key)
    plainTextBytes = f.decrypt(base64.urlsafe_b64decode(cipherText))
    plainText = plainTextBytes.decode('utf-8')
    log.info("Plain text: %s" % plainText)
    return plainText

def generate_symmeytricKey():
    key = Fernet.generate_key()
    return key

def generate_asymmeytricKey():
        privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend = default_backend()
        )
        publicKey: object = privateKey.public_key()
        return privateKey, publicKey

def asymmetric_encryption(plainText, publicKey):
    log = logging.getLogger('asymmetricEncryption')
    log.info("Plain text: %s" % plainText)
    cipherTextBytes = publicKey.encrypt(
        plaintext=plainText.encode('utf-8'),
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    cipherText = base64.urlsafe_b64encode(cipherTextBytes)
    log.info("Cipher text: %s" % cipherText)
    return cipherText

def asymmetric_decryption(cipherText, privateKey):
    log = logging.getLogger('asymmetricDecryption')
    log.info("Cipher text: %s" % cipherText)
    plainTextBytes = privateKey.decrypt(
        ciphertext=base64.urlsafe_b64decode(cipherText),
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    plainText = plainTextBytes.decode('utf-8')
    log.info("Plain text: %s" % plainText)
    return plainText

def create_digitalSignature(message, privateKey):
    messageTuple = message.encode('utf-8'),
    signatureBytes = privateKey.sign(
        messageTuple[0],
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature = base64.urlsafe_b64encode(signatureBytes)
    return signature

def verify_digitalSignature(signature, message, publicKey):
    try:
        log = logging.getLogger('verifyDigitalSignature')
        messageTuple = message.encode('utf-8'),
        publicKey.verify(
            base64.urlsafe_b64decode(signature),
            messageTuple[0],
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        log.error("Provided digital Signature is not valid.")
        return False

def store_secret_parameter(id,k):
    with db:
        db.execute('INSERT OR IGNORE INTO secret_parameters VALUES (?, ?)', (id, k))

def retrieve_secret_parameter(id):
    with db:
        k = db.execute('SELECT secret_parameter FROM secret_parameters WHERE id=?',(id,)).fetchone()
        return k

if __name__ == '__main__':
    publicKey, privateKey, p = get_key_pair()
    # print(p)
    # save_private_key(privateKey,"private_key.pem")
    # save_public_key(publicKey,"public_key.pem")
    # f = open("key_component.txt", "w+")
    # f.write(str(p))
    # f.close()

    # privateKey = load_private_key("private_key.pem")
    # publicKey = load_public_key("public_key.pem")

    f = open("key_component.txt", "r+")
    content = f.read()
    f.close()
    p = int(content)
    print('p='+content)

    k = get_secret_parameter(p)
    print('k='+str(k))
    id = 'aserrytigtyufgh'
    store_secret_parameter(id,k)
    k1 = retrieve_secret_parameter(id)
    print("k1="+k1[0])
    # message = 'aslkjfgnrubvjkeltbmdfgbjr'
    # plain_text = "hello world"
    # key = generate_secret_key(message,k)
    # plain_text_bytes = plain_text.encode('utf-8')
    # f = Fernet(key)
    # encrypted_bytes = f.encrypt(plain_text_bytes)
    # encrypted_text = base64.urlsafe_b64encode(encrypted_bytes)
    # decrypted_bytes = f.decrypt(base64.urlsafe_b64decode(encrypted_text))
    # decrypted_text = decrypted_bytes.decode('utf-8')

