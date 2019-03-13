#!/usr/bin/env python
# copyright of sandro gauci 2008
# hijack helper functions
import base64
import logging

from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import rsa
from cryptography.hazmat.primitives import padding, hashes

def parseHeader(buff,type='response'):
    import re
    SEP = '\r\n\r\n'
    HeadersSEP = '\r*\n(?![\t\x20])'
    log = logging.getLogger('parseHeader')
    if SEP in buff:
        header,body = buff.split(SEP,1)
    else:
        header = buff
        body = ''
    headerlines = re.split(HeadersSEP, header)
    
    if len(headerlines) > 1:
        r = dict()
        if type == 'response':
            _t = headerlines[0].split(' ',2)
            if len(_t) == 3:
                httpversion,_code,description = _t
            else:
                log.warning('Could not parse the first header line: %s' % repr(_t))
                return r
            try:
                r['code'] = int(_code)
            except ValueError:
                return r
        elif type == 'request':
            _t = headerlines[0].split(' ',2)
            if len(_t) == 3:
                method,uri,httpversion = _t
                r['method'] = method
                r['uri'] = uri
                r['httpversion'] = httpversion
        else:
            log.warn('Could not parse the first header line')
            return r  
        r['headers'] = dict()
        for headerline in headerlines[1:]:
            SEP = ':'
            if SEP in headerline:
                tmpname,tmpval = headerline.split(SEP,1)
                name = tmpname.lower().strip()
                val =  map(lambda x: x.strip(),tmpval.split(','))
            else:
                name,val = headerline.lower(),None
            r['headers'][name] = val
        r['body'] = body
        return r

def getdsturl(tcpdata):
        log = logging.getLogger('getdsturl')
        p = parseHeader(tcpdata,type='request')
        if p is None:
                log.warn('parseHeader returned None')
                return
        if p.has_key('uri') and p.has_key('headers'):
            if p['headers'].has_key('host'):
                r = 'http://%s%s' % (p['headers']['host'][0],p['uri'])
                return r
            else:
                log.warning('seems like no host header was set')
        else:
                log.warning('parseHeader did not give us a nice return %s' % p)

def gethost(tcpdata):
    log = logging.getLogger('getdsturl')
    p = parseHeader(tcpdata,type='request')
    if p is None:
            log.warn('parseHeader returned None')
            return
    if p.has_key('headers'):
        if p['headers'].has_key('host'):
            return p['headers']['host']

def getuseragent(tcpdata):
    log = logging.getLogger('getuseragent')
    p = parseHeader(tcpdata,type='request')
    if p is None:
            log.warn('parseHeader returned None')
            return
    if p.has_key('headers'):
        if p['headers'].has_key('user-agent'):
            return p['headers']['user-agent']
        
def calcloglevel(options):
    logginglevel = 30
    if options.verbose is not None:
        if options.verbose >= 3:
            logginglevel = 10
        else:
            logginglevel = 30-(options.verbose*10)
    if options.quiet:
        logginglevel = 50
    return logginglevel

def getcookie(tcpdata):
	p = parseHeader(tcpdata,type='request')
	if p is None:
		return
	if p.has_key('headers'):
		if p['headers'].has_key('cookie'):
			return p['headers']['cookie']

def generateSymmeytricKey():
    key = Fernet.generate_key()
    return key

def symmetricEncryption(plainText, key):
    log = logging.getLogger('symmetricEncryption')
    log.info("Plain text: %s" % plainText)
    plainTextBytes = plainText.encode('utf-8')
    f = Fernet(key)
    cipherTextBytes = f.encrypt(plainTextBytes)
    cipherText = base64.urlsafe_b64encode(cipherTextBytes)
    log.info("Cipher text: %s" % cipherText)
    return cipherText

def symmetricDecryption(cipherText, key):
    log = logging.getLogger('symmetricDecryption')
    log.info("Cipher text: %s" % cipherText)
    f = Fernet(key)
    plainTextBytes = f.decrypt(base64.urlsafe_b64decode(cipherText))
    plainText = plainTextBytes.decode('utf-8')
    log.info("Plain text: %s" % plainText)
    return plainText

def generateAsymmeytricKey():
        privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend = default_backend()
        )
        publicKey: object = privateKey.public_key()
        return privateKey, publicKey

def asymmetricEncryption(plainText, publicKey):
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

def asymmetricDecryption(cipherText, privateKey):
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

def createDigitalSignature(message, privateKey):
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

def verifyDigitalSignature(signature, message, publicKey):
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


