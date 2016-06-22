#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function, division, absolute_import, unicode_literals
try:
    from __builtin__ import bytes, str, open, super, range, zip, round, int, pow, object, input
except ImportError:
    pass
try:
    from __builtin__ import raw_input as input
except ImportError:
    pass
import os
import sys
import unicodedata
from binascii import hexlify
from binascii import unhexlify
from hashlib import sha256
import hashlib


# The flag byte starts at 0x00 for EC multiplication being used, 
# and 0xC0 for non-EC multiplication, and then you add any extra 
# information to the byte, as specified by the BIP0038 wiki.

# The numbers you add to it are such that the sum can only happen
# with specific components added, therefore the sum total can tell you
# exactly what was added and whether it started at 00 or c0. So the
# flag byte can give multiple peices of information in a single byte.
# If you decode the hex into decimal, you can easily see how this is
# possible.

# The available flag byte switches, in decimal, are:
# 0, 4, 8, 16, 32, 192

# You can see how we could still have 1 and 2 available, as well as
# have 64 available for EC multiplied keys only.

# See the wiki for more information:
# https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki#Proposed_specification

# To more easily determine the key properties from the flag byte
COMPRESSION_FLAGBYTES = ['20','24','28','2c','30','34','38','3c','e0','e8','f0','f8']
LOTSEQUENCE_FLAGBYTES = ['04','0c','14','1c','24','2c','34','3c']
NON_MULTIPLIED_FLAGBYTES = ['c0','c8','d0','d8','e0','e8','f0','f8']
EC_MULTIPLIED_FLAGBYTES = ['00','04','08','0c','10','14','18','1c','20','24','28','2c','30','34','38','3c']
# Lotsequence bytes on non-EC multiplied keys are illegal.
ILLEGAL_FLAGBYTES = ['c4','cc','d4','dc','e4','ec','f4','fc']


# Much of the following functions taken from James D'Angelo's
# World Bitcoin Network Blackboard series code:
# https://github.com/wobine/blackboard101/blob/master/EllipticCurvesPart5-TheMagic-SigningAndVerifying.py

# secp256k1 curve is  y^2 = x^3 + A*x^2 + B, with the following parameters:
P_CURVE = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
N_ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337
A_CURVE = 0
B_CURVE = 7
H_COFACTOR = 1
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424

def ec_modular_inverse(a,p=P_CURVE):
    """Calculate the modular inverse"""

    lm, hm = 1, 0
    low, high = a % p, p
    while low > 1:
        ratio = high // low
        nm, new = hm - lm*ratio, high - low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % p

def ec_add(xp,yp,xq,yq):
    """Add two points (aka public keys)"""

    m = ((yq-yp) * ec_modular_inverse(xq-xp,P_CURVE)) % P_CURVE
    xr = (m*m-xp-xq) % P_CURVE
    yr = (m*(xp-xr)-yp) % P_CURVE
    return xr, yr

def ec_double(xp,yp):
    """EC double and add."""

    lam_numerator = 3*xp*xp + A_CURVE
    lam_denominator = 2*yp
    lam = (lam_numerator * ec_modular_inverse(lam_denominator,P_CURVE)) % P_CURVE
    xr = (lam**2 - 2*xp) % P_CURVE
    yr = (lam*(xp-xr) - yp) % P_CURVE
    return xr, yr

def ec_multiply(xs,ys,scalar):
    """Multiply a point by an integer scalar."""

    if scalar == 0 or scalar >= N_ORDER:
        raise Exception('ec_multiply() Invalid Scalar/Private Key')

    scalar_bin = str(bin(scalar)).lstrip('0b')
    Qx,Qy=xs,ys
    for i in range (1, len(scalar_bin)):
        Qx, Qy = ec_double(Qx,Qy)
        if scalar_bin[i] == '1':
            Qx,Qy=ec_add(Qx,Qy,xs,ys)
    return Qx, Qy

# End WBN code


def hex_to_hexstr(hexinput,zfill_=0):
    """Convert hex data to a string of hex chars"""
    if hexinput == '' or not hexinput:
        return ''
    output = str(hexlify(unhexlify(hexinput)))
    output = "z" + str(output)
    output = str(output).replace('L','').replace('0x','').replace("'",'').replace('z','')
    if int(sys.version_info.major) == 3:
        output = "z" + output
        output = output[2:].replace("'",'').replace("'",'')
        output = str(output)
    output = output.zfill(zfill_)
    if len(output) % 2:
        output = '0' + output
    output = str(output)
    return output

def hexstrlify(rawdata_or_int,zfill_=0):
    if 'int' in str(type(rawdata_or_int)) or 'long' in str(type(rawdata_or_int)):
        try:
            output = hex_to_hexstr(hexlify(unhexlify(hex(rawdata_or_int))),zfill_)
        except:
            output = '0' + str(hex(rawdata_or_int)).replace('0x','').replace('L','')
            if len(output) % 2 and output[:1] == '0':
                output = output[1:]
            output = hex_to_hexstr(hexlify(unhexlify(output)),zfill_)
        if len(output) % 2:
            output = '0' + output
        return output
    else:
        return hex_to_hexstr(hexlify(rawdata_or_int),zfill_)

def hexstr_to_hex(hexstrinput):
    """Convert a hex string into actual hex"""
    return hexlify(unhexlify(hexstrinput))

def rehexlify(unknown_hex_or_hexstr):
    """Returns hex for input of either hex or hexstr"""
    return hexlify(unhexlify(unknown_hex_or_hexstr))

def pow_mod(x,y,z):
    """
    Modular exponentiation

    Code taken from:
    https://bitcointalk.org/index.php?topic=644919.msg7205689#msg7205689
    """

    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

def uncompress_pubkey(compressedPubKey):
    """
    Turn a 02/03 prefix public key into an uncompressed 04 key

    pow_mod() and most of this function taken from:
    https://bitcointalk.org/index.php?topic=644919.msg7205689#msg7205689
    """

    try:
        test1 = unhexlify(compressedPubKey)
        test2 = int(compressedPubKey,16)
        tast1,test2 = "",""
    except:
        raise Exception('uncompress_pubkey() input not hex')
    #Sanitize input key
    compressedPubKey = hex_to_hexstr(hexlify(unhexlify(compressedPubKey))).zfill(66)
    if (len(compressedPubKey) != 66) \
     or ((compressedPubKey[:-64] != '02') \
      and (compressedPubKey[:-64] != '03')):
        raise Exception('uncompress_pubkey() Unknown input error')
    y_parity = int(compressedPubKey[:2],16) - 2
    x = int(compressedPubKey[2:],16)
    a = (pow_mod(x, 3, P_CURVE) + 7) % P_CURVE
    y = pow_mod(a, (P_CURVE+1)//4, P_CURVE)
    if y % 2 != y_parity:
        y = -y % P_CURVE
    x = hexstrlify(x,64)
    y = hexstrlify(y,64)
    return hexlify(unhexlify('04' + x + y))

def compress_pub_key(uncompressedPubKey):
    """Compress an 04 prefix public key to a 02/03 key"""

    try:
        test1 = unhexlify(uncompressedPubKey)
        test2 = int(uncompressedPubKey,16)
        tast1,test2 = "",""
    except:
        raise Exception('compress_pub_key() input not hex')
    #Sanitize input key
    uncompressedPubKey = hex_to_hexstr(hexlify(unhexlify(uncompressedPubKey))).zfill(130)
    if uncompressedPubKey[:2] != '04':
        raise Exception('compress_pub_key() unknown error, key does not begin with 04')
    x_coordStr = uncompressedPubKey[2:66]
    y_coordStr = uncompressedPubKey[66:]
    if int(y_coordStr,16) % 2:
        outputHexStr = '03' + x_coordStr
    else:
        outputHexStr = '02' + x_coordStr
    return hexlify(unhexlify(outputHexStr))

def base58_check(payload,prefix='',postfix=''):
    """Returns the 4 byte checksum that is done prior to base58
       encoding a key"""

    try:
        payload = hexlify(unhexlify(payload))
        if prefix != '':
            prefix = hexlify(unhexlify(prefix))
        if postfix != '':
            postfix = hexlify(unhexlify(postfix))
    except:
        raise Exception('base58_check() Invalid input')
    payload, prefix, postfix = hex_to_hexstr(payload), hex_to_hexstr(prefix), hex_to_hexstr(postfix)
    inputdata = unhexlify(prefix + payload + postfix)
    finalHash = hex_to_hexstr(sha256(sha256(inputdata).digest()).hexdigest()).zfill(64)
    return hexlify(unhexlify(finalHash[:8]))

def base58_encode(a,version='',postfix=''):
    """
    Base58 encode input

    Mostly ripped from:
    https://github.com/jgarzik/python-bitcoinlib/blob/master/bitcoin/base58.py
    """

    try:
        a = hexlify(unhexlify(a))
        version = hexlify(unhexlify(version))
        postfix = hexlify(unhexlify(postfix))
    except:
        raise Exception('base58_encode() Invalid input')
    a, version, postfix = hex_to_hexstr(a), hex_to_hexstr(version), hex_to_hexstr(postfix)
    b = version + a + postfix
    b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n1 = int(b,16)
    res = []
    while n1 > 0:
        n1, r = divmod(n1,58)
        res.append(b58_digits[r])
    res = ''.join(res[::-1])
    pad = 0
    for i in range(len(b) // 2):
        j = int(2*i)
        teststr = str(b[j] + b[j+1])
        if teststr == '00':
            pad += 1
        else:
            break
    return str(b58_digits[0] * pad + res)

def base58_decode(s,doEval=True,returnWithChecksum=True):
    """
    Decode base58 string

    Mostly ripped from:
    https://github.com/jgarzik/python-bitcoinlib/blob/master/bitcoin/base58.py
    """

    if not s:
        if doEval:
            return '', False
        else:
            return ''

    b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n1 = 0
    for c in s:
        n1 *= 58
        if c not in b58_digits:
            raise Exception('base58_decode() Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n1 += digit
    h = '%x' % n1
    if len(h) % 2:
        h = '0' + h
    res = str(h)
    pad = 0
    for c in s:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    outputStrWithChecksum = '00' * pad + res
    outputStrNoCheck = outputStrWithChecksum[:-8]
    outputLength = int(len(outputStrWithChecksum) - 8)
    checksum = hexlify(unhexlify(outputStrWithChecksum[outputLength:]))
    if returnWithChecksum:
        outputStr = outputStrWithChecksum
    else:
        outputStr = outputStrNoCheck
    if doEval:
        return hexlify(unhexlify(outputStr)), base58_check(outputStrNoCheck) == checksum
    else:
        return hexlify(unhexlify(outputStr))

def base58_check_and_encode(a):
    """Perform base58 check and then encode input and checksum"""
    try:
        abc = unhexlify(a)
        defg = int(a,16)
    except:
        raise Exception('base58_check_and_encode() Invalid input')
    a = hexlify(unhexlify(a))
    return base58_encode(a,'',base58_check(a))

def hash160(inputhex):
    """Return ripemd160(sha256()) for given input hex."""

    try:
        test = int(inputhex,16)
        inputhex = unhexlify(inputhex)
        test = ''
    except:
        raise Exception('hash160() Invalid input')
    ripe160 = hashlib.new('ripemd160')
    sha256Hash = sha256(inputhex).digest()
    ripe160.update(sha256Hash)
    ripe160.digest()
    output = hex_to_hexstr(ripe160.hexdigest()).zfill(40)
    return hexlify(unhexlify(output))

def pubkey_to_address(pubKey,versionbyte='00'):
    """Convert public key into arbitrary altcoin address string"""
    versionstr = hex_to_hexstr(hexlify(unhexlify(versionbyte)),2)
    hash160str = hex_to_hexstr(hash160(hexlify(unhexlify(pubKey))),40)
    hash160withversionbyte = hexlify(unhexlify(versionstr + hash160str))
    return base58_check_and_encode(hash160withversionbyte) 

def privkey_to_pubkey(privkey,compressed=False):
    """Derive public key from private key hex input"""

    try:
        privkey = int(privkey,16)
    except:
        raise Exception('privkey_to_pubkey() Input not hex')
    pubX, pubY = ec_multiply(Gx,Gy,privkey)
    pubX = hexstrlify(pubX,64)
    pubY = hexstrlify(pubY,64)
    uncompressedpub = hexlify(unhexlify('04' + pubX + pubY))
    if compressed:
        return compress_pub_key(uncompressedpub)
    else:
        return uncompressedpub

def double_sha256_hex(hexinput):
    """Takes hex or hexstr in and returns hex"""
    return hexlify(unhexlify(sha256(sha256(unhexlify(hexinput)).digest()).hexdigest()))
