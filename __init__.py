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
from Crypto.Cipher import AES
try:
    import scrypt
except ImportError:
    # pyscrypt is an "emergency backup" pure python implementation
    # for use if you can't get the scrypt C wrapper module installed...
    # but it's like 300x slower than the C implementation, so you should
    # really try to get the scrypt wrapper module working.
    import pyscrypt as scrypt # https://bitbucket.org/mhallin/py-scrypt/src
from pyBIP0038.helper_funcs_and_vars import *


def aes_encrypt_bip38(msg,key,pad='{',blocksize=16):
    """
    Very simple AES encryption, with parameters specifically for
    use in BIP0038.

    # Doctest done this way so it outputs the same for Python 2 and 3
    >>> hexstrlify(aes_encrypt_bip38(unhexlify("45e8364d907e802d87d3b29f4b527b49"),unhexlify("3cfc181482b735941483ec8f158314f9ada2aa0d6e4a5c15bd46515092716d3b")))
    '8f4b4aa6e27d1669ba5dd6039c16d4f1'
    >>> hexstrlify(aes_encrypt_bip38(unhexlify("45e8364d907e802d87d3b29f4b7b7b7b"),unhexlify("3cfc181482b735941483ec8f158314f9ada2aa0d6e4a5c15bd46515092716d3b")))
    '1e7bddc6f793d4444e61a99f5e57fd44'
    """

    msg, key = hexstrlify(msg), hexstrlify(key)
    if len(key) != 64:
        raise Exception('aes_encrypt_bip38() key size must be 32 bytes')
    key = unhexlify(key)
    pad = hexstrlify(pad.encode('utf-8'))
    pad_len = blocksize - (len(msg) % blocksize)
    for i in range(pad_len):
        msg = msg + pad
    cipher = AES.new(key)
    return unhexlify(hexstrlify(cipher.encrypt(unhexlify(msg)),64)[:-32])

def aes_decrypt_bip38(encMsg,key,pad='{'):
    """
    Very simple AES decryption, with parameters specifically for
    use in BIP0038.

    # Doctest done this way so it outputs the same for Python 2 and 3
    >>> hexstrlify(aes_decrypt_bip38(unhexlify("8f4b4aa6e27d1669ba5dd6039c16d4f1"),unhexlify("3cfc181482b735941483ec8f158314f9ada2aa0d6e4a5c15bd46515092716d3b")))
    '45e8364d907e802d87d3b29f4b527b49'
    >>> hexstrlify(aes_decrypt_bip38(unhexlify("1e7bddc6f793d4444e61a99f5e57fd44"),unhexlify("3cfc181482b735941483ec8f158314f9ada2aa0d6e4a5c15bd46515092716d3b")))
    '45e8364d907e802d87d3b29f4b7b7b7b'
    """

    pad = pad.encode('utf-8')
    key = hexstrlify(key)
    if len(key) != 64:
        raise Exception('aes_decrypt_bip38() key size must be 32 bytes')
    key = unhexlify(key)
    cipher = AES.new(key)
    msg = cipher.decrypt(encMsg)
    try:
        msg = msg.rstrip(pad)
    except:
        msg = msg.rstrip(bytes(pad,'utf-8'))
    if len(msg) != 16:
        if len(msg) > 16:
            raise Exception('aes_decrypt_bip38() decrypted msg larger than 16 bytes after pad strip')
        else:
            msg = msg + pad * int(16 - len(msg))
    return msg

def intermediate_code(password,useLotAndSequence=False,lot=100000,sequence=0,
                      _doctest_ownersalt=os.urandom(4),_doctest_ownersalt2=os.urandom(8)):
    """
    Generates an intermediate code, as outlined by the BIP0038
    wiki, found at:

    https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

    Output is a string, beginning with 'passphrase'.  Lot and
    sequence inputs are ints.  Even though the Lot range is only
    recommended to be in the range 100000-999999, that
    recommendation is enforced in this code.  Sequence is in the
    range 0-4095.

    Also, note that the wiki test vectors do not include examples
    for compressed keys with EC multiplication.  Nor does the 
    Bitcoin Address Utility reference implementation successfully
    identify 'cfrm38' confirmation codes for compressed keys.
    This implementation works just fine with them, and the Bitcoin
    Address Utility can still decrypt the '6P' encrypted private
    keys for compressed public keys, but for compatibility with
    the reference implementation, it is highly recommended that
    you create encrypted keys and confirmation codes only for
    uncompressed public keys when using an intermediate code to
    create EC multiplied encryped private keys with confirmation
    codes.

    >>> intermediate_code("satoshi",True,339092,0,unhexlify("367f7c82"))
    'passphraseZYqSopHd1ZWbZTA3cy9Z9e8VVxUbXudrj6fY8kLDyJXMi67V2gngSv5T8ur4RQ'
    >>> intermediate_code("nakamoto",False,100000,0,'',unhexlify("f285f0292698dca5"))
    'passphrasersSAEzKBzZHbyNpgtbW7MTsJUvm8ZrXy9ZTZtR8MPA6gv9sL4kBEsGocknkR14'
    """

    password = str(password)
    if int(sys.version_info.major) == 2:
        password = unicode(password)
    password = unicodedata.normalize('NFC',password)
    password = str(password)
    try:
        password = unhexlify(hexlify(password))
    except:
        password = unhexlify(hexlify(bytearray(password,'utf-8')))
    if useLotAndSequence:
        if 'int' not in str(type(lot)):
            raise Exception('intermediate_code() lot not int')
        elif 'int' not in str(type(sequence)):
            raise Exception('intermediate_code() sequence not int')
        elif ((lot < 100000) or (lot > 999999) or (sequence < 0) or (sequence > 4095)):
            raise Exception('intermediate_code() lot or sequence out of range')
        lotsequence = hexstrlify(int(lot*4096 + sequence),8)
        ownersalt = hexstrlify(_doctest_ownersalt,8)
        ownerentropy = ownersalt + lotsequence
        ownersalt = unhexlify(ownersalt)
        magicbytes = '2ce9b3e1ff39e251'
        prefactor = hexstrlify(scrypt.hash(password,ownersalt,16384,8,8,32),64)
        ownersalt = hexstrlify(ownersalt,8)
        passfactor = double_sha256_hex(rehexlify(prefactor + ownerentropy))
    else:
        ownersalt = hexstrlify(_doctest_ownersalt2,16)
        ownerentropy = unhexlify(ownersalt)
        magicbytes = '2ce9b3e1ff39e253'
        passfactor = hexlify(scrypt.hash(password,ownerentropy,16384,8,8,32))
        ownerentropy = ownersalt # Easy convert back to hexstr
    passpoint = hex_to_hexstr(privkey_to_pubkey(passfactor,True))
    if len(passpoint) != 66:
        raise Exception('intermediate_code() passpoint length error')
    return base58_check_and_encode(rehexlify(magicbytes + ownerentropy + passpoint))

def encrypt_privkey_from_password(password,privKey,compressFlag=False):
    """
    Use BIP0038 wiki specification to encrypt a private key with a
    given password (the non-EC multiplication method).

    See the wiki for more information:
    https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

    >>> encrypt_privkey_from_password("casascius","288BB3F127CDF3C4903B3E575E6E005649591B505EC73BBF0858BD63171A9458")
    '6PRVi4uuUKF8uJW4HEzWdsWmAF51QuMB95bfuxzwyc8ibng9ToE6QXmXzY'
    >>> encrypt_privkey_from_password("casascius","288BB3F127CDF3C4903B3E575E6E005649591B505EC73BBF0858BD63171A9458",True)
    '6PYT5g7hxmejiWZy7MZZLbAUr4CJRNc5vteCVnsRJFEYTzq1qh1jdd6fz2'
    >>> encrypt_privkey_from_password("casascius","5J89GTg7An8KnM8osCLR5Vq7xKutejQNypeLHvX6gN5ZmhTEsKY")
    '6PRVi4uuUKF8uJW4HEzWdsWmAF51QuMB95bfuxzwyc8ibng9ToE6QXmXzY'
    >>> encrypt_privkey_from_password("casascius","KxaXVEjcEABKu9sTrZ2hGrFPhCUSyYAC1oHn9hDr4k39eC1pdHKA")
    '6PYT5g7hxmejiWZy7MZZLbAUr4CJRNc5vteCVnsRJFEYTzq1qh1jdd6fz2'
    """

    #Sanitize inputs
    try:
        privKey2, isValid = base58_decode(privKey,True,False)
        if (not isValid):
            raise Exception("Base58 checksum failed.")
        elif (privKey[:1] != "5" and privKey[:1] != "K" and privKey[:1] != "L") or len(str(privKey)) > 53:
            raise Exception("Input may not be base58 encoded Bitcoin private key.")
    except Exception as e:
        try:
            privKey = hex_to_hexstr(rehexlify(privKey),64)
        except Exception as f:
            raise Exception("Error with private key input. Exception on base58 decode attempt was: " + str(e) + "\nand exception on attempt to determine if input is hex was: " + str(f))
    else:
        privKey = privKey2
        privKey2 = None
        if len(str(privKey)) == 66 and privKey[:2] == '80':
            compressFlag = False
        elif len(str(privKey)) == 68 and privKey[:2] == '80' and privKey[-2:] == '01':
            compressFlag = True
    privKey = hex_to_hexstr(rehexlify(privKey),64)
    if len(privKey) == 66 or len(privKey) == 68:
        assert privKey[:2] == '80'
        privKey = privKey[2:]
    if len(privKey) == 66:
        assert privKey[-2:] == '01'
        compressFlag = True
        privKey = privKey[:-2]
    assert len(privKey) == 64
    password = str(password)
    if int(sys.version_info.major) == 2:
        password = unicode(password)
    password = unicodedata.normalize('NFC',password)
    password = str(password)
    try:
        password = unhexlify(hexlify(password))
    except:
        password = unhexlify(hexlify(bytearray(password,'utf-8')))
    prefix = '0142' # Do not use EC multiplication
    flagByte = int('11000000',2) # Doing it this way to help my understanding of the flag byte
    if compressFlag:
        flagByte = flagByte + int('20',16)
    flagByte = hexstrlify(flagByte,2)
    if len(flagByte) != 2:
        raise Exception('encrypt_from_password() flag byte length error')
    pubKey = rehexlify(privkey_to_pubkey(privKey,compressFlag))
    bitcoinPubAddress = pubkey_to_address(pubKey)
    try:
        bitcoinPubAddressStrAsHex = hexlify(bitcoinPubAddress)
    except:
        bitcoinPubAddressStrAsHex = hexlify(bytearray(bitcoinPubAddress,'ascii'))
    addresshash = hex_to_hexstr(double_sha256_hex(bitcoinPubAddressStrAsHex),64)[:8]
    scryptSalt = unhexlify(addresshash)
    scryptHash = hexstrlify(scrypt.hash(password,scryptSalt,16384,8,8,64),128)
    msg1 = unhexlify(hexstrlify(int(privKey[:-32],16) ^ int(scryptHash[:-96],16),32))
    msg2 = unhexlify(hexstrlify(int(privKey[32:],16) ^ int(scryptHash[32:-64],16),32))
    encryptedHalf1 = hexstrlify(aes_encrypt_bip38(msg1,unhexlify(scryptHash[64:])),32)
    encryptedHalf2 = hexstrlify(aes_encrypt_bip38(msg2,unhexlify(scryptHash[64:])),32)
    return base58_check_and_encode(rehexlify(prefix + flagByte + addresshash + encryptedHalf1 + encryptedHalf2))

def gen_enckey_from_intermediatecode(intermediatecode,compressFlag=False,_doctest_seedb=os.urandom(24)):
    """
    Use BIP0038 wiki specification to generate an encrypted private
    key from an intermeiate code.  Input should be str beginning
    with 'passphrase'.  First output is the base58 encoded encrypted
    private key, a str beginning with '6P'.  Seoncd output is the
    cfrm38 code, also a str.  Third output is the public address.

    As noted in the intermediate_code() __doc__, the wiki test
    vectors do not include examples for compressed EC multiplied
    encrypted keys, and the Bitcoin Address Utility reference
    implementation does not recognize cfrm38 confirmation codes
    for compressed keys.  So if you are using an intermediate code
    to generate an EC multiplied key, for compatibility purposes it
    strongly recommended that you use the uncompressed key flagbyte.
    That is why the compressFlag variable is defaulted to False.

    That being said, this implementation has no trouble verifying
    compressed confirmation codes, and the Bitcoin Address Utility
    can still properly decrypt the '6P' encrypted private keys for
    compressed keys, even though the confirmation code fails
    verification in the Utility.

    See the wiki for more information:
    https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

    >>> gen_enckey_from_intermediatecode("passphraseZYqSopHd1ZWbZTA3cy9Z9e8VVxUbXudrj6fY8kLDyJXMi67V2gngSv5T8ur4RQ",False,unhexlify("a8d8d0e0a025191571d0507d5cc6377adf30b88f1195f53f"))
    ('6PgQ2YnVRnJ71CC5pYQdnu1FzFbSoNd3a5zYZwNm61gNi2dHZRdQaLXmcz', 'cfrm38V8gYSDXGaVurnkWM1khxfovC2Cd7wy59Gfszg4RN3ixcp2qGUyN5GEd9pbu3RcQUM2KRz', '1EcGE6ozoxwkCemjzaKQCKxaLVyHT1SktW')
    >>> gen_enckey_from_intermediatecode("passphraseZYqSopHd1ZWbZTA3cy9Z9e8VVxUbXudrj6fY8kLDyJXMi67V2gngSv5T8ur4RQ",True,unhexlify("a8d8d0e0a025191571d0507d5cc6377adf30b88f1195f53f"))
    ('6PoKPpqUxPjTAJQwePHfqwekSKGNuZEzXHJ3UMVWHAsp9Fd55EHpYuYUng', 'cfrm38VXER1kfP12EAF7Av2SfvN2im4mnyyzt58FTsqHojUAeJn3UeyLkqCA3mfwMkbFhCsBc2B', '1CJLjwCUKvywUVLUM9xRhncLmGu2N4czcr')
    """

    intermediatecode = str(intermediatecode)
    if int(sys.version_info.major) == 2:
        intermediatecode = unicode(intermediatecode)
    intermediatecode = unicodedata.normalize('NFC',intermediatecode)
    intermediatecode = str(intermediatecode)
    try:
        intermediateHexStr, isValid = base58_decode(intermediatecode,True,False)
    except:
        raise Exception('gen_enckey_from_intermediatecode() base58 decode fail, check input')
    if not isValid:
        raise Exception("gen_enckey_from_intermediatecode() base58 checksum doesn't match")
    intermediateHexStr = hex_to_hexstr(intermediateHexStr,98)
    if intermediateHexStr[:4].lower() != '2ce9' or len(intermediateHexStr) != 98:
        print(intermediateHexStr)
        raise Exception('gen_enckey_from_intermediatecode() input is not intermediate code')
    prefix = '0143' # Use EC multiplication
    flagByte = int('00000000',2) # Doing it this way to help my understanding of the flag byte
    if compressFlag:
        flagByte = flagByte + int('20',16)
    flagByte = hexstrlify(flagByte,2)
    if len(flagByte) != 2:
        raise Exception('gen_enckey_from_intermediatecode() flag byte length error 1')
    lotsequencebyte = intermediateHexStr[14:-82]
    if lotsequencebyte != '53' and lotsequencebyte != '51':
        raise Exception('gen_enckey_from_intermediatecode() lotsequence byte not 51 or 53')
    magicBytes = intermediateHexStr[:-82]
    ownerentropy = intermediateHexStr[16:-66]
    passpoint = intermediateHexStr[32:]
    if lotsequencebyte == '51': # If Lot and sequence are used
        lotsequence = ownerentropy[8:]
        ownersalt = ownerentropy[:-8]
        flagByte = hexstrlify(int(flagByte,16) + int('04',16),2)
        if len(flagByte) != 2:
            raise Exception('gen_enckey_from_intermediatecode() flag byte length error 2')
    else: # If Lot and sequence are not used
        ownersalt = ownerentropy
    seedb = hexstrlify(_doctest_seedb,48)
    factorb = double_sha256_hex(rehexlify(seedb))
    passpointUncompressed = hex_to_hexstr(uncompress_pubkey(passpoint),130)
    if passpointUncompressed[:2] != '04':
        raise Exception('gen_enckey_from_intermediatecode() passpoint decompression error')
    passpointX = passpointUncompressed[2:-64]
    passpointY = passpointUncompressed[66:]
    genX, genY = ec_multiply(int(passpointX,16),int(passpointY,16),int(factorb,16))
    genKey = rehexlify('04' + hexstrlify(genX,64) + hexstrlify(genY,64))
    if compressFlag:
        genKey = compress_pub_key(genKey)
    genKey = rehexlify(genKey)
    generatedaddress = pubkey_to_address(genKey)
    try:
        generatedaddressStrAsHex = hexlify(generatedaddress)
    except:
        generatedaddressStrAsHex = hexlify(bytearray(generatedaddress,'ascii'))
    addresshash = hex_to_hexstr(double_sha256_hex(generatedaddressStrAsHex),64)[:8]
    passphrase = unhexlify(passpoint)
    scryptSalt = unhexlify(addresshash + ownerentropy)
    scryptHash = hexstrlify(scrypt.hash(passphrase,scryptSalt,1024,1,1,64),128)
    msg1 = unhexlify(hexstrlify(int(seedb[:-16],16) ^ int(scryptHash[:-96],16),32))
    encryptedHalf1 = hexstrlify(aes_encrypt_bip38(msg1,unhexlify(scryptHash[64:])),32)
    msg2 = unhexlify(hexstrlify(int(encryptedHalf1[16:] + seedb[32:],16) ^ int(scryptHash[32:-64],16),32))
    encryptedHalf2 = hexstrlify(aes_encrypt_bip38(msg2,unhexlify(scryptHash[64:])),32)
    finalHexStr = prefix + flagByte + addresshash + ownerentropy + encryptedHalf1[:-16] + encryptedHalf2
    # End enc priv key creation, now we are deriving the cfrm38 code
    pointb = hex_to_hexstr(privkey_to_pubkey(factorb,True),66)
    if pointb[:2] != '02' and pointb[:2] != '03':
        raise Exception('gen_enckey_from_intermediatecode() cfrm38 pointb derivation error')
    pointbprefix = hexstrlify((int(scryptHash[126:],16) & int('01',16)) ^ int(pointb[:-64],16),2)
    cfrm_msg1 = unhexlify(hexstrlify(int(pointb[2:-32],16) ^ int(scryptHash[:-96],16),32))
    pointbx1 = hexstrlify(aes_encrypt_bip38(cfrm_msg1,unhexlify(scryptHash[64:])),32)
    cfrm_msg2 = unhexlify(hexstrlify(int(pointb[34:],16) ^ int(scryptHash[32:-64],16),32))
    pointbx2 = hexstrlify(aes_encrypt_bip38(cfrm_msg2,unhexlify(scryptHash[64:])),32)
    encryptedpointb = pointbprefix + pointbx1 + pointbx2
    cfrmHexString = '643bf6a89a' + flagByte + addresshash + ownerentropy + encryptedpointb
    return base58_check_and_encode(rehexlify(finalHexStr)), base58_check_and_encode(rehexlify(cfrmHexString)), generatedaddress

def confirm_code(password,cfrmCode,returnLot=False):
    """
    Returns a bitcoin address if the cfrm38 code is confirmed, or
    False if the code does not confirm.  As mentioned elsewhere, the
    official BIP0038 draft test vectors do not includes EC multiplied
    keys and confirmation codes for compressed public keys, and the
    Bitcoin Address Utility reference implementation does not validate
    confirmation codes for compressed addresses, so for compatability
    purposes, it is strongly recommended that you create uncompressed
    EC multiplied keys and confirmation codes when creating them with
    this module.  This module has no problem creating or validating
    compressed keys, so the option is still available, it is just set
    to uncompressed keys by default.

    returnLot bool is whether or not to return lot and sequence
    numbers with the output, assuming the confirmation code is valid.
    If returnLot is set to True, but the flagbyte indicates lot and
    sequence are not used, then this method will return False for
    the lot and sequence outputs.

    >>> confirm_code("satoshi","cfrm38V8gYSDXGaVurnkWM1khxfovC2Cd7wy59Gfszg4RN3ixcp2qGUyN5GEd9pbu3RcQUM2KRz")
    '1EcGE6ozoxwkCemjzaKQCKxaLVyHT1SktW'
    >>> confirm_code("satoshi","cfrm38V8gYSDXGaVurnkWM1khxfovC2Cd7wy59Gfszg4RN3ixcp2qGUyN5GEd9pbu3RcQUM2KRz",True)
    ('1EcGE6ozoxwkCemjzaKQCKxaLVyHT1SktW', 339092, 0)
    >>> confirm_code("dorian","cfrm38V8gYSDXGaVurnkWM1khxfovC2Cd7wy59Gfszg4RN3ixcp2qGUyN5GEd9pbu3RcQUM2KRz",True)
    (False, False, False)
    """

    password = str(password)
    cfrmCode = str(cfrmCode)
    if int(sys.version_info.major) == 2:
        password = unicode(password)
        cfrmCode = unicode(cfrmCode)
    password = unicodedata.normalize('NFC',password)
    cfrmCode = unicodedata.normalize('NFC',cfrmCode)
    password = str(password)
    cfrmCode = str(cfrmCode)
    try:
        password = unhexlify(hexlify(password))
    except:
        password = unhexlify(hexlify(bytearray(password,'utf-8')))
    try:
        confirmHexStr, isValid = base58_decode(cfrmCode,True,False)
    except:
        raise Exception('confirm_code() base58 decode failure on cfrm38 code')
    if not isValid:
        raise Exception('confirm_code() base58 checksum does not match for cfrm38 code')
    confirmHexStr = hex_to_hexstr(confirmHexStr)
    if len(confirmHexStr) != 102 or confirmHexStr[:10].lower() != '643bf6a89a':
        raise Exception('confirm_code() second input does not appear to be cfrm38 code')
    flagByte = confirmHexStr[10:-90]
    addresshash = confirmHexStr[12:-82]
    ownerentropy = confirmHexStr[20:-66]
    encryptedpointb = confirmHexStr[36:]
    if flagByte.lower() in LOTSEQUENCE_FLAGBYTES:
        ownersalt = ownerentropy[:-8]
        lotsequence = ownerentropy[8:]
    else:
        lotsequence = False
        ownersalt = ownerentropy
    ownersalt = unhexlify(ownersalt)
    prefactor = hexstrlify(scrypt.hash(password,ownersalt,16384,8,8,32),64)
    if flagByte.lower() in LOTSEQUENCE_FLAGBYTES:
        passfactor = double_sha256_hex(prefactor + ownerentropy)
    else:
        passfactor = prefactor
    passfactor = rehexlify(passfactor)
    passpoint = rehexlify(privkey_to_pubkey(passfactor,True))
    scryptPass = unhexlify(passpoint)
    scryptSalt = unhexlify(addresshash + ownerentropy)
    scryptHash = hexstrlify(scrypt.hash(scryptPass,scryptSalt,1024,1,1,64),128)
    encpointbprefix = encryptedpointb[:-64]
    cfrmHexStr1 = aes_decrypt_bip38(unhexlify(encryptedpointb[2:-32]),unhexlify(scryptHash[64:]))
    cfrmHexStr2 = aes_decrypt_bip38(unhexlify(encryptedpointb[34:]),unhexlify(scryptHash[64:]))
    cfrmHexStr1, cfrmHexStr2 = hexlify(cfrmHexStr1), hexlify(cfrmHexStr2)
    pointbFirstHalf = hexstrlify(int(cfrmHexStr1,16) ^ int(scryptHash[:-96],16),32)
    pointbSecondHalf = hexstrlify(int(cfrmHexStr2,16) ^ int(scryptHash[32:-64],16),32)
    pointbprefix = hexstrlify(int(encpointbprefix,16) ^ (int(scryptHash[126:],16) & int('01',16)),2)
    pointb = pointbprefix + pointbFirstHalf + pointbSecondHalf
    if pointb[:2] != '02' and pointb[:2] != '03':
        raise Exception('confirm_code() pointb prefix decryption error, pointb prefix was:  ' + str(pointbprefix))
    pointbUncompressed = hex_to_hexstr(uncompress_pubkey(pointb),130)
    if len(pointbUncompressed) != 130 or pointbUncompressed[:2] != '04':
        raise Exception('confirm_code() unknown pointb error')
    pointbX = int(pointbUncompressed[2:-64],16)
    pointbY = int(pointbUncompressed[66:],16)
    cfrmKeyX, cfrmKeyY = ec_multiply(pointbX,pointbY,int(passfactor,16))
    cfrmKey = rehexlify('04' + hexstrlify(cfrmKeyX,64) + hexstrlify(cfrmKeyY,64))
    if flagByte.lower() in COMPRESSION_FLAGBYTES:
        cfrmKey = compress_pub_key(cfrmKey)
    cfrmKey = rehexlify(cfrmKey)
    confrimAddress = pubkey_to_address(cfrmKey)
    try:
        confrimAddressStrAsHex = hexlify(confrimAddress)
    except:
        confrimAddressStrAsHex = hexlify(bytearray(confrimAddress,'ascii'))
    addresshash2 = hex_to_hexstr(double_sha256_hex(confrimAddressStrAsHex),64)[:8]
    if (not lotsequence) and returnLot:
        if addresshash2 == addresshash:
            return confrimAddress, False, False
        else:
            return False, False, False
    elif not returnLot:
        if addresshash2 == addresshash:
            return confrimAddress
        else:
            return False
    else:
        if addresshash2 == addresshash:
            lotsequence = int(lotsequence,16)
            sequenceNum = int(lotsequence % 4096)
            lotNum = int((lotsequence - sequenceNum) // 4096)
            return confrimAddress, lotNum, sequenceNum
        else:
            return False, False, False

def decrypt_priv_key(password,encKey,returnLot=False):
    """
    Decrypts a BIP0038 encrypted private key.  Input password is
    str, input key is str beginning with '6P'.  Output is str of
    base58 check-encoded bitcoin private key.  If returnLot is True
    and there are lot/sequence bytes included in an EC-multiplied 
    encrypted key, those lot and sequence numbers are returned as well.
    If returnLot is set to True but the key does not contain lot and 
    sequence bytes, lot and sequence outputs are returned as 'False'.

    >>> decrypt_priv_key("satoshi","6PgQ2YnVRnJ71CC5pYQdnu1FzFbSoNd3a5zYZwNm61gNi2dHZRdQaLXmcz")
    '5JhL4awp3UDFMWqASNDk6ZXJ8XfnEatHUS8gxYrsVWBKqPJgCQk'
    >>> decrypt_priv_key("satoshi","6PgQ2YnVRnJ71CC5pYQdnu1FzFbSoNd3a5zYZwNm61gNi2dHZRdQaLXmcz",True)
    ('5JhL4awp3UDFMWqASNDk6ZXJ8XfnEatHUS8gxYrsVWBKqPJgCQk', 339092, 0)
    >>> decrypt_priv_key("dorian","6PgQ2YnVRnJ71CC5pYQdnu1FzFbSoNd3a5zYZwNm61gNi2dHZRdQaLXmcz")
    False
    >>> decrypt_priv_key("casascius","6PYT5g7hxmejiWZy7MZZLbAUr4CJRNc5vteCVnsRJFEYTzq1qh1jdd6fz2",True)
    ('KxaXVEjcEABKu9sTrZ2hGrFPhCUSyYAC1oHn9hDr4k39eC1pdHKA', False, False)
    """

    password = str(password)
    encKey = str(encKey)
    if int(sys.version_info.major) == 2:
        password = unicode(password)
        encKey = unicode(encKey)
    password = unicodedata.normalize('NFC',password)
    encKey = unicodedata.normalize('NFC',encKey)
    password = str(password)
    encKey = str(encKey)
    try:
        password = unhexlify(hexlify(password))
    except:
        password = unhexlify(hexlify(bytearray(password,'utf-8')))
    if encKey[:2] != '6P':
        raise Exception('decrypt_priv_key() private key input must begin with 6P')
    try:
        encKeyHex, isValid = base58_decode(encKey,True,False)
    except:
        raise Exception('decrypt_priv_key() private key base58 decode failure')
    if not isValid:
        raise Exception('decrypt_priv_key() private key base58 checksum does not match')
    encKeyHex = hex_to_hexstr(encKeyHex,78)
    if len(encKeyHex) != 78 or encKeyHex[:3] != '014':
        raise Exception('decrypt_priv_key() private key input error')
    prefix = encKeyHex[:-74]
    flagByte = encKeyHex[4:-72]
    if prefix == '0142':
        salt = encKeyHex[6:-64]
        encryptedHalf1 = encKeyHex[14:-32]
        encryptedHalf2 = encKeyHex[46:]
    elif prefix == '0143':
        addresshash = encKeyHex[6:-64]
        ownerentropy = encKeyHex[14:-48]
        encryptedHalf1FirstHalf = encKeyHex[30:-32]
        encryptedHalf2 = encKeyHex[46:]
    else:
        raise Exception('decrypt_priv_key() unknown private key input error 1')
    if prefix == '0142':
        scryptSalt = unhexlify(salt)
        scryptHash = hexstrlify(scrypt.hash(password,scryptSalt,16384,8,8,64),128)
        decryption1 = hexlify(aes_decrypt_bip38(unhexlify(encryptedHalf1),unhexlify(scryptHash[64:])))
        decryption2 = hexlify(aes_decrypt_bip38(unhexlify(encryptedHalf2),unhexlify(scryptHash[64:])))
        privKeyHalf1 = hexstrlify(int(decryption1,16) ^ int(scryptHash[:-96],16),32)
        privKeyHalf2 = hexstrlify(int(decryption2,16) ^ int(scryptHash[32:-64],16),32)
        privKeyHex = rehexlify(privKeyHalf1 + privKeyHalf2)
        if flagByte.lower() in COMPRESSION_FLAGBYTES:
            pubKey = privkey_to_pubkey(privKeyHex,True)
        else:
            pubKey = privkey_to_pubkey(privKeyHex,False)
        pubKey = rehexlify(pubKey)
        bitcoinAddress = pubkey_to_address(pubKey)
        try:
            bitcoinAddressStrAsHex = hexlify(bitcoinAddress)
        except:
            bitcoinAddressStrAsHex = hexlify(bytearray(bitcoinAddress,'ascii'))
        fourByteCheckSum = hex_to_hexstr(double_sha256_hex(bitcoinAddressStrAsHex),64)[:8]
        if fourByteCheckSum == salt:
            privKeyHex = hex_to_hexstr(privKeyHex,64)
            privKeyHex = '80' + privKeyHex
            if flagByte.lower() in COMPRESSION_FLAGBYTES:
                privKeyHex = privKeyHex + '01'
            if returnLot:
                return base58_check_and_encode(rehexlify(privKeyHex)), False, False
            else:
                return base58_check_and_encode(rehexlify(privKeyHex))
        else:
            if returnLot:
                return False, False, False
            else:
                return False
    elif prefix == '0143':
        if flagByte.lower() in LOTSEQUENCE_FLAGBYTES:
            lotsequence = ownerentropy[8:]
            ownersalt = ownerentropy[:-8]
            returnlot2 = True
        else:
            ownersalt = ownerentropy
            returnlot2 = False
        scryptSalt = unhexlify(ownersalt)
        prefactor = hexstrlify(scrypt.hash(password,scryptSalt,16384,8,8,32),64)
        if flagByte.lower() in LOTSEQUENCE_FLAGBYTES:
            passfactor = double_sha256_hex(prefactor + ownerentropy)
        else:
            passfactor = prefactor
        passfactor = rehexlify(passfactor)
        passpoint = rehexlify(privkey_to_pubkey(passfactor,True))
        password2 = unhexlify(passpoint)
        scryptSalt2 = unhexlify(addresshash + ownerentropy)
        secondSeedbKey = hexstrlify(scrypt.hash(password2,scryptSalt2,1024,1,1,64),128)
        decryption2 = hexlify(aes_decrypt_bip38(unhexlify(encryptedHalf2),unhexlify(secondSeedbKey[64:])))
        encryptedHalf1SecondHalfCATseedblastthird = \
                       hexstrlify(int(decryption2,16) ^ int(secondSeedbKey[32:-64],16),32)
        encryptedHalf1 = (encryptedHalf1FirstHalf + encryptedHalf1SecondHalfCATseedblastthird[:-16])
        decryption1 = hexlify(aes_decrypt_bip38(unhexlify(encryptedHalf1),unhexlify(secondSeedbKey[64:])))
        seedbFirstPart = hexstrlify(int(decryption1,16) ^ int(secondSeedbKey[:-96],16),16)
        seedb = rehexlify(seedbFirstPart + encryptedHalf1SecondHalfCATseedblastthird[16:])
        factorb = double_sha256_hex(seedb)
        newPrivKey = rehexlify(hexstrlify(int((int(factorb,16) * int(passfactor,16)) % N_ORDER),64))
        if flagByte.lower() in COMPRESSION_FLAGBYTES:
            newPubKey = rehexlify(privkey_to_pubkey(newPrivKey,True))
        else:
            newPubKey = rehexlify(privkey_to_pubkey(newPrivKey,False))
        bitcoinAddress = pubkey_to_address(newPubKey)
        try:
            bitcoinAddressStrAsHex = hexlify(bitcoinAddress)
        except:
            bitcoinAddressStrAsHex = hexlify(bytearray(bitcoinAddress,'ascii'))
        checksum = hex_to_hexstr(double_sha256_hex(bitcoinAddressStrAsHex),64)[:8]
        if checksum == addresshash:
            newPrivKey = hex_to_hexstr(newPrivKey,64)
            newPrivKey = '80' + newPrivKey
            if flagByte.lower() in COMPRESSION_FLAGBYTES:
                newPrivKey = newPrivKey + '01'
            if returnLot:
                if returnlot2:
                    lotsequence = int(lotsequence,16)
                    sequenceNum = int(lotsequence % 4096)
                    lotNum = int((lotsequence - sequenceNum) // 4096)
                    return base58_check_and_encode(rehexlify(newPrivKey)), lotNum, sequenceNum
                else:
                    return base58_check_and_encode(rehexlify(newPrivKey)), False, False
            else:
                return base58_check_and_encode(rehexlify(newPrivKey))
        else:
            if returnLot:
                return False, False, False
            else:
                return False
    else:
        raise Exception('decrypt_priv_key() unknown private key input error 2')

def encode_version_byte(ecnKeyInput,versionByte='80'):
    """
    Adds a version byte to an encrypted private key, and changes
    the beginning from "6P" to "6V".  Not sure whether version byte
    should be public or private version byte, but I've defaulted to
    private, with the default being bitcoin private key format '80'.

    ***WARNING***
    This is not an official change.
#   >>>>>>> It is not used or supported ANYWHERE ELSE. <<<<<<<<
    This is a novelty function available only in this module.
    ***END WARNING***

    >>> encode_version_byte("6PRQvv84z2zaLJHt96j7LNuCXUt1z8FTY76MAzRUJuNVHPTrwASw8SA5bJ")
    '6VC7VZmC7nP6XdUDFyd9VbMeN9CokzqzkPn8aZDF9xMdUkZWETAFB8EJUEgA'
    >>> encode_version_byte("6PRQvv84z2zaLJHt96j7LNuCXUt1z8FTY76MAzRUJuNVHPTrwASw8SA5bJ","30")
    '6VAn46FeteNanwEukZcAiPmM9bHVQ8EBuFnEYc5HRY2PX9uY6L6GF86VLtte'
    >>> encode_version_byte("6PgMhJbWE3chLKeWF2YhpDURxR4uWKGtxby6Amx7ttcJJbP7PK6ga8c8Mj","c7")
    '6VHZKGUhVJi6XUc3JiFAVNpbJ4of1k2oXU9JwYeDjp6RSyMEGhR4yEZTeZpi'
    """

    try:
        encKeyHex, isValid = base58_decode(ecnKeyInput,True,False)
    except:
        raise TypeError("First input must be encrypted private key str beginning with '6P'.")
    try:
        versionByte = hexstrlify(unhexlify(versionByte),2)
        if len(versionByte) != 2 or 'int' in str(type(versionByte)):
            raise Exception(" ")
    except:
        raise TypeError("Second input must be 2-char hex str version byte.")
    if ecnKeyInput[:2] != '6P' or len(ecnKeyInput) != 58:
        raise TypeError("First input is not an encrypted private key str beginning with '6P'.")
    if not isValid:
        raise Exception("Input private key checksum failed on base58 decode attempt. Check for typos.")
    # The range for retaining the '6V' prefix is 0x10dd to 0x10e9.
    # The last char can thus potentially be used to store extra information
    # since 10d and 10e are all that is needed to convey 0142 or 0143.
    # However, I have set the defaults to be fixed at df and e0 just so the output
    # is deterministic.  The decode function doesn't check the last char, so you can
    # change it if you want.
    encKeyHex = hex_to_hexstr(encKeyHex)
    if str(encKeyHex)[:4] == '0142':
        newFirstBytes = '10df'
    elif str(encKeyHex)[:4] == '0143':
        newFirstBytes = '10e0'
    else:
        raise Exception("Unknown error with input. Base58 decoded hex was: " + str(encKeyHex))
    outputHexStr = str(str(newFirstBytes) + str(versionByte) + encKeyHex[4:])
    return base58_check_and_encode(outputHexStr)

def decode_version_byte(ecnKeyInput,outputVersion=False):
    """
    Strips version byte from a '6V' encrypted private key.
    Optionally, returns the version byte in addition to the
    6P non-version key output.

    >>> decode_version_byte("6VC7VZmC7nP6XdUDFyd9VbMeN9CokzqzkPn8aZDF9xMdUkZWETAFB8EJUEgA")
    '6PRQvv84z2zaLJHt96j7LNuCXUt1z8FTY76MAzRUJuNVHPTrwASw8SA5bJ'
    >>> decode_version_byte("6VC7VZmC7nP6XdUDFyd9VbMeN9CokzqzkPn8aZDF9xMdUkZWETAFB8EJUEgA",True)
    ('6PRQvv84z2zaLJHt96j7LNuCXUt1z8FTY76MAzRUJuNVHPTrwASw8SA5bJ', '80')
    >>> decode_version_byte("6VHZKGUhVJi6XUc3JiFAVNpbJ4of1k2oXU9JwYeDjp6RSyMEGhR4yEZTeZpi")
    '6PgMhJbWE3chLKeWF2YhpDURxR4uWKGtxby6Amx7ttcJJbP7PK6ga8c8Mj'
    """

    try:
        encKeyHex, isValid = base58_decode(ecnKeyInput,True,False)
    except:
        raise TypeError("Input must be encrypted private key str beginning with '6V'.")
    if ecnKeyInput[:2] != '6V' or len(ecnKeyInput) != 60:
        raise TypeError("Input is not a version-encrypted private key str beginning with '6V'.")
    if not isValid:
        raise Exception("Input private key checksum failed on base58 decode attempt. Check for typos.")
    encKeyHex = hex_to_hexstr(encKeyHex)
    if encKeyHex[:3] == '10d':
        newFirstBytes = '0142'
    elif encKeyHex[:3] == '10e':
        newFirstBytes = '0143'
    else:
        raise Exception("Unknown error with input.")
    outputHexStr = str(newFirstBytes) + encKeyHex[6:]
    if outputVersion:
        return base58_check_and_encode(outputHexStr), str(encKeyHex[4:6])
    else:
        return base58_check_and_encode(outputHexStr)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
