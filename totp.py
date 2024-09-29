#!/usr/bin/env python3

import hmac
import hashlib
import time
import base64


# https://www.ietf.org/rfc/rfc4226.txt
def hotp(secret, count, length=6, digestmod=hashlib.sha1):

    if type(secret) == str:
        secret = base64.b32decode(secret)

    assert length >= 6, "length too short"

    hmac_result = hmac.new(key=secret, msg=int(count).to_bytes(8, byteorder='big'), digestmod=digestmod).digest()

    offset = hmac_result[len(hmac_result) - 1] & 0x0f

    bin_code = int.from_bytes(hmac_result[offset:offset+4], byteorder='big') & 0x7fffffff

    return f'{bin_code % pow(10, length):0{length}d}'


# https://www.ietf.org/rfc/rfc6238.txt
def totp(secret, time=time.time(), timestep=30, length=6, digestmod=hashlib.sha1):
    return hotp(secret, time // timestep, length, digestmod)


if __name__ == '__main__':
    # https://www.ietf.org/rfc/rfc4226.txt page 32
    assert hotp('12345678901234567890'.encode('utf-8'), 0, 6, hashlib.sha1) == '755224'
    assert hotp('12345678901234567890'.encode('utf-8'), 1, 6, hashlib.sha1) == '287082'
    assert hotp('12345678901234567890'.encode('utf-8'), 2, 6, hashlib.sha1) == '359152'
    assert hotp('12345678901234567890'.encode('utf-8'), 3, 6, hashlib.sha1) == '969429'
    assert hotp('12345678901234567890'.encode('utf-8'), 4, 6, hashlib.sha1) == '338314'
    assert hotp('12345678901234567890'.encode('utf-8'), 5, 6, hashlib.sha1) == '254676'
    assert hotp('12345678901234567890'.encode('utf-8'), 6, 6, hashlib.sha1) == '287922'
    assert hotp('12345678901234567890'.encode('utf-8'), 7, 6, hashlib.sha1) == '162583'
    assert hotp('12345678901234567890'.encode('utf-8'), 8, 6, hashlib.sha1) == '399871'
    assert hotp('12345678901234567890'.encode('utf-8'), 9, 6, hashlib.sha1) == '520489'

    # https://www.ietf.org/rfc/rfc6238.txt page 15
    assert totp('12345678901234567890'.encode('utf-8'),          59, 30, 8, hashlib.sha1) == '94287082'
    assert totp('12345678901234567890'.encode('utf-8'),  1111111109, 30, 8, hashlib.sha1) == '07081804'
    assert totp('12345678901234567890'.encode('utf-8'),  1111111111, 30, 8, hashlib.sha1) == '14050471'
    assert totp('12345678901234567890'.encode('utf-8'),  1234567890, 30, 8, hashlib.sha1) == '89005924'
    assert totp('12345678901234567890'.encode('utf-8'),  2000000000, 30, 8, hashlib.sha1) == '69279037'
    assert totp('12345678901234567890'.encode('utf-8'), 20000000000, 30, 8, hashlib.sha1) == '65353130'

    # https://www.ietf.org/rfc/rfc6238.txt page 15, with errata'd secret key
    assert totp('12345678901234567890123456789012'.encode('utf-8'),          59, 30, 8, hashlib.sha256) == '46119246'
    assert totp('12345678901234567890123456789012'.encode('utf-8'),  1111111109, 30, 8, hashlib.sha256) == '68084774'
    assert totp('12345678901234567890123456789012'.encode('utf-8'),  1111111111, 30, 8, hashlib.sha256) == '67062674'
    assert totp('12345678901234567890123456789012'.encode('utf-8'),  1234567890, 30, 8, hashlib.sha256) == '91819424'
    assert totp('12345678901234567890123456789012'.encode('utf-8'),  2000000000, 30, 8, hashlib.sha256) == '90698825'
    assert totp('12345678901234567890123456789012'.encode('utf-8'), 20000000000, 30, 8, hashlib.sha256) == '77737706'

    # https://www.ietf.org/rfc/rfc6238.txt page 15, with errata'd secret key
    assert totp('1234567890123456789012345678901234567890123456789012345678901234'.encode('utf-8'),          59, 30, 8, hashlib.sha512) == '90693936'
    assert totp('1234567890123456789012345678901234567890123456789012345678901234'.encode('utf-8'),  1111111109, 30, 8, hashlib.sha512) == '25091201'
    assert totp('1234567890123456789012345678901234567890123456789012345678901234'.encode('utf-8'),  1111111111, 30, 8, hashlib.sha512) == '99943326'
    assert totp('1234567890123456789012345678901234567890123456789012345678901234'.encode('utf-8'),  1234567890, 30, 8, hashlib.sha512) == '93441116'
    assert totp('1234567890123456789012345678901234567890123456789012345678901234'.encode('utf-8'),  2000000000, 30, 8, hashlib.sha512) == '38618901'
    assert totp('1234567890123456789012345678901234567890123456789012345678901234'.encode('utf-8'), 20000000000, 30, 8, hashlib.sha512) == '47863826'
