"""
    Basic tests
"""

import decrypt

expected = {
    'public_id': 'cbdefghijkln',
    'secret_id': 'ab1234512345',
    'counter':  41345,
    'counter_session': 244,
    'timestamp': 12123456,
    'random_number': 32999
}

aes_key = '0123456789abcdef0123456789abcdef'
otp = 'cbdefghijklnbvhgbhebfuurheknkvulgtdejrljhifn'

print 'Testing a succesful decryption:\n'

yubikey = decrypt.YubikeyToken(otp, aes_key)

if yubikey.crc_ok:

    for key, value in expected.items():

        print '%s = %s' % (key, getattr(yubikey, key))
        if getattr(yubikey, key) == value:
            print '%s value is OK' % key
        else:
            print 'ERROR: %s value is NOT the same' % key

else:

    print 'ERROR: CRC check NOT ok'

print '\nNow testing if invalid tokens and keys get detected:\n'

# Invalid token length

otp_invalid_length = otp[1:]

try:
    yubikey = decrypt.YubikeyToken(otp_invalid_length, aes_key)
except decrypt.InvalidToken:
    print 'Invalid token length succesfully detected. OK'
else:
    print 'ERROR: invalid token length got accepted'

# Invalid token character

otp_invalid_chars = otp.replace('b', 'a')

try:
    yubikey = decrypt.YubikeyToken(otp_invalid_chars, aes_key)
except decrypt.InvalidToken:
    print 'Invalid token character succesfully detected. OK'
else:
    print 'ERROR: invalid token character got accepted'

# Invalid AES key length

aes_key_invalid_length = aes_key[1:]

try:
    yubikey = decrypt.YubikeyToken(otp, aes_key_invalid_length)
except decrypt.InvalidAESKey:
    print 'Invalid AES key length succesfully detected. OK'
else:
    print 'ERROR: invalid AES key length got accepted'

# Invalid AES character

aes_key_invalid_chars = aes_key.replace('0', 'X')

try:
    yubikey = decrypt.YubikeyToken(otp, aes_key_invalid_chars)
except decrypt.InvalidAESKey:
    print 'Invalid AES key character succesfully detected. OK'
else:
    print 'ERROR: invalid AES key character got accepted'
