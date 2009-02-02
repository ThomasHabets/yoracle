"""

Yubikey decrypting and parsing library

"""
import re

from Crypto.Cipher import AES

RE_TOKEN = re.compile(r'^[cbdefghijklnrtuv]{44}$')
RE_AES_KEY = re.compile(r'^[0-9a-fA-F]{32}$')

class InvalidToken(Exception):
    pass

class InvalidAESKey(Exception):
    pass

class YubikeyToken:

    def __init__(self, input, aes_key):

        if not RE_TOKEN.match(input):
            raise InvalidToken('Invalid token. A token should be 44 ModHex characters.')

        if not RE_AES_KEY.match(aes_key):
            raise InvalidAESKey('Invalid AES key. The key should be 32 hexadecimal characters.')

        self.public_id = input[:-32]
        self.token = input[-32:]
        self.aes_key = aes_key
        
        token_bin = ''.join(self._modhex_decode(self.token))

        aes_key_bin = self.aes_key.decode('hex')
        aes = AES.new(aes_key_bin, AES.MODE_ECB)
        decoded = aes.decrypt(token_bin)

        self.secret_id = decoded[0:6].encode('hex')
        self.counter = ord(decoded[7]) * 256 + ord(decoded[6])
        self.timestamp = ord(decoded[10]) * 65536 + ord(decoded[9]) * 256 + ord(decoded[8])
        self.counter_session = ord(decoded[11])
        self.random_number = ord(decoded[13]) * 256 + ord(decoded[12])
        self.crc = ord(decoded[15]) * 256 + ord(decoded[14])
    
        if self._crc_check(decoded):
            self.crc_ok = True
        else:
            self.crc_ok = False

    def _modhex_decode(self, input):
        it = iter(input)
        chars = 'cbdefghijklnrtuv'
        for first, second in zip(it, it):
            yield chr(chars.index(first) * 16 + chars.index(second))

    def _crc_check(self, decoded):
        m_crc = 0xffff
        for pos in range(0, 16):
            m_crc ^= ord(decoded[pos]) & 0xff
            for i in range(0, 8):
                test = m_crc & 1
                m_crc >>= 1
                if test:
                    m_crc ^= 0x8408

        return m_crc == 0xf0b8

    def __str__(self):
        return 'Key for ID %s' % self.public_id
