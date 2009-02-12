#!/usr/bin/python

import yubikey.decrypt
import sys, re
import sha

class YOracle:
    class ErrBase(Exception):
        pass
    class ErrNOTICE(Exception):
        def __init__(self, msg):
            self.args = msg

    def __init__(self, db):
        self.db = db

    def dvorak2qwerty(self, s):
        dvorak = "`1234567890[]',.pyfgcrl/=aoeuidhtns-\\<;qjkxbmwvz"
        qwerty_us = "`1234567890-=qwertyuiop[]asdfghjkl;'\\<zxcvbnm,./"
        m = {}
        for i in range(len(dvorak)):
            m[dvorak[i]] = qwerty_us[i]
        return ''.join([m[x] for x in s])

    def decrypt(self, token):
        def try_decrypt(token):
            dbentry = self.getDbEntry(token[:12])
            try:
                y = yubikey.decrypt.YubikeyToken(token, dbentry['aeskey'])
            except Exception, e:
                raise self.ErrBase('Yubikey decode error')
                
            if not y.crc_ok:
                raise self.ErrBase('CRC error')
            return y, dbentry

        try:
            return try_decrypt(token)
        except self.ErrBase, e:
            token = self.dvorak2qwerty(token)
            return try_decrypt(token)

    def getDbEntry(self, yid, password = None):
        pw = ""
        if password is not None:
            pw = " and password = '%s'" % (password)
        try:
            return self.db.select('yubikey',
                                  where="yubikeyid='%s' %s" % (yid, pw))[0]
        except:
            raise self.ErrBase('User <%s> not found in database' % (yid))

    def verify(self, token):
        password = None
        if len(token) > 44:
            print token
            password = token[:-44]
            token = token[-44:]
            password = sha.sha(password).hexdigest()

        if len(token) != 44:
            raise YOracle.ErrBase("Wrong token length %d" % (len(token)))
            

        y, dbentry = self.decrypt(token)

        if (password is not None and password != dbentry['password']):
            raise YOracle.ErrBase("Bad password password")

        if y.counter < dbentry['counter']:
            raise YOracle.ErrBase("counter (%d) < old (%d)"
                                  % (y.counter, dbentry['counter']))

        if (y.counter == dbentry['counter']
            and y.counter_session <= dbentry['counter_session']):
            raise YOracle.ErrBase("counter == old == %d and "
                                  "counter_session (%d) <= old (%d)"
                                  % (y.counter, y.counter_session,
                                     dbentry['counter_session']))

        if y.secret_id != dbentry['secret_id']:
            raise YOracle.ErrBase("wrong secret_id %s != %s"
                                  % (y.secret_id, dbentry['secret_id']))
        
        if dbentry['counter'] != y.counter and password is None:
            raise self.ErrNOTICE('New session. Enter password before '
                                 'pressing the Yubikey button')
                
        self.db.update('yubikey',
                       counter=y.counter,
                       counter_session=y.counter_session,
                       timestamp=y.timestamp,
                       where="yubikeyid='%s'" %(y.public_id))
        return y
        
def cmdline(db):
    yoracle = YOracle(db)
    while True:
        r = raw_input("OTP: ")
        try:
            y = yoracle.verify(r)
        except YOracle.ErrNOTICE, e:
            print "NOTICE:",e.args
        except YOracle.ErrBase, e:
            print "Broken key:",e
        except Exception, e:
            print "Other exception:", e
            raise
        else:
            for k in [x for x in dir(y) if not re.match(r'_.*', x)]:
                print k, getattr(y,k)

if __name__ == '__main__':
    import web
    cmdline(web.database(dbn='sqlite', db='yoracle.sqlite'))
