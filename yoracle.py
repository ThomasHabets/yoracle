#!/usr/bin/python

import yubikey.decrypt
import sys, re
import web
import sha


def dvorak2qwerty(s):
    dvorak = "`1234567890[]',.pyfgcrl/=aoeuidhtns-\\<;qjkxbmwvz"
    qwerty_us = "`1234567890-=qwertyuiop[]asdfghjkl;'\\<zxcvbnm,./"
    m = {}
    for i in range(len(dvorak)):
        m[dvorak[i]] = qwerty_us[i]
    return ''.join([m[x] for x in s])

class YOracle:
    class ErrBase(Exception):
        pass
    class ErrNOTICE(Exception):
        def __init__(self, msg):
            self.args = msg
    def __init__(self, db):
        self.db = db
    def lookupUserKey(self, user):
        return self.db.select('yubikey',
                              what='aeskey',
                              where="yubikeyid='%s'" % (user))[0]['aeskey']

    def decrypt(self, token):

        def try_decrypt(token):
            dbentry = self.getDbEntry(token[:12])
            print token
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
            token = dvorak2qwerty(token)
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
        
def cmdline():
    db = web.database(dbn='sqlite', db='yoracle.sqlite')
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


class YOracleWebAuth:
    def __init__(self):
        self.db = web.database(dbn='sqlite',
                               db='yoracle.sqlite')
        self.yoracle = YOracle(self.db)
    def GET(self):
        token = web.input()['token']
        try:
            self.yoracle.verify(token)
            return "OK"
        except YOracle.ErrNOTICE, e:
            return "NOTICE %s" % (e.args)
        except YOracle.ErrBase, e:
            return "FAIL"

class Index:
    def GET(self):
        return """
        <form method="get" action='/auth/0/'>
        <input type='password' name='token' />
        </form>
        """
def webpy():
    urls = (
        r'/', Index,
        r'/auth/0/', YOracleWebAuth,
    )
    app = web.application(urls, globals())
    app.run()

if __name__ == '__main__':
    if sys.argv[1] == '-i':
        cmdline()
    elif True:
        webpy()
