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
    def __init__(self, db):
        self.db = db
    def lookupUserKey(self, user):
        return self.db.select('yubikey',
                              where="yubikeyid='%s'" % (user))[0]['aeskey']

    def decrypt(self, token):
        print token,len(token)
        try:
            userkey = self.lookupUserKey(token[:12])
            y = yubikey.decrypt.YubikeyToken(token, userkey)
            if y.crc_ok:
                return y
        except yubikey.decrypt.InvalidToken, e:
            pass
        except IndexError, e:
            pass

        try:
            token = dvorak2qwerty(token)
            userkey = self.lookupUserKey(token[:12])
            y = yubikey.decrypt.YubikeyToken(token, userkey)
            if y.crc_ok:
                return y
        except yubikey.decrypt.InvalidToken, e:
            raise self.ErrBase(e)

        raise self.ErrBase("other error")
        

def cmdline():
    yoracle = YOracle()
    while True:
        r = raw_input("OTP: ")
        try:
            y = yoracle.decrypt(r)
        except:
            print "Broken key"
            continue
        for k in [x for x in dir(y) if not re.match(r'_.*', x)]:
            print k, getattr(y,k)


class YOracleWebAuth:
    class ErrNOTICE(Exception):
        def __init__(self, msg):
            self.msg = msg
    def __init__(self):
        self.db = web.database(dbn='sqlite',
                               db='yoracle.sqlite')
        self.yoracle = YOracle(self.db)
    def getDbEntry(self, yid, password = None):
        pw = ""
        if password is not None:
            pw = " and password = '%s'" % (password)
        try:
            return self.db.select('yubikey',
                                  where="yubikeyid='%s' %s" % (yid, pw))[0]
        except IndexError, e:
            yid = dvorak2qwerty(yid)
            return self.db.select('yubikey',
                                  where="yubikeyid='%s' %s" % (yid, pw))[0]
    def GET(self):
        token = web.input()['token']
        password = None
        print token, len(token)
        
        if len(token) > 44:
            print token
            password = token[:-44]
            token = token[-44:]
            password = sha.sha(password).hexdigest()
        try:
            y = self.yoracle.decrypt(token)
            try:
                dbentry = self.getDbEntry(token[:12], password=password)
            except:
                raise YOracle.ErrBase("unknown user or bad session password")
            if y.counter < dbentry['counter']:
                raise YOracle.ErrBase("FIXME: counter < old")

            if (y.counter == dbentry['counter']
                and y.counter_session <= dbentry['counter_session']):
                raise YOracle.ErrBase("counter == old and "
                                      "counter_session <= old")

            if dbentry['counter'] != y.counter and password is None:
                raise self.ErrNOTICE('New session. Enter password before '
                                     'pressing the Yubikey button')
                

            self.db.update('yubikey',
                           counter=y.counter,
                           counter_session=y.counter_session,
                           timestamp=y.timestamp,
                           where="yubikeyid='%s'" %(y.public_id))
            return "OK"
        except self.ErrNOTICE, e:
            return "NOTICE %s" % (e.msg)
        except YOracle.ErrBase, e:
            print "Error: " + str(e) # FIXME: logfile
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
    if False:
        cmdline()
    elif True:
        webpy()
