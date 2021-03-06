#!/usr/bin/python

import yubikey.decrypt
import sys, re
import os.path
import pwd

try:
    import hashlib
    sha1hash = hashlib.sha1
except:
    import sha
    sha1hash = sha.sha

KEY_DATABASE='yoracle.sqlite'

def dvorak2qwerty(s):
    """dvorak2qwerty(s)
    
    If keyboard mapping was dvorak, return what the user thought
    they wrote.
    """
    dvorak = "`1234567890[]',.pyfgcrl/=aoeuidhtns-\\<;qjkxbmwvz"
    qwerty_us = "`1234567890-=qwertyuiop[]asdfghjkl;'\\<zxcvbnm,./"
    m = {}
    for i in range(len(dvorak)):
        m[dvorak[i]] = qwerty_us[i]
    return ''.join([m.get(x, x) for x in s])

def identitymapping(s):
    """identitymapping(s)
    
    No change.
    """
    return s

class YOracle:
    class ErrBase(Exception):
        pass
    class ErrNOTICE(ErrBase):
        """YOracle.ErrNOTICE

        Deny login and show message to authenticating user.
        """
        def __init__(self, msg, err = None):
            """YOracle.ErrNOTICE.__init__(msg)
            """
            self.args = msg
            self.err = err
    class ErrTempErr(ErrNOTICE):
        def __init__(self):
            YOracle.ErrNOTICE.__init__(self,
                                       "Temporary error, please try again.",
                                       err='503 Service Unavailable')
        

    def __init__(self, db):
        """YOracle.__init__(db)

        db:    web.database()-style (webpy.org) database connection object.
        """
        self.db = db

    def decrypt(self, token):
        """YOracle.decrypt(token)

        token:  44 modhex characters taken from yubikey.
                (will also correct for dvorak, trying both original
                and corrected before failing)
                
        Decrypts, but does NOT verify the token. Only the CRC is checked.

        returns tuple(y,dbentry). The database entry needs to be
        fetched anyway, so why not here.
        """
        def try_decrypt(token):
            """try_decrypt(token)

            decrypt token and check CRC. Fetch AES key from database.
            """
            # do format checks (weed out dvorak keymapping stuff before
            # SQL query.
            try:     yubikey.decrypt.YubikeyToken(token, '00' * 16)
            except:  raise self.ErrBase('Yubikey decode error')

            # decrypt token
            dbentry = self.getDbEntry(token[:12])
            try:
                y = yubikey.decrypt.YubikeyToken(token, dbentry['aeskey'])
            except Exception, e:
                raise self.ErrBase('Yubikey decode error')

            # Check CRC
            if not y.crc_ok:
                raise self.ErrBase('CRC error')
            return y, dbentry

        if len(token) != 44:
            raise YOracle.ErrBase("Wrong token length %d" % (len(token)))

        # Try with all mappings
        err = None
        for mapping in (identitymapping, dvorak2qwerty):
            try:                      return try_decrypt(mapping(token))
            except self.ErrBase, e:   err = e
        raise err

    def getDbEntry(self, yid):
        """YOracle.getDbEntry(yid)

        Get dictionary of yubikey id yid (12 characters).

        Does not correct for dvorak. (that is done in YOracle.decrypt())
        """
        try:
            return self.db.select('yubikey',
                                  where="yubikeyid=$id",
                                  vars={'id': yid})[0]
        except:
            raise self.ErrBase('User <%s> not found in database' % (yid))

    def verify(self, token):
        """YOracle.verify(token)

        Wrapper for YOracle.verify2(). Should prolly be a decorator.
        """
        def doCommit():
            try:
                t.commit()
            except:
                print "FIXME: commit fail"
                t.rollback()
                raise self.ErrTempErr()
                
        t = self.db.transaction()
        try:
            ret = self.verify2(token)
            doCommit()
        except self.ErrBase, e:
            doCommit()
            raise
        return ret
        

    def verify2(self, token):
        """YOracle.verify2(token)

        token:  static password + 44 modhex charachers. Static password can
                be null.

        On success, returns decoded object.

        On fail, raises something under YOracle.ErrBase.
        YOracle.ErrNOTICE exceptions should be displayed to enduser, others
        should not, and instead just be logged.
        """
        # if password is there, extract it
        password = None
        if len(token) > 44:
            password = token[:-44]
            token = token[-44:]
            password = sha1hash(password).hexdigest()

        y, dbentry = self.decrypt(token)

        if y.counter < dbentry['counter']:
            raise YOracle.ErrBase("counter (%d) < old (%d)"
                                  % (y.counter, dbentry['counter']))

        if y.counter == dbentry['counter']:
            # counter_session is only 8bit, will wrap
            #
            #if y.counter_session <= dbentry['counter_session']:
            #    raise YOracle.ErrBase("counter == old == %d and "
            #                          "counter_session (%d) <= old (%d)"
            #                          % (y.counter, y.counter_session,
            #                             dbentry['counter_session']))

            # timestamp wraps every 24 days or so (right?).
            # Requires re-insert.
            if y.timestamp <= dbentry['timestamp']:
                raise YOracle.ErrBase("counter == old == %d and "
                                      "timestamp (%d) <= old (%d)"
                                      % (y.counter,
                                         y.timestamp,
                                         dbentry['timestamp']))

        if y.secret_id != dbentry['secret_id']:
            raise YOracle.ErrBase("wrong secret_id %s != %s"
                                  % (y.secret_id, dbentry['secret_id']))

        #
        passwordOk = False
        if dbentry['counter'] == y.counter:
            passwordOk = dbentry['passwordok']
        if password is not None:
            passwordOk = (dbentry['password'] == password)

        # update database even if we really needed a password here
        try:
            self.db.update('yubikey',
                           counter=y.counter,
                           counter_session=y.counter_session,
                           timestamp=y.timestamp,
                           passwordok=passwordOk,
                           where="yubikeyid=$yid",
                           vars={'yid': y.public_id})
        except Exception, e:
            raise self.ErrTempErr()

        if not passwordOk:
            if password is None:
                raise self.ErrNOTICE( ('Unauthenticated session. '
                                     + 'Enter password before pressing '
                                     + 'the Yubikey button.',))
            else:
                raise self.ErrNOTICE( ('Bad password.',))
            
        return y
        
def cmdline(db):
    """cmdline(db)

    Command line OTP decryption.

    db:    web.database()-style (webpy.org) database connection object.
    """
    yoracle = YOracle(db)
    while True:
        try:
            r = raw_input("OTP: ")
        except EOFError, e:
            print
            break
        except KeyboardInterrupt, e:
            print
            break

        try:
            y = yoracle.verify(r)
        except YOracle.ErrNOTICE, e:
            print "NOTICE:", e.err, e.args[0]
        except YOracle.ErrBase, e:
            print "Invalid key:",e
        else:
            print "\nDecoded token:"
            for k in [x for x in dir(y)
                      if not (re.match(r'_.*', x)
                              or x in ('aes_key',))]:
                print "    %-20s %s" % (k, getattr(y,k))

def pamauth(db):
    """pamauth(db)

    PAM auth

    db:    web.database()-style (webpy.org) database connection object.
    """
    yoracle = YOracle(db)
    try:
        user = raw_input("")
        token = raw_input("")
        keyid = token[-44:][:12]

        try:
            for line in open(os.path.join(pwd.getpwnam(user)[5],
                                          ".yubikeys")):
                key, url = line.split(None, 1)
                if key == keyid or key == dvorak2qwerty(keyid):
                    break
            else:
                # no key matched
                return "FAIL"
        except:
            # user or their ~/.yubikeys doesn't exist
            return "FAIL"
        
        try:
            y = yoracle.verify(token)
        except YOracle.ErrNOTICE, e:
            return "NOTICE " + e.args[0]
        except YOracle.ErrBase, e:
            #print "Invalid key:",e
            return "FAIL"
        else:
            return "OK"
    except:
        raise
    return "FAIL"

if __name__ == '__main__':
    import web
    if True:
        os.chdir(os.path.dirname(sys.argv[0]))
        web.config.debug = False
        db = web.database(dbn='sqlite', db=KEY_DATABASE)
        print pamauth(db)
    else:
        cmdline(web.database(dbn='sqlite', db=KEY_DATABASE))
