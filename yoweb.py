#!/usr/bin/env python

import web
from yoracle import YOracle

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
            web.ctx.status = '401 Unauthorized'
            return "NOTICE %s" % (e.args)
        except YOracle.ErrBase, e:
            web.ctx.status = '401 Unauthorized'
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
    webpy()
