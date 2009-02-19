#!/usr/bin/env python

import web
from yoracle import YOracle

class YOracleWebAuth:
    """YOracleWebAuth

    Webpy handler for authenticating.
    """
    def __init__(self):
        self.db = web.database(dbn='sqlite',
                               db='yoracle.sqlite')
        self.yoracle = YOracle(self.db)
        
    def GET(self):
        """YOracleWebAuth.GET()

        Handler for /auth/0/?token=%s
        """
        token = web.input()['token']
        try:
            self.yoracle.verify(token)
            return "OK"
        except YOracle.ErrNOTICE, e:
            if e.err is None:
                web.ctx.status = '409 Conflict'
            print "Notice:",e
            return "NOTICE %s" % (e.args)
        except YOracle.ErrBase, e:
            web.ctx.status = '401 Unauthorized'
            return "FAIL"

class Index:
    def GET(self):
        """Index.GET()

        Just present a form.
        """
        return """
        <html>
          <head>
            <title>YOracle web authentication</title>
          </head>
          <body>
            <h1>YOracle web authentication</h1>
            <form method='get' action='/auth/0/'>
              <input type='password' name='token' />
            </form>
          </body>
        </html>
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
