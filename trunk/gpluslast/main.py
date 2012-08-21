# -*- coding: utf-8 -*-

__author__ = 'cnwesleywang@gmail.com'

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.api import urlfetch
from google.appengine.api import memcache
from google.appengine.api import taskqueue
from google.appengine.ext import db
import logging

class CfgDb(db.Model):
    thekey=db.StringProperty()
    thevalue=db.StringProperty()

class LastPost(webapp.RequestHandler):
    def get(self):
        mycfg=False
        cfgdb=CfgDb.all().filter("thekey =","keyword").get()
        if cfgdb:
            mycfg=cfgdb.thevalue
        if not mycfg:
            return
        logging.info(mycfg)
        lastpost=""
        try:
            result = urlfetch.fetch(url="https://plus.google.com/"+self.request.get("id")+"/posts") 
        except Exception,e:
            logging.error("Error fetching last post of %s,Exception:%s" % (self.request.get("id"),str(e)))
            return
        cnt= result.content.split("%s\">" % (mycfg.encode("utf-8")))[:2]
        if len(cnt)>=2:
            cnt= cnt[1].split("</div>")[:1]
            if len(cnt)>=1:
                lastpost=cnt[0].decode('utf-8')[:200] #只取前100个字符
        self.response.out.write(lastpost)

class Check(webapp.RequestHandler):
    def post(self):
        return self.get()
    def get(self):
        try:
            mycfg=memcache.get("keyword")
            if not mycfg:
                return
            lastpost=""
            try:
                result = urlfetch.fetch(url="https://plus.google.com/"+self.request.get("id")+"/posts") 
            except Exception,e:
                logging.error("Error fetching last post of %s,Exception:%s" % (self.request.get("id"),str(e)))
                return
            cnt= result.content.split("%s\">" % (mycfg.encode("utf-8")))[:2]
            if len(cnt)>=2:
                cnt= cnt[1].split("</div>")[:1]
                if len(cnt)>=1:
                    lastpost=cnt[0].decode('utf-8')[:200] #只取前100个字符

            conf=self.request.get("id")
            #logging.info("lastpost of %s (%s) memcache:(%s)" % (conf,lastpost,memcache.get(conf)))
            
            cnt=lastpost
            oldcnt=memcache.get(conf)
            if (oldcnt==None ) or (cnt != memcache.get(conf)):
                logging.info("need sync %s (%s) and (%s) not match " % (conf,cnt,memcache.get(conf)))
                res=urlfetch.fetch(url="http://gplus2ft.appspot.com/sync?id="+conf)
                if int(res.status_code)==200:
                    memcache.set(conf,cnt)
                else:
                    logging.error("Server error of %s:%d,will check next time!" % (conf,int(res.status_code)))
        except Exception,e:
            logging.error("Error check last post of %s,Exception:%s" % (self.request.get("id"),str(e)))

class CronCheck(webapp.RequestHandler):
    def get(self):
        mycfg=memcache.get("mycfg")
        if not mycfg:
            cfgdb=CfgDb.all().filter("thekey =","users").get()
            if cfgdb:
                mycfg=cfgdb.thevalue
        if not mycfg:
            return
        confs=mycfg.split("|")[:15] #最多15个人
        mycfg=False
        cfgdb=CfgDb.all().filter("thekey =","keyword").get()
        if cfgdb:
            mycfg=cfgdb.thevalue
        if not mycfg:
            return
        memcache.set("keyword",mycfg)

        for conf in confs:
            if conf.strip()!="":
                taskqueue.add(url='/check',
                    params=dict(id=conf))

class Cfg(webapp.RequestHandler):
    def get(self):
        self.response.out.write("current cfg is:"+ memcache.get("mycfg"))

class UpdateKeyWord(webapp.RequestHandler):
    def get(self):
        memcache.set("keyword",self.request.get('kw'))
        cfg=CfgDb.all().filter("thekey =","keyword").get()
        if not cfg:
            cfg=CfgDb()
            cfg.thekey="keyword"
        cfg.thevalue=self.request.get('kw')
        cfg.put()
        self.response.out.write("ok")
        logging.info("ok all");

class UpdateCfg(webapp.RequestHandler):
    def get(self):
        memcache.set("mycfg",self.request.get('cfg'))
        cfg=CfgDb.all().filter("thekey =","users").get()
        if not cfg:
            cfg=CfgDb()
            cfg.thekey="users"
        cfg.thevalue=self.request.get('cfg')
        cfg.put()
        confs=self.request.get('cfg').strip().split("|")
        self.response.out.write("ok %d 15" % (len(confs)))

def main():
  application = webapp.WSGIApplication(
      [
       ('/last',LastPost),
       ('/updatecfg',UpdateCfg),
       ('/cron',CronCheck),
       ('/check',Check),
       ('/cfg',Cfg),
       ('/kw',UpdateKeyWord),
      ],
      debug=True)
  run_wsgi_app(application)


if __name__ == '__main__':
  main()
