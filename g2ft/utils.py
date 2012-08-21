from google.appengine.ext import webapp
from oauth2client.appengine import StorageByKeyName
from main import MyRealCfg
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.api import memcache
from google.appengine.ext import db
from google.appengine.api import urlfetch
import logging

class ModifyLimit(webapp.RequestHandler):
    def get(self):
        if self.request.get('limit'):
            StorageByKeyName(MyRealCfg, 'userlimit', 'cfgvalue').put(self.request.get('limit'))
        self.response.out.write("Done,now limit is:"+StorageByKeyName(MyRealCfg, 'userlimit', 'cfgvalue').get())


class ModifyLastSites(webapp.RequestHandler):
    def post(self):
        if self.request.get('sites'):
            lastsites=self.request.get('sites')
            logging.info("I was called with %s" % (lastsites))
            if len(lastsites.strip())<=4:
                logging.error("this is bad,why keep calling this with %s" % (lastsites))
                return
            StorageByKeyName(MyRealCfg, 'lastsites', 'cfgvalue').put(self.request.get('sites'))
            #change to let that site check last post diretly,and then callback here
            sites=self.request.get('sites').split()
            sql="SELECT * FROM MyCfg"
            confs = db.GqlQuery(sql)
            total=confs.count()
            each=total/len(sites)
            if each * len(sites)<total:each+=1
            sitenow=0
            confnow=0
            siteconf=""
            for conf in confs:
                siteconf+=conf.gplusid+"|"
                confnow+=1
                if confnow>=each:
                    url="http://"+sites[sitenow]+"/updatecfg?cfg="+siteconf
                    try:
                        result = urlfetch.fetch(url=url)
                        self.response.out.write("update site "+sites[sitenow]+" return "+result.content+"<p/>")
                    except:
                        logging.info("modify last site %s fail!" % (sites[sitenow]))
                    siteconf=""
                    confnow=0
                    sitenow+=1
            if confnow>0:
                url="http://"+sites[sitenow]+"/updatecfg?cfg="+siteconf
                try:
                    result = urlfetch.fetch(url=url)
                except:
                    logging.info("modify last site %s fail!" % (sites[sitenow]))
                self.response.out.write("update site "+sites[sitenow]+" return "+result.content+"<p/>")
        
    def get(self):
        self.response.out.write("""
<FORM ACTION="modifylastsites" METHOD=POST>

lastsites:<BR>
<TEXTAREA NAME="sites" COLS=40 ROWS=6>%s</TEXTAREA>

<P><INPUT TYPE=SUBMIT VALUE="submit">
</FORM>
""" % (StorageByKeyName(MyRealCfg, 'lastsites', 'cfgvalue').get()))

def main():
  application = webapp.WSGIApplication(
      [
       ('/modifylimit',ModifyLimit),
       ('/modifylastsites',ModifyLastSites),
      ],
      debug=True)
  run_wsgi_app(application)


if __name__ == '__main__':
  main()
