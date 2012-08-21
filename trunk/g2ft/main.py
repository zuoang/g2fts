# -*- coding: utf-8 -*-

__author__ = 'cnwesleywang@gmail.com'

from google.appengine.dist import use_library
use_library('django', '0.96')

import settings
import cgi
import httplib2
import logging
import os
import pickle
import urllib,urllib2
import datetime
from google.appengine.api import urlfetch
import base64
import oauth
import feed.date.rfc3339
import datetime
from urllib import quote as urlquote
from django.utils import simplejson as json
import time
import random
import re,htmlentitydefs
import bitly
import traceback

from apiclient.discovery import build
from oauth2client.appengine import OAuth2Decorator
from google.appengine.api import memcache
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import login_required
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.client import AccessTokenRefreshError
from google.appengine.api import users
from weibo import APIClient,APIError,OAuthToken
from google.appengine.ext import db
from oauth2client.appengine import CredentialsProperty
from oauth2client.appengine import StorageByKeyName
from google.appengine.api import taskqueue


TWITTER_KEY="3ZCkqgkHgMzN5B22py6lw"
TWITTER_SECRET="e19lxvlT6RSBfkjKqotXiQRnwF0yKYN2JG26PJ6eWVs"
#TWITTER_CALLBACK="http://localhost:8080/link?mode=twitter"
TWITTER_CALLBACK="http://gplus2ft.appspot.com/link?mode=twitter"

FACEBOOK_APP_ID = "241341535957794"
FACEBOOK_APP_SECRET = "a623d40ed40025c1a1ef5f5e243b6658"

SINA_KEY = '270935849' 
SINA_SECRET = '854563acef8af9abb79892ef1f4cb974' 
SINA_CALLBACK = 'http://gplus2ft.appspot.com/link?mode=sina'
#SINA_CALLBACK = 'http://127.0.0.1:8080/link?mode=sina'

class A_llPost(db.Model):
    gpluswho=db.StringProperty()
    tomode=db.StringProperty()
    destwho=db.StringProperty()
    content=db.TextProperty()
    lat=db.FloatProperty()
    lon=db.FloatProperty()
    url=db.StringProperty()
    atwhen=db.DateTimeProperty()

class MyCfg(db.Model):
    gplusname=db.StringProperty()
    gplusid=db.StringProperty()
    credentials = CredentialsProperty()
    twitterid=db.StringProperty()
    twitteruname=db.StringProperty()
    twittertoken=db.StringProperty()
    twittersecret=db.StringProperty()
    facebookuname=db.StringProperty()
    facebooktoken=db.StringProperty()
    sinatoken=db.StringProperty()
    sinasecret=db.StringProperty()
    sinaname=db.StringProperty()
    lastgplusup=db.DateTimeProperty()

class MyRealCfg(db.Model):
    cfgvalue=db.StringProperty()

class Index(webapp.RequestHandler):
    def get(self):
        userlimit=10
        cfgvalue=StorageByKeyName(MyRealCfg, 'userlimit', 'cfgvalue').get()
        if not cfgvalue:
            StorageByKeyName(MyRealCfg, 'userlimit', 'cfgvalue').put('10')
        else:
            userlimit=int(cfgvalue)
        foo = db.GqlQuery("SELECT * FROM MyCfg")
        my_count = foo.count()

        path = os.path.join(os.path.dirname(__file__), 'index.html')
        self.response.out.write(template.render(path, {'left':userlimit-my_count,"more":userlimit>my_count}))

class LastPost(webapp.RequestHandler):
    def get(self):
        return self.post()
    def post(self):
        pass
        #lastpost=None
        #lastsites=memcache.get('G2FTS_LAST_SITES')
        #if lastsites==None:
        #    lastsites=StorageByKeyName(MyRealCfg, 'lastsites', 'cfgvalue').get()
        #    if lastsites==None:
        #        lastsites="gpluslast.appspot.com"
        #    memcache.set('G2FTS_LAST_SITES',lastsites)
        #try:
        #    sites=lastsites.split()
        #    site=sites[random.randint(0,len(sites)-1)]
        #    url="http://"+site+"/last?id="+self.request.get("id")
        #    result = urlfetch.fetch(url=url) 
        #except Exception,e:
        #    logging.error("Error fetching last post of %s,Exception:%s" % (self.request.get("id"),str(e)))
        #    return
        #lastpost=result.content
        #forcesync=False
        #if memcache.get(self.request.get('id')+"_lastsync") and time.time()- memcache.get(self.request.get('id')+"_lastsync")>3600:
        #    forcesync=True
        #if (lastpost!=None) and  (memcache.get(self.request.get('id'))==None or (lastpost != memcache.get(self.request.get('id'))) or forcesync):
        #    memcache.set(self.request.get('id'),lastpost)
        #    memcache.set(self.request.get('id')+"_lastsync",time.time())
        #    taskqueue.add(url='/sync',
        #        params=dict(id=self.request.get('id')))

class NewSync(webapp.RequestHandler):
    def get(self):
        pass
        #confinfo=memcache.get('G2FTS_USERS')
        #if confinfo==None:
        #    logging.info("getting conf from data store!")
        #    sql="SELECT * FROM MyCfg"
        #    confs = db.GqlQuery(sql)
        #    confinfo=""
        #    for conf in confs:
        #        confinfo+=conf.gplusid+" "
        #    memcache.set('G2FTS_USERS',confinfo)
        #for confid in confinfo.split():
        #    taskqueue.add(url='/last',
        #        params=dict(id=confid))

class UnlinkHandler(webapp.RequestHandler):
    def get(self):
        user = users.get_current_user()
        if not user:
            self.redirect("/link")
            return
        if self.request.get('mode')=='twitter':
            StorageByKeyName(MyCfg, user.user_id(), 'twitteruname').put(None)
            StorageByKeyName(MyCfg, user.user_id(), 'twittertoken').put(None)
        elif self.request.get('mode')=='facebook':
            StorageByKeyName(MyCfg, user.user_id(), 'facebookuname').put(None)
            StorageByKeyName(MyCfg, user.user_id(), 'facebooktoken').put(None)
        elif self.request.get('mode')=='sina':
            StorageByKeyName(MyCfg, user.user_id(), 'sinaname').put(None)
        self.redirect("/link")    


class LinkHandler(webapp.RequestHandler):
    def get(self):
        user = users.get_current_user()
        args = dict(client_id=FACEBOOK_APP_ID, redirect_uri="http://gplus2ft.appspot.com/link",scope='publish_stream')

        template_values = {}

        if self.request.get('mode')=='gplus':
            userlimit=10
            cfgvalue=StorageByKeyName(MyRealCfg, 'userlimit', 'cfgvalue').get()
            if not cfgvalue:
                StorageByKeyName(MyRealCfg, 'userlimit', 'cfgvalue').put('10')
            else:
                userlimit=int(cfgvalue)
            foo = db.GqlQuery("SELECT * FROM MyCfg")
            my_count = foo.count()
            if my_count>=userlimit:
                self.redirect("/")
                return
            flow = pickle.loads(memcache.get(user.user_id()))
            if flow:
                credentials = flow.step2_exchange(self.request.params)
                http = httplib2.Http()
                http = credentials.authorize(http)
                service = build("plus", "v1", http=http)
                me = service.people().get(userId='me').execute(http)
                StorageByKeyName(MyCfg, user.user_id(), 'gplusid').put(me['id'])
                StorageByKeyName(MyCfg, user.user_id(), 'credentials').put(credentials)
                StorageByKeyName(MyCfg, user.user_id(), 'gplusname').put(user.nickname())
                self.redirect("/link")
                return
        elif self.request.get('mode')=='twitter':
            consumer_key = TWITTER_KEY
            consumer_secret = TWITTER_SECRET
            callback_url = TWITTER_CALLBACK
            client = oauth.TwitterClient(consumer_key, consumer_secret, callback_url)
            auth_token = self.request.get("oauth_token")
            auth_verifier = self.request.get("oauth_verifier")
            user_info = client.get_user_info(auth_token, auth_verifier=auth_verifier)
            StorageByKeyName(MyCfg, user.user_id(), 'twitterid').put(str(user_info['id']))
            StorageByKeyName(MyCfg, user.user_id(), 'twitteruname').put(user_info['username'])
            StorageByKeyName(MyCfg, user.user_id(), 'twittertoken').put(user_info['token'])
            StorageByKeyName(MyCfg, user.user_id(), 'twittersecret').put(user_info['secret'])
            self.redirect("/link")
            return
        elif self.request.get('mode')=='sina':
            oauth_token = self.request.get('oauth_token')
            oauth_verifier = self.request.get('oauth_verifier')
            oauth_token_secret = memcache.get('%s_sina_request_token' % (user.user_id()))
            request_token = OAuthToken(oauth_token, oauth_token_secret, oauth_verifier)
            client = APIClient(app_key=SINA_KEY, app_secret=SINA_SECRET, token=request_token)
            access_token = client.get_access_token()
            client = APIClient(SINA_KEY, SINA_SECRET, access_token)
            account = client.account__verify_credentials()
            logging.info(account)
            StorageByKeyName(MyCfg, user.user_id(), 'sinatoken').put(access_token.oauth_token)
            StorageByKeyName(MyCfg, user.user_id(), 'sinasecret').put(access_token.oauth_token_secret)
            StorageByKeyName(MyCfg, user.user_id(), 'sinaname').put(account.name)
            self.redirect("/link")
            return
        elif self.request.get('code'):
            verification_code = self.request.get("code")
            args["client_secret"] = FACEBOOK_APP_SECRET
            args["code"] = self.request.get("code")
            res=urllib.urlopen(
                "https://graph.facebook.com/oauth/access_token?" +
                urllib.urlencode(args)).read()
            response = cgi.parse_qs(res)
            logging.info("rsp is:"+str(response))
            if response.has_key("access_token"):
                access_token = response["access_token"][-1]
                profile = json.load(urllib.urlopen(
                    "https://graph.facebook.com/me?" +
                    urllib.urlencode(dict(access_token=access_token))))
                StorageByKeyName(MyCfg, user.user_id(), 'facebookuname').put(profile["name"])
                StorageByKeyName(MyCfg, user.user_id(), 'facebooktoken').put(access_token)

            self.redirect("/link")
            return

        credentials = StorageByKeyName(MyCfg, user.user_id(), 'credentials').get()
        if credentials:
            template_values["gplus"]=user.nickname()

        twittertoken=StorageByKeyName(MyCfg, user.user_id(), 'twittertoken').get()
        if twittertoken:
            template_values["twitter"]=StorageByKeyName(MyCfg, user.user_id(), 'twitteruname').get()

        facebooktoken=StorageByKeyName(MyCfg, user.user_id(), 'facebooktoken').get()
        if facebooktoken:
            template_values["facebook"]=StorageByKeyName(MyCfg, user.user_id(), 'facebookuname').get()
            
        sinaname=StorageByKeyName(MyCfg, user.user_id(), 'sinaname').get()
        if sinaname:
            template_values["sina"]=sinaname

        #sql="SELECT * FROM MyCfg"
        #confs = db.GqlQuery(sql)
        #confinfo=""
        #for conf in confs:
        #    if conf.gplusid:
        #        confinfo+=conf.gplusid+" "
        #memcache.set('G2FTS_USERS',confinfo) #update user cache on every link
        
        lastsites=StorageByKeyName(MyRealCfg, 'lastsites', 'cfgvalue').get()
        logging.info("get from db,lastsites is %s" % (lastsites))
        if lastsites==None:
            lastsites="gpluslast.appspot.com"
        taskqueue.add(url='/modifylastsites',params=dict(sites=lastsites))

        templatepath = os.path.join(os.path.dirname(__file__), 'link.html')
        self.response.out.write(template.render(templatepath, template_values))

class AuthHandler(webapp.RequestHandler):
    def get(self):
        user = users.get_current_user()
        if self.request.get('gplus'):
            flow = OAuth2WebServerFlow(
                client_id=settings.CLIENT_ID,
                client_secret=settings.CLIENT_SECRET,
                scope='https://www.googleapis.com/auth/plus.me',
                user_agent='gplus2ft/1.0',
                approval_prompt='force')

            callback = self.request.relative_url('/link?mode=gplus')
            authorize_url = flow.step1_get_authorize_url(callback)
            memcache.set(user.user_id(), pickle.dumps(flow))
            self.redirect(authorize_url)
            return
        elif self.request.get('twitter'):
            consumer_key = TWITTER_KEY
            consumer_secret = TWITTER_SECRET
            callback_url = TWITTER_CALLBACK
            client = oauth.TwitterClient(consumer_key, consumer_secret, callback_url)
            self.redirect(client.get_authorization_url())
            return
        elif self.request.get('facebook'):
            args = dict(client_id=FACEBOOK_APP_ID, redirect_uri=self.request.relative_url('/link'),scope='publish_stream')
            self.redirect("https://graph.facebook.com/oauth/authorize?" +
                urllib.urlencode(args))
            return
        elif self.request.get('sina'):
            client = APIClient(app_key=SINA_KEY, app_secret=SINA_SECRET,callback=SINA_CALLBACK)
            try:
                request_token = client.get_request_token()
            except Exception,e:
                self.response.out.write('can not access sina apt site!:'+str(e))
                return
            memcache.set('%s_sina_request_token' % (user.user_id()),request_token.oauth_verifier)
            self.redirect(client.get_authorize_url(request_token.oauth_token))
            return

class UpdateStatus(webapp.RequestHandler):
    def shorten(self,url):
        rURL = r'https?://[^\s]+'
        api_root = 'https://api.t.sina.com.cn/short_url/shorten.json'
        def shorten(match):
            url = match.group()
            data = {'source': '270935849',
                    'url_long': url
                    }
     
            stream = urllib2.urlopen(api_root, data=urllib.urlencode(data, doseq=1))
            rspstr=stream.read()
            resp = json.loads(rspstr)
            return resp[0]['url_short']
        return re.sub(rURL, shorten, url)

    def toShort(self,content,fullurl,limit,removehttp=True):
        #api = bitly.Api(login='cnwesleywang', apikey='R_2f9363a1f811b99efdf8028598be6494')
        contents=re.split("(http[s]?://[a-zA-Z_\./0-9%&\?=\+\-;,]*)",content)
        finals=[]
        for content in contents:
            if content.startswith(u'http'):
                try:
                    content=self.shorten(content)
                except Exception,e:
                    logging.info("shorten url exception:"+str(e))
            finals.append(content)
        content=u" ".join([s.strip() for s in finals])
        if removehttp: content=content.replace("http://","").replace("https://","")       
        if len(content)>limit:
            try:
                fullurl=self.shorten(fullurl)
            except Exception,e:
                logging.info("shorten url exception:"+str(e))
            if removehttp: fullurl=fullurl.replace("http://","").replace("https://","")
            lennow=len(content.encode("gbk",'ignore'))
            limit=limit-3-len(fullurl)
            while lennow>limit:
                content=content[:-1]
                if len(content)<10:break
                lennow=len(content.encode("gbk",'ignore'))
            content=u"%s %s" % (content,fullurl)
        return content

    def get(self):
        self.saveToDB(self.request)
    
    def saveToDB(self,request):
        post=A_llPost.get_or_insert(str(time.time()))
        post.gpluswho=self.request.get("from")
        post.tomode=self.request.get("dest")
        post.destwho=self.request.get("to")
        post.content=self.request.get("content")
        if self.request.get('lat'):
            post.lat=float(self.request.get('lat'))
        if self.request.get('lon'):
            post.lon=float(self.request.get('lon'))
        post.url=self.request.get("url")
        post.atwhen=datetime.datetime.now()
        post.put()

    def txt2url(self,content):
        urlbase=u"http://chart.apis.google.com/chart?chst=d_text_outline&chld=000000|14|h|FFFFFF|_|"
        linewidth=0
        for char in content:
            if char=="\n":
                urlbase+="|"
                linewidth=0
                continue
            if linewidth==0:
                urlbase+="    "
            urlbase+=char
            linewidth+=len(char.encode("gbk",'ignore'))
            if linewidth>100:
                linewidth=0
                urlbase+="|"
        logging.info(u"the url is:"+urlbase)
        return urlbase.encode("utf-8",'ignore')

    def post(self):
        if self.request.get('dest')=='twitter':
            consumer_key = TWITTER_KEY
            consumer_secret = TWITTER_SECRET
            callback_url = TWITTER_CALLBACK
            client = oauth.TwitterClient(consumer_key, consumer_secret, callback_url)
            content = self.toShort(self.request.get('content'),self.request.get("url"),140)
            additional_params = {
              "status": content,
            }
            protected=False
            url="http://twitter.com/statuses/update.json"
            if self.request.get('lon'):
                additional_params['long']=float(self.request.get('lon'))
            if self.request.get('lat'):
                additional_params['lat']=float(self.request.get('lat'))
            if self.request.get('imageurl'):
                imageurl=self.request.get('imageurl')
                additional_params['media[]']=urllib.urlopen(imageurl)
                url="https://upload.twitter.com/1/statuses/update_with_media.json"
                protected=True
            try:
                result = client.make_request(
                    url,
                    token=self.request.get('token'),
                    secret=self.request.get('secret'),
                    additional_params=additional_params,
                    protected=protected,
                    method=urlfetch.POST)
                logging.info(u"TWITTER:%s return:%s" % (content,result.content))
                #self.saveToDB(self.request) #not do this again to reduce the db usage
            except Exception,e:
                tb = traceback.format_exc()
                logging.error("TWITTER:%s exception:%s %s" % (self.request.get('content'),str(e),str(tb)))
                url="http://twitter.com/statuses/update.json"
                additional_params = {
                  "status": self.toShort(u"G2FTS提示:原文无法转发，要观看请移步:%s" % (self.request.get("url")),self.request.get("url"),140),
                }
                protected=False
                if self.request.get('lon'):
                    additional_params['long']=float(self.request.get('lon'))
                if self.request.get('lat'):
                    additional_params['lat']=float(self.request.get('lat'))
                try:
                    result = client.make_request(
                        url,
                        token=self.request.get('token'),
                        secret=self.request.get('secret'),
                        additional_params=additional_params,
                        protected=protected,
                        method=urlfetch.POST)
                except:
                    logging.error("TWITTER:still fail!")

                
                
        elif self.request.get('dest')=='facebook':
            params = {
              "message": self.request.get('content'),
              "access_token": self.request.get('token'),
            }
            if self.request.get('imageurl'):
                params['picture']=self.request.get('imageurl')

            if self.request.get('lon') and self.request.get('lat'):
                for distence in [100,1000]:
                    places=json.load(urllib.urlopen("https://graph.facebook.com/search?type=place&center=%s,%s&distance=100&access_token=%s" % 
                            (self.request.get('lat'),self.request.get('lon'),self.request.get('token'))))
                    if places and places.has_key('data') and len(places['data'])>0: break;
                if places and places.has_key('data') and len(places['data'])>0:
                    params['place']=places['data'][0]['id']
                else:
                    logging.info("there is no known place for:%s,%s" % (self.request.get('lat'),self.request.get('lon')))

            for k,v in params.items():
                if isinstance(v, unicode):
                    params[k] = v.encode('utf8')
            form_data = "&".join(["%s=%s" % (urlquote(str(k), ""), urlquote(str(params[k]),""))for k in sorted(params)])
            try:
                result = urlfetch.fetch(url="https://graph.facebook.com/me/feed",
                                        payload=form_data,
                                        method=urlfetch.POST,
                                        headers={'Content-Type': 'application/x-www-form-urlencoded'})
                logging.info("FACEBOOK:%s return:%s" % (self.request.get('content'),result.content))
                #self.saveToDB(self.request)
            except Exception,e:
                logging.error("FACEBOOK:%s exception:%s" % (self.request.get('content'),str(e)))
        elif self.request.get('dest')=='sina':
            try:
                token=OAuthToken(self.request.get('token'),self.request.get('secret'))
                client = APIClient(app_key=SINA_KEY, app_secret=SINA_SECRET, token=token)
                content = self.toShort(self.request.get('content'),self.request.get("url"),140,removehttp=False)
                #logging.info(u"content after short:"+content)
                #logging.info(u"unicode len:%d gbk len:%d" % (len(content),len(content.encode("gbk",'ignore'))))
                #content = self.request.get('content')
                #content = self.request.get('content')
                params={}
                if self.request.get('imageurl'):
                    params['pic']=urllib.urlopen(self.request.get('imageurl'))
                #if len(content)>140:#we will first conside convert long text to image
                #    params['pic']=urllib.urlopen(self.txt2url(content))
                #    content=""
                params['status']=content
                
                if self.request.get('lon'):
                    params['long']=float(self.request.get('lon'))
                if self.request.get('lat'):
                    params['lat']=float(self.request.get('lat'))
                if params.has_key("pic"):
                    result=client.upload.statuses__upload(**params)
                else:
                    result=client.post.statuses__update(**params)
                logging.info("WEIBO:%s return:%s" % (content,result))
                #self.saveToDB(self.request)
            except APIError,e:
                logging.error("post to sina fail,the post is:%s,Exception is:%s" % (content,str(e)))
                if int(e.error_code)==21327:
                    logging.info("Sina wei token expire,remove token of %s" % (self.request.get('key')))
                    StorageByKeyName(MyCfg, self.request.get('key'), 'sinaexpiresin').put(0)
                #params = {
                #  "status": u"请移步:%s" % (self.request.get("url")),
                #}
                #if self.request.get('lon'):
                #    params['long']=float(self.request.get('lon'))
                #if self.request.get('lat'):
                #    params['lat']=float(self.request.get('lat'))
                #try:
                #    result=client.post.statuses__update(**params)
                #except:
                #    logging.error("SINA:still fail!")
            except Exception,e:
                logging.error("post to sina fail,the post is:%s,Exception is:%s" % (self.request.get('content'),str(e)))
                #params = {
                #  "status": u"请移步:%s" % (self.request.get("url")),
                #}
                #if self.request.get('lon'):
                #    params['long']=float(self.request.get('lon'))
                #if self.request.get('lat'):
                #    params['lat']=float(self.request.get('lat'))
                #try:
                #    result=client.post.statuses__update(**params)
                #except:
                #    logging.error("SINA:still fail!")

def unescape(text):
    def fixup(m):
        text = m.group(0)
        if text[:2] == "&#":
            # character reference
            try:
                if text[:3] == "&#x":
                    return unichr(int(text[3:-1], 16))
                else:
                    return unichr(int(text[2:-1]))
            except ValueError:
                pass
        else:
            # named entity
            try:
                text = unichr(htmlentitydefs.name2codepoint[text[1:-1]])
            except KeyError:
                pass
        return text # leave as is
    return re.sub("&#?\w+;", fixup, text)

class SyncHandler(webapp.RequestHandler):
    def sendToTwitter(self,conf,params):
        pparams=dict(dest='twitter', token=conf.twittertoken,secret=conf.twittersecret)
        for k,v in params.items():
            pparams[k]=v    
        taskqueue.add(url='/updatestatus',params=pparams)
        
    def sendToFacebook(self,conf,params):
        pparams=dict(dest='facebook', token=conf.facebooktoken)    
        for k,v in params.items():
            pparams[k]=v    
        taskqueue.add(url='/updatestatus',params=pparams)
        
    def sendToSina(self,conf,params):
        pparams=dict(dest='sina', key=conf.key().name(), token=conf.sinatoken, secret=conf.sinasecret)
        for k,v in params.items():
            pparams[k]=v    
        taskqueue.add(url='/updatestatus',params=pparams)
    def get(self):
        return self.post()
 
    def post(self):

        httpUnauth = httplib2.Http(memcache)
        serviceUnauth = build("plus", "v1", http=httpUnauth, developerKey=settings.API_KEY)
        sql="SELECT * FROM MyCfg"
        if self.request.get('id'):
            sql+=" where gplusid='%s'" % (self.request.get('id'))
        force=False
        if (self.request.get('force')):
            force=True
        confs = db.GqlQuery(sql)
        needdelobj=[]
        for conf in confs:
            if conf.twitteruname or conf.facebookuname or conf.sinatoken:
                try:
                    activities_doc = serviceUnauth.activities().list(userId=conf.gplusid,maxResults=1, collection='public').execute(httpUnauth)

                    activities = []
                    if 'items' in activities_doc:
                        activities += activities_doc['items']

                    totalSynced=0
                    for i in range(len(activities)-1,-1,-1):#change the count limit to maxResults in list,to reduce the bandwith and cpu usage
                        activity=activities[i]
                        activities_doc = activity#serviceUnauth.activities().get(activityId=activity['id']).execute(httpUnauth)
                        updateat=datetime.datetime.fromtimestamp(feed.date.rfc3339.tf_from_timestamp(activities_doc['updated']))
                        if not force:
                            if conf.lastgplusup and conf.lastgplusup>=updateat:
                                continue

                        annotation=""
                        if activities_doc.has_key('annotation'): annotation=activities_doc['annotation']
                        content=activities_doc['object']['content']
                        if activities_doc['object'].has_key('originalContent') and activities_doc['object']['originalContent']!="": 
                            content=activities_doc['object']['originalContent']
                        if annotation=="":
                            twitterStatus=content
                        else:
                            twitterStatus=u"%s [转] %s" % (annotation,content)
                        contents=re.split('<[^>]*>', twitterStatus)
                        content=" ".join([v.strip() for v in re.split('<[^>]*>', twitterStatus)]) #remove html tag 
                        params={
                            "content":content,
                            "from":conf.gplusname,
                            "url":activities_doc['url'],
                        }                       
                        if activities_doc.has_key('geocode'):
                            lat,lon=activities_doc['geocode'].split(" ")
                            params['lat']=lat
                            params['lon']=lon
                        
                        #logging.info(activities_doc)
                        #if activities_doc['object'].has_key("url"):
                        #    logging.info("object url:"+activities_doc['object']['url'])

                        if activities_doc['object'].has_key('attachments'):
                            if len(activities_doc['object']['attachments'])>0:
                                if activities_doc['object']['attachments'][0]['objectType']=='photo':
                                    imageurl=activities_doc['object']['attachments'][0]['fullImage']['url']
                                    oimageurl=imageurl
                                    imageurl=imageurl.split("/")
                                    imageurl[-2]="s0"#some hack for google+api address to show full image size
                                    imageurl="/".join(imageurl)
                                    request = urllib2.Request(imageurl)
                                    request.get_method = lambda : 'HEAD'
                                    try:
                                        response = urllib2.urlopen(request)
                                        if response.getcode()!=200:#check if it is there!
                                            imageurl=oimageurl
                                    except:
                                            imageurl=oimageurl
                                    params['imageurl']=imageurl
                                    params['imagetype']=activities_doc['object']['attachments'][0]['fullImage']['type']
                                elif activities_doc['object']['attachments'][0]['objectType']=='article':
                                    params["content"]+=u" : %s" % (activities_doc['object']['attachments'][0]['url'])
                        logging.info(params)
                        params["content"]=unescape(params["content"])[:1000]#Let's do this to avoid google task size limit
 
                        if conf.twitteruname:
                            params["to"]=conf.twitteruname
                            self.sendToTwitter(conf,params)

                        if conf.facebookuname:
                            params["to"]=conf.facebookuname
                            self.sendToFacebook(conf,params)
                        
                        if conf.sinaname:
                            params["to"]=conf.sinaname
                            self.sendToSina(conf,params)

                        conf.lastgplusup=updateat
                        conf.put()

                        totalSynced+=1
                        if totalSynced>=3: break # so far,3 twitter eachtime max 
                        
                    self.response.out.write("User %s synced %d notes total" % (conf.twitteruname,totalSynced))

                except AccessTokenRefreshError:
                    needdelobj.append(conf)
                
        for conf in needdelobj:
            conf.delete()

def main():
  application = webapp.WSGIApplication(
      [
       ('/link',LinkHandler),
       ('/unlink',UnlinkHandler),
       ('/auth',AuthHandler),
       ('/sync',SyncHandler),
       ('/updatestatus',UpdateStatus),
       ('/last',LastPost),
       ('/newsync',NewSync),
       ('/',Index),
      ],
      debug=True)
  run_wsgi_app(application)


if __name__ == '__main__':
  main()
