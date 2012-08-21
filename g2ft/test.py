# -*- coding: utf-8 -*-
__author__ = 'cnwesleywang@gmail.com'

import time
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.api import urlfetch
import oauth
import urllib
import cgi
from django.utils import simplejson as json
from weibo import APIClient,OAuthToken

class TestFaceBook(webapp.RequestHandler):
    def get(self):
        FACEBOOK_APP_ID = "241341535957794"
        FACEBOOK_APP_SECRET = "a623d40ed40025c1a1ef5f5e243b6658"
        verification_code = self.request.get("code")
        args = dict(client_id=FACEBOOK_APP_ID, redirect_uri=self.request.path_url,scope='publish_stream')
        if self.request.get("code"):
            args["client_secret"] = FACEBOOK_APP_SECRET
            args["code"] = self.request.get("code")
            response = cgi.parse_qs(urllib.urlopen(
                "https://graph.facebook.com/oauth/access_token?" +
                urllib.urlencode(args)).read())
            access_token = response["access_token"][-1]

            # Download the user profile and cache a local instance of the
            # basic profile info
            profile = json.load(urllib.urlopen(
                "https://graph.facebook.com/me?" +
                urllib.urlencode(dict(access_token=access_token))))
            #user = User(key_name=str(profile["id"]), id=str(profile["id"]),
            #            name=profile["name"], access_token=access_token,
            #            profile_url=profile["link"])
            #user.put()
            #set_cookie(self.response, "fb_user", str(profile["id"]),
            #           expires=time.time() + 30 * 86400)
            #self.redirect("/")

            form_fields = {
              "message": "Albert test:"+str(time.time()),
              "access_token": access_token,
            }
            form_data = urllib.urlencode(form_fields)
            result = urlfetch.fetch(url="https://graph.facebook.com/me/feed",
                                    payload=form_data,
                                    method=urlfetch.POST,
                                    headers={'Content-Type': 'application/x-www-form-urlencoded'})
            self.response.out.write(result.content)
        else:
            self.redirect(
                "https://graph.facebook.com/oauth/authorize?" +
                urllib.urlencode(args))

class TestSina(webapp.RequestHandler):
    def get(self):
        token=OAuthToken("ed0b0ce2d91c72e3a8abc2e92b6e106c","23c62cbf1ddf13118e60ed54fd21a562")
        client = APIClient(app_key="270935849", app_secret="854563acef8af9abb79892ef1f4cb974", token=token)
        params={
             'status':u"很很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长很长长很长",
             'lat':38.5226,
             'long':116.4427,
             'url':"http://gplus2ft.appspot.com",
        }
        result=client.upload.statuses__upload(**params)

class TestTwitter(webapp.RequestHandler):
    def get(self):
        TWITTER_KEY="3ZCkqgkHgMzN5B22py6lw"
        TWITTER_SECRET="e19lxvlT6RSBfkjKqotXiQRnwF0yKYN2JG26PJ6eWVs"
        TWITTER_CALLBACK="http://localhost:8080/link?mode=twitter"

        client = oauth.TwitterClient(TWITTER_KEY, TWITTER_SECRET, TWITTER_CALLBACK)
        additional_params = {
                          "status": "test:"+str(time.time()),
                          'lat':38.5226,
                          'long':116.4427,
                          "media[]":urllib.urlopen("https://lh6.googleusercontent.com/-JeneiuW7E4g/T1nswEtUDBI/AAAAAAAABq0/gZnX7IJK12Q/s0-d/12-2-26%2B-%2B1"),
                            }
        result = client.make_request(
                            "https://upload.twitter.com/1/statuses/update_with_media.json",
                            token="107907401-0UK7trN25W7EhTzZoBlI0G5BfmgZk0edwuoPhPtU",
                            secret="7gZSbuZ81ftGsHTW5TSXmXeV6MRbHtKN9WDy5Znn4Ug",
                            additional_params=additional_params,
                            protected=True,
                            method=urlfetch.POST)

        self.response.out.write(result.content)

def main():
  application = webapp.WSGIApplication(
      [
       ('/twitter',TestTwitter),
       ('/fb',TestFaceBook),
       ('/sina',TestSina),
      ],
      debug=True)
  run_wsgi_app(application)


if __name__ == '__main__':
  main()
