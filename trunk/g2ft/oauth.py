#!/usr/bin/env python

"""
A simple OAuth implementation for authenticating users with third party
websites.

A typical use case inside an AppEngine controller would be:

1) Create the OAuth client. In this case we'll use the Twitter client,
  but you could write other clients to connect to different services.

  import oauth

  consumer_key = "LKlkj83kaio2fjiudjd9...etc"
  consumer_secret = "58kdujslkfojkjsjsdk...etc"
  callback_url = "http://www.myurl.com/callback/twitter"

  client = oauth.TwitterClient(consumer_key, consumer_secret, callback_url)

2) Send the user to Twitter in order to login:

  self.redirect(client.get_authorization_url())

3) Once the user has arrived back at your callback URL, you'll want to
  get the authenticated user information.

  auth_token = self.request.get("oauth_token")
  auth_verifier = self.request.get("oauth_verifier")
  user_info = client.get_user_info(auth_token, auth_verifier=auth_verifier)

  The "user_info" variable should then contain a dictionary of various
  user information (id, picture url, etc). What you do with that data is up
  to you.

  That's it!

4) If you need to, you can also call other other API URLs using
  client.make_request() as long as you supply a valid API URL and an access
  token and secret. Note, you may need to set method=urlfetch.POST.

@author: Mike Knapp
@copyright: Unrestricted. Feel free to use modify however you see fit. Please
note however this software is unsupported. Please don't email me about it. :)
"""

from google.appengine.api import memcache
from google.appengine.api import urlfetch
from google.appengine.ext import db

from cgi import parse_qs
from django.utils import simplejson as json
from hashlib import sha1
from hmac import new as hmac
from random import getrandbits
from time import time
from urllib import urlencode
from urllib import quote as urlquote
from urllib import unquote as urlunquote
import base64
import uuid

import logging


class OAuthException(Exception):
    pass


def get_oauth_client(service, key, secret, callback_url):
  """Get OAuth Client.

  A factory that will return the appropriate OAuth client.
  """

  if service == "twitter":
    return TwitterClient(key, secret, callback_url)
  elif service == "yahoo":
    return YahooClient(key, secret, callback_url)
  elif service == "myspace":
    return MySpaceClient(key, secret, callback_url)
  else:
    raise Exception, "Unknown OAuth service %s" % service


class AuthToken(db.Model):
  """Auth Token.

  A temporary auth token that we will use to authenticate a user with a
  third party website. (We need to store the data while the user visits
  the third party website to authenticate themselves.)

  TODO: Implement a cron to clean out old tokens periodically.
  """

  service = db.StringProperty(required=True)
  token = db.StringProperty(required=True)
  secret = db.StringProperty(required=True)
  created = db.DateTimeProperty(auto_now_add=True)

_CONTENT_TYPES = { '.png': 'image/png', '.gif': 'image/gif', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.jpe': 'image/jpeg' }
def _guess_content_type(ext):
    return _CONTENT_TYPES.get(ext, 'application/octet-stream')

def _generate_signature(key, base_string):
    '''
    generate url-encoded oauth_signature with HMAC-SHA1
    '''
    return _quote(base64.b64encode(hmac(key, base_string, sha1).digest()))

def _generate_base_string(method, url, **params):
    '''
    generate base string for signature
    
    >>> method = 'GET'
    >>> url = 'http://www.sina.com.cn/news'
    >>> params = dict(a=1, b='A&B')
    >>> _generate_base_string(method, url, **params)
    'GET&http%3A%2F%2Fwww.sina.com.cn%2Fnews&a%3D1%26b%3DA%2526B'
    '''
    plist = [(_quote(k), _quote(v)) for k, v in params.iteritems()]
    plist.sort()
    for i in range(0,len(plist)):
        if plist[i][0]=='pic':#will not base pic param
            del plist[i]
            break
    return '%s&%s&%s' % (method, _quote(url), _quote('&'.join(['%s=%s' % (k, v) for k, v in plist])))

def _quote(s):
    '''
    quote everything including /
    
    >>> _quote(123)
    '123'
    >>> _quote(u'\u4e2d\u6587')
    '%E4%B8%AD%E6%96%87'
    >>> _quote('/?abc=def& _+%')
    '%2F%3Fabc%3Ddef%26%20_%2B%25'
    '''
    if isinstance(s, unicode):
        s = s.encode('utf-8')
    return urlquote(str(s), safe='')

def _generate_nonce():
    ' generate random uuid as oauth_nonce '
    return uuid.uuid4().hex

class OAuthClient():

  def __init__(self, service_name, consumer_key, consumer_secret, request_url,
               access_url, callback_url=None):
    """ Constructor."""

    self.service_name = service_name
    self.consumer_key = consumer_key
    self.consumer_secret = consumer_secret
    self.request_url = request_url
    self.access_url = access_url
    self.callback_url = callback_url

  def prepare_request(self, url, token="", secret="", additional_params=None,
                      method=urlfetch.GET):
    """Prepare Request.

    Prepares an authenticated request to any OAuth protected resource.

    Returns the payload of the request.
    """

    def encode(text):
      return urlquote(str(text), "")

    params = {
      "oauth_consumer_key": self.consumer_key,
      "oauth_signature_method": "HMAC-SHA1",
      "oauth_timestamp": str(int(time())),
      "oauth_nonce": str(getrandbits(64)),
      "oauth_version": "1.0"
    }

    if token:
      params["oauth_token"] = token
    elif self.callback_url:
      params["oauth_callback"] = self.callback_url

    if additional_params:
        params.update(additional_params)

    for k,v in params.items():
        if isinstance(v, unicode):
            params[k] = v.encode('utf8')

    # Join all of the params together.
    params_str = "&".join(["%s=%s" % (encode(k), encode(params[k]))
                           for k in sorted(params)])

    # Join the entire message together per the OAuth specification.
    message = "&".join(["GET" if method == urlfetch.GET else "POST",
                        encode(url), encode(params_str)])

    # Create a HMAC-SHA1 signature of the message.
    key = "%s&%s" % (self.consumer_secret, secret) # Note compulsory "&".
    signature = hmac(key, message, sha1)
    digest_base64 = signature.digest().encode("base64").strip()
    params["oauth_signature"] = digest_base64

    # Construct the request payload and return it
    return urlencode(params)
    
  def prepare_multipart_request(self,url, token="", secret="", additional_params=None,
                      method=urlfetch.GET):
    boundary = '----------%s' % hex(int(time() * 1000))
    data = []
    for k, v in additional_params.iteritems():
        data.append('--%s' % boundary)
        if hasattr(v, 'read'):
            # file-like object:
            ext = ''
            filename = getattr(v, 'name', '')
            if filename=='':
                filename = getattr(v, 'url', '')
            n = filename.rfind('.')
            if n != (-1):
                ext = filename[n:].lower()
            if ext=='' or len(ext)>5:
                ext=".jpg"
            content = v.read()
            data.append('Content-Disposition: form-data; name="%s"; filename="hidden"' % k)
            data.append('Content-Length: %d' % len(content))
            data.append('Content-Type: %s\r\n' % _guess_content_type(ext))
            data.append(content)
        else:
            data.append('Content-Disposition: form-data; name="%s"\r\n' % k)
            data.append(v.encode('utf-8') if isinstance(v, unicode) else str(v))
    data.append('--%s--\r\n' % boundary)
    return '\r\n'.join(data), boundary

  def __build_oauth_header(self, params, **kw):
    '''
    build oauth header like: Authorization: OAuth oauth_token="xxx", oauth_nonce="123"
    Args:
      params: parameter dict.
      **kw: any additional key-value parameters.
    '''
    d = dict(**kw)
    d.update(params)
    L = [r'%s="%s"' % (k, v) for k, v in d.iteritems() if k.startswith('oauth_')]
    return 'OAuth %s' % ', '.join(L)

    
  def make_async_request(self, url, token="", secret="", additional_params=None,
                   protected=False, method=urlfetch.GET):
    """Make Request.

    Make an authenticated request to any OAuth protected resource.

    If protected is equal to True, the Authorization: OAuth header will be set.

    A urlfetch response object is returned.
    """      

    def encode(text):
      return urlquote(str(text), "")

    params = {
      "oauth_consumer_key": self.consumer_key,
      "oauth_signature_method": "HMAC-SHA1",
      "oauth_timestamp": str(int(time())),
      "oauth_nonce": str(getrandbits(64)),
      "oauth_version": "1.0"
    }
    if token:
      params["oauth_token"] = token
    elif self.callback_url:
      params["oauth_callback"] = self.callback_url

    for k,v in params.items():
        if isinstance(v, unicode):
            params[k] = v.encode('utf8')

    plist = [(_quote(k), _quote(v)) for k, v in params.iteritems()]
    plist.sort()
    message='%s&%s&%s' % ('POST', _quote(url), _quote('&'.join(['%s=%s' % (k, v) for k, v in plist])))

    # Create a HMAC-SHA1 signature of the message.
    key = "%s&%s" % (self.consumer_secret, secret) # Note compulsory "&".
    signature = hmac(key, message, sha1)
    digest_base64 = signature.digest().encode("base64").strip()
    params["oauth_signature"] = digest_base64

    # Create a HMAC-SHA1 signature of the message.
    key = "%s&%s" % (self.consumer_secret, secret) # Note compulsory "&".
    digest_base64 = signature.digest().encode("base64").strip()
    params["oauth_signature"] = _quote(digest_base64)
    L = [r'%s="%s"' % (k, v) for k, v in params.iteritems() if k.startswith('oauth_')]
    L.sort()
    params_str = 'OAuth %s' % ', '.join(L)

    # Construct the request payload and return it
    authhead=urlencode(params)
    headers = {"Authorization": "OAuth"} if protected else {}
    if additional_params and additional_params.has_key('media[]'):
        headers = {"Authorization": params_str} if protected else {}
        payload,boundary=self.prepare_multipart_request(url, token, secret, additional_params,
                                   method)
        headers['Content-Type']='multipart/form-data; boundary=%s' % boundary
    else:
        payload = self.prepare_request(url, token, secret, additional_params,
                                   method)
    if method == urlfetch.GET:
        url = "%s?%s" % (url, payload)
        payload = None
    rpc = urlfetch.create_rpc(deadline=10.0)
    urlfetch.make_fetch_call(rpc, url, method=method, headers=headers, payload=payload)
    return rpc

  def make_request(self, url, token="", secret="", additional_params=None,
                                      protected=False, method=urlfetch.GET):
    ret=self.make_async_request(url, token, secret, additional_params, protected, method)
    result=ret.get_result()
    return result  

  def get_authorization_url(self):
    """Get Authorization URL.

    Returns a service specific URL which contains an auth token. The user
    should be redirected to this URL so that they can give consent to be
    logged in.
    """

    raise NotImplementedError, "Must be implemented by a subclass"

  def get_user_info(self, auth_token, auth_verifier=""):
    """Get User Info.

    Exchanges the auth token for an access token and returns a dictionary
    of information about the authenticated user.
    """

    auth_token = urlunquote(auth_token)
    auth_verifier = urlunquote(auth_verifier)

    auth_secret = memcache.get(self._get_memcache_auth_key(auth_token))

    if not auth_secret:
      result = AuthToken.gql("""
        WHERE
          service = :1 AND
          token = :2
        LIMIT
          1
      """, self.service_name, auth_token).get()

      if not result:
        logging.error("The auth token %s was not found in our db" % auth_token)
        raise Exception, "Could not find Auth Token in database"
      else:
        auth_secret = result.secret

    response = self.make_request(self.access_url,
                                token=auth_token,
                                secret=auth_secret,
                                additional_params={"oauth_verifier":
                                                    auth_verifier})

    # Extract the access token/secret from the response.
    result = self._extract_credentials(response)

    # Try to collect some information about this user from the service.
    user_info = self._lookup_user_info(result["token"], result["secret"])
    user_info.update(result)

    return user_info

  def _get_auth_token(self):
    """Get Authorization Token.

    Actually gets the authorization token and secret from the service. The
    token and secret are stored in our database, and the auth token is
    returned.
    """

    response = self.make_request(self.request_url)
    result = self._extract_credentials(response)

    auth_token = result["token"]
    auth_secret = result["secret"]

    # Save the auth token and secret in our database.
    auth = AuthToken(service=self.service_name,
                     token=auth_token,
                     secret=auth_secret)
    auth.put()

    # Add the secret to memcache as well.
    memcache.set(self._get_memcache_auth_key(auth_token), auth_secret,
                 time=20*60)

    return auth_token

  def _get_memcache_auth_key(self, auth_token):

    return "oauth_%s_%s" % (self.service_name, auth_token)

  def _extract_credentials(self, result):
    """Extract Credentials.

    Returns an dictionary containing the token and secret (if present).
    Throws an Exception otherwise.
    """

    token = None
    secret = None
    parsed_results = parse_qs(result.content)

    if "oauth_token" in parsed_results:
      token = parsed_results["oauth_token"][0]

    if "oauth_token_secret" in parsed_results:
      secret = parsed_results["oauth_token_secret"][0]

    if not (token and secret) or result.status_code != 200:
      logging.error("Could not extract token/secret: %s" % result.content)
      raise OAuthException("Problem talking to the service")

    return {
      "service": self.service_name,
      "token": token,
      "secret": secret
    }

  def _lookup_user_info(self, access_token, access_secret):
    """Lookup User Info.

    Complies a dictionary describing the user. The user should be
    authenticated at this point. Each different client should override
    this method.
    """

    raise NotImplementedError, "Must be implemented by a subclass"

  def _get_default_user_info(self):
    """Get Default User Info.

    Returns a blank array that can be used to populate generalized user
    information.
    """

    return {
      "id": "",
      "username": "",
      "name": "",
      "picture": ""
    }


class TwitterClient(OAuthClient):
  """Twitter Client.

  A client for talking to the Twitter API using OAuth as the
  authentication model.
  """

  def __init__(self, consumer_key, consumer_secret, callback_url):
    """Constructor."""

    OAuthClient.__init__(self,
        "twitter",
        consumer_key,
        consumer_secret,
        "http://twitter.com/oauth/request_token",
        "http://twitter.com/oauth/access_token",
        callback_url)

  def get_authorization_url(self):
    """Get Authorization URL."""

    token = self._get_auth_token()
    return "http://twitter.com/oauth/authorize?oauth_token=%s" % token

  def _lookup_user_info(self, access_token, access_secret):
    """Lookup User Info.

    Lookup the user on Twitter.
    """

    response = self.make_request(
        "http://twitter.com/account/verify_credentials.json",
        token=access_token, secret=access_secret, protected=True)

    data = json.loads(response.content)

    user_info = self._get_default_user_info()
    user_info["id"] = data["id"]
    user_info["username"] = data["screen_name"]
    user_info["name"] = data["name"]
    user_info["picture"] = data["profile_image_url"]

    return user_info


class MySpaceClient(OAuthClient):
  """MySpace Client.

  A client for talking to the MySpace API using OAuth as the
  authentication model.
  """

  def __init__(self, consumer_key, consumer_secret, callback_url):
    """Constructor."""

    OAuthClient.__init__(self,
        "myspace",
        consumer_key,
        consumer_secret,
        "http://api.myspace.com/request_token",
        "http://api.myspace.com/access_token",
        callback_url)

  def get_authorization_url(self):
    """Get Authorization URL."""

    token = self._get_auth_token()
    return ("http://api.myspace.com/authorize?oauth_token=%s"
            "&oauth_callback=%s" % (token, urlquote(self.callback_url)))

  def _lookup_user_info(self, access_token, access_secret):
    """Lookup User Info.

    Lookup the user on MySpace.
    """

    response = self.make_request("http://api.myspace.com/v1/user.json",
        token=access_token, secret=access_secret, protected=True)

    data = json.loads(response.content)

    user_info = self._get_default_user_info()
    user_info["id"] = data["userId"]
    username = data["webUri"].replace("http://www.myspace.com/", "")
    user_info["username"] = username
    user_info["name"] = data["name"]
    user_info["picture"] = data["image"]

    return user_info


class YahooClient(OAuthClient):
  """Yahoo! Client.

  A client for talking to the Yahoo! API using OAuth as the
  authentication model.
  """

  def __init__(self, consumer_key, consumer_secret, callback_url):
    """Constructor."""

    OAuthClient.__init__(self,
        "yahoo",
        consumer_key,
        consumer_secret,
        "https://api.login.yahoo.com/oauth/v2/get_request_token",
        "https://api.login.yahoo.com/oauth/v2/get_token",
        callback_url)

  def get_authorization_url(self):
    """Get Authorization URL."""

    token = self._get_auth_token()
    return ("https://api.login.yahoo.com/oauth/v2/request_auth?oauth_token=%s"
            % token)

  def _lookup_user_info(self, access_token, access_secret):
    """Lookup User Info.

    Lookup the user on Yahoo!
    """

    user_info = self._get_default_user_info()

    # 1) Obtain the user's GUID.
    response = self.make_request(
        "http://social.yahooapis.com/v1/me/guid", token=access_token,
        secret=access_secret, additional_params={"format": "json"},
        protected=True)

    data = json.loads(response.content)["guid"]
    guid = data["value"]

    # 2) Inspect the user's profile.
    response = self.make_request(
        "http://social.yahooapis.com/v1/user/%s/profile/usercard" % guid,
         token=access_token, secret=access_secret,
         additional_params={"format": "json"}, protected=True)

    data = json.loads(response.content)["profile"]

    user_info["id"] = guid
    user_info["username"] = data["nickname"].lower()
    user_info["name"] = data["nickname"]
    user_info["picture"] = data["image"]["imageUrl"]

    return user_info
