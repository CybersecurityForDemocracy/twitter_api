#!/usr/bin/env python3

import base64
import time
import requests
from requests_oauthlib import OAuth1
from bs4 import BeautifulSoup
import configparser
import logging
from collections import defaultdict


# Logging parameters
logging.getLogger("urllib3").propagate = True
logging.getLogger("requests").propagate = True
logging.basicConfig(level=logging.INFO)


class TwitterApiError(Exception):
    pass


class TwitterApi:

    def __init__(self):
        '''Class Initialization'''

        # Read Credentials
        Config = configparser.ConfigParser()
        Config.read("credentials.ini")
        consumer_key = Config.get("TwitterCredentials", "consumer_key")
        consumer_secret = Config.get("TwitterCredentials", "consumer_secret")
        access_token = Config.get("TwitterCredentials", "access_token")
        access_token_secret = Config.get("TwitterCredentials", "access_token_secret")
        self.session = requests.Session()
        self.url_counter = defaultdict(int)
        self.access_objs = []
        self.url = "https://twitter.com"
        self.api_base_url = 'https://api.twitter.com/'
        self.loginPost = "https://twitter.com/sessions"
        self.ads_guest_token = None
        self.ads_bearer_auth = 'AAAAAAAAAAAAAAAAAAAAAOLv4AAAAAAAQubRLkVexZO02uKUva6eI9ZHmMY%3D3jfkYEj27hoTzTlXvxRiMg0wSb285GH9h2WfCvEeOh53QyxA5j'
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36'

        # Add App Authentication to Access Objects
        self.access_objs.append({'type': 'app',
                                 'name': 'app',
                                 'consumer_key': consumer_key,
                                 'consumer_secret': consumer_secret,
                                 'token': self.get_token(consumer_key, consumer_secret),
                                 'rate_limit_remaining': defaultdict(int),
                                 'rate_limit_reset': defaultdict(int)})

    def get_token(self, consumer_key: str, consumer_secret: str) -> str:
        '''Get API Token'''
        key_secret = '{}:{}'.format(consumer_key, consumer_secret).encode('ascii')
        b64_encoded_key = base64.b64encode(key_secret).decode('ascii')
        base_url = 'https://api.twitter.com/'
        auth_url = '{}oauth2/token'.format(base_url)
        auth_headers = {'Authorization': 'Basic {}'.format(b64_encoded_key),
                        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'}
        auth_data = {'grant_type': 'client_credentials'}
        auth_resp = requests.post(auth_url, headers=auth_headers, data=auth_data)
        access_token = auth_resp.json()['access_token']
        return access_token

    def fetch_login_auth_token(self):
        '''Fetch authentication token'''

        data = {"session[username_or_email]": self.username.encode('ascii'),
                "session[password]": self.password.encode('ascii'),
                "scribe_log": "",
                "redirect_after_login": "/",
                "remember_me": "1"}

        with self.session:
            resp = self.session.get(self.url)
            soup = BeautifulSoup(resp.content, "lxml")
            self.auth_token = soup.select_one("input[name=authenticity_token]")["value"]
            self.ui_metric = soup.select_one("input[name=ui_metrics]")

        # update data, post and you are logged in.
        data["authenticity_token"] = self.auth_token
        data['ui_metrics'] = self.ui_metric

    def fetch_ads_guest_token(self):
        '''Fetch a new guest token for the ads library'''
        url = "https://api.twitter.com/1.1/guest/activate.json"
        headers = {'authorization': 'Bearer {}'.format(self.ads_bearer_auth)}
        req = self.make_request(url, headers=headers, type='post', use_auth=False)
        self.ads_guest_token = req.json()['guest_token']

    def ads_timeline(self, user_id: int, cursor: int = 0) -> dict:
        '''Fetch Twitter ad data for a user'''
        url = "https://ads.twitter.com/transparency/ads_timeline.json"
        params = {}
        params['user_id'] = user_id
        if self.ads_guest_token is None:
            self.fetch_ads_guest_token()
        headers = {'x-guest-token': str(self.ads_guest_token), 'authorization': 'Bearer {}'.format(self.ads_bearer_auth)}
        r = self.make_request(url, params, headers)
        if r.status_code == 403:
            self.fetch_ads_guest_token()
            r = self.make_request(url, params, headers)
        if r.ok:
            status_ids = []
            data = []
            for obj in r.json()['ads']:
                status_ids.append(obj['creativeId'])
            if status_ids:
                tweets = self.statuses_lookup(id=status_ids, map=True)
            creativeIds = tweets['id']
            for obj in r.json()['ads']:
                if obj['creativeId'] in creativeIds:
                    obj['data'] = creativeIds[obj['creativeId']]
                else:
                    obj['data'] = None
                data.append(obj)
            return data

    def statuses_lookup(self, **kwargs):
        '''Fetch individual statuses (up to 100 per call)'''
        allowed_params = ['id', 'include_entities', 'trim_user', 'map', 'include_ext_alt_text', 'include_card_uri', 'tweet_mode']

        # Set Default parameters
        if 'tweet_mode' not in kwargs:
            kwargs['tweet_mode'] = 'extended'

        # Remove unknown parameters
        for k in kwargs.keys():
            if k not in allowed_params:
                kwargs.pop(k, None)

        if len(kwargs['id']) > 100:
            raise TwitterApiError("More than 100 ids used for statuses_lookup")

        kwargs['id'] = ','.join([str(id) for id in kwargs['id']])
        url = '{}1.1/statuses/lookup.json'.format(self.api_base_url)
        r = self.make_request(url, params=kwargs)
        if r.ok:
            return r.json()

    def users_lookup(self, **kwargs) -> dict:
        '''Fetch user info (up to 100 per call)'''
        allowed_params = ['screen_name', 'user_id', 'include_entities', 'tweet_mode']

        # Set Default parameters
        if 'tweet_mode' not in kwargs:
            kwargs['tweet_mode'] = 'extended'

        # Remove unknown parameters
        for k in kwargs.keys():
            if k not in allowed_params:
                kwargs.pop(k, None)

        for k in ['screen_name', 'user_id']:
            if k in kwargs:
                kwargs[k] = ','.join(kwargs[k])

        url = '{}1.1/users/lookup.json'.format(self.api_base_url)
        r = self.make_request(url, params=kwargs)
        if r.ok:
            return r.json()

    def lists_list(self, **kwargs) -> dict:
        '''Get list of lists for a user'''
        allowed_params = ['user_id', 'screen_name', 'reverse']

        # Remove unknown parameters
        for k in kwargs.keys():
            if k not in allowed_params:
                kwargs.pop(k, None)

        url = '{}1.1/lists/list.json'.format(self.api_base_url)
        r = self.make_request(url, params=kwargs)
        if r.ok:
            return r.json()

    def lists_members(self, **kwargs) -> dict:
        '''Get members of a specific list'''
        allowed_params = ['list_id', 'slug', 'owner_screen_name', 'owner_id', 'count', 'cursor']

        # Set Default parameters
        if 'count' not in kwargs:
            kwargs['count'] = 5000

        # Remove unknown parameters
        for k in kwargs.keys():
            if k not in allowed_params:
                kwargs.pop(k, None)

        url = '{}1.1/lists/members.json'.format(self.api_base_url)
        r = self.make_request(url, params=kwargs)
        if r.ok:
            return r.json()

    def lists_memberships(self, **kwargs) -> dict:
        '''Gets lists where a particular user is a member'''
        allowed_params = ['user_id', 'screen_name', 'count', 'cursor', 'filter_to_owned_lists']

        # Set Default parameters
        if 'count' not in kwargs:
            kwargs['count'] = 500

        # Remove unknown parameters
        for k in kwargs.keys():
            if k not in allowed_params:
                kwargs.pop(k, None)

        url = '{}1.1/lists/memberships.json'.format(self.api_base_url)
        r = self.make_request(url, params=kwargs)
        if r.ok:
            return r.json()

    def lists_subscribers(self, **kwargs) -> dict:
        '''Gets subscribers to a list'''
        allowed_params = ['list_id', 'slug', 'owner_screen_name', 'owner_id', 'count', 'cursor', 'include_entities', 'skip_status']

        # Set Default parameters
        if 'count' not in kwargs:
            kwargs['count'] = 5000

        # Remove unknown parameters
        for k in kwargs.keys():
            if k not in allowed_params:
                kwargs.pop(k, None)

        url = '{}1.1/lists/subscribers.json'.format(self.api_base_url)
        r = self.make_request(url, params=kwargs)
        if r.ok:
            return r.json()

    def lists_statuses(self, **kwargs) -> dict:
        '''Gets lists where a particular user is a member'''
        allowed_params = ['list_id', 'slug', 'owner_screen_name', 'owner_id', 'since_id', 'max_id', 'count', 'include_entities', 'include_rts']

        # Set Default parameters
        if 'count' not in kwargs:
            kwargs['count'] = 100

        # Remove unknown parameters
        for k in kwargs.keys():
            if k not in allowed_params:
                kwargs.pop(k, None)

        url = '{}1.1/lists/statuses.json'.format(self.api_base_url)
        r = self.make_request(url, params=kwargs)
        if r.ok:
            return r.json()

    def friends_list(self, **kwargs) -> dict:
        '''Get friends list for a user'''
        allowed_params = ['user_id', 'screen_name', 'cursor', 'count', 'skip_status', 'include_user_entries']

        # Set Default parameters
        if 'count' not in kwargs:
            kwargs['count'] = 200

        # Remove unknown parameters
        for k in kwargs.keys():
            if k not in allowed_params:
                kwargs.pop(k, None)

        url = '{}1.1/friends/list.json'.format(self.api_base_url)
        r = self.make_request(url, params=kwargs)
        if r.ok:
            return r.json()

    def friends_ids(self, **kwargs) -> dict:
        '''Get friends ids for a user'''
        allowed_params = ['user_id', 'screen_name', 'cursor', 'stringify_ids', 'count']

        # Set Default parameters
        if 'count' not in kwargs:
            kwargs['count'] = 5000

        # Remove unknown parameters
        for k in kwargs.keys():
            if k not in allowed_params:
                kwargs.pop(k, None)

        url = '{}1.1/friends/ids.json'.format(self.api_base_url)
        r = self.make_request(url, params=kwargs)
        if r.ok:
            return r.json()

    def followers_list(self, **kwargs) -> dict:
        '''Get followers list for a user'''
        allowed_params = ['user_id', 'screen_name', 'cursor', 'count', 'skip_status', 'include_user_entries']

        # Set Default parameters
        if 'count' not in kwargs:
            kwargs['count'] = 200

        # Remove unknown parameters
        for k in kwargs.keys():
            if k not in allowed_params:
                kwargs.pop(k, None)

        url = '{}1.1/followers/list.json'.format(self.api_base_url)
        r = self.make_request(url, params=kwargs)
        if r.ok:
            return r.json()

    def follower_ids(self, **kwargs) -> dict:
        '''Get follower ids for a user'''
        allowed_params = ['user_id', 'screen_name', 'cursor', 'stringify_ids', 'count']

        # Set Default parameters
        if 'count' not in kwargs:
            kwargs['count'] = 5000

        # Remove unknown parameters
        for k in kwargs.keys():
            if k not in allowed_params:
                kwargs.pop(k, None)

        url = '{}1.1/followers/ids.json'.format(self.api_base_url)
        r = self.make_request(url, params=kwargs)
        if r.ok:
            return r.json()

    def get_access_obj(self, access_objs, url):

        while True:
            for obj in access_objs:
                if obj['rate_limit_remaining'][url] > 0 or obj['rate_limit_reset'][url] < int(time.time()):
                    return obj

        time.sleep(1)

    def make_request(self, url: str, params: dict = {}, headers: dict = {}, type: str = 'get', use_auth=True, user_auth=None) -> dict:
        '''Helper function for Twitter API calls'''

        retries = 0
        max_retries = 3
        self.url_counter['url'] += 1

        if user_auth:
            access_obj = self.access_objs[0]
        else:
            access_obj = self.get_access_obj(self.access_objs, url)

        while True:
            auth = None
            if use_auth:
                if 'token' in access_obj:
                    if 'authorization' not in headers:
                        headers.update({'authorization': 'Bearer {}'.format(access_obj['token'])})
                else:
                    auth = OAuth1(access_obj['consumer_key'], access_obj['consumer_secret'], access_obj['access_token'], access_obj['access_token_secret'])
            if type == 'get':
                r = requests.get(url, params=params, headers=headers, auth=auth)
            elif type == 'post':
                r = requests.post(url, params=params, headers=headers, auth=auth)
            status_code = r.status_code
            response_headers = r.headers
            if 'x-rate-limit-remaining' in response_headers:
                rate_limit_remaining = int(response_headers['x-rate-limit-remaining'])
                rate_limit_reset = int(response_headers['x-rate-limit-reset'])
                access_obj['rate_limit_remaining'][url] = rate_limit_remaining
                access_obj['rate_limit_reset'][url] = rate_limit_reset
            if status_code == 200:
                return r
            elif status_code == 429:
                access_obj = self.get_access_obj(self.access_objs, url)
                retries += 1
                logging.warning("Rate limit reached. Sleeping for {} seconds...".format((rate_limit_reset - int(time.time())+1)))
            elif status_code == 401:
                return None
            elif status_code == 403:
                logging.warning("Received status error code {} to endpoint {}".format(status_code, url))
                return r
            elif status_code == 404:
                return None
            else:
                logging.warning("Received status error code {} making call to endpoint {}".format(status_code, url))
                retries += 1
                time.sleep(retries**2)
            if retries > max_retries:
                return False
