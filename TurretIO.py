#!/usr/bin/env python

"""
Copyright 2014 Loop Science

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

__author__ = "Tim Henrich"
__copyright__ = "Copyright 2014, Loop Science"
__credits__ = ["Tim Henrich"]
__license__ = "Apache"
__version__ = "0.2"
__maintainer__ = "Tim Henrich"
__email__ = "tim@loopscience.com"
__status__ = "Production"

import base64, hmac, hashlib, time, json
import requests

DOMAIN='https://api.turret.io'

class CredentialsNotProvided(Exception):
    def __init__(self, message):
        super(CredentialsNotProvided, self).__init__(self, message)

class TurretIO(object):
    def __init__(self, key, secret):
        self.key = key
        self.secret = secret

    def get_secret(self):
        return base64.b64decode(self.secret)

    def build_string_to_sign(self, uri, t, data=None):
        if data is None:
            data = {}

        if len(data) is not 0:
            return '%s%s%s' % (uri, data, t)

        return '%s%s' % (uri, t)

    def make_headers(self, uri, t, data=None):
        if data is None:
            data = {}

        headers = {}
        headers['X-LS-Time'] = t
        headers['X-LS-Key'] = self.key
        headers['X-LS-Auth'] = base64.b64encode(hmac.new(self.get_secret(), self.build_string_to_sign(uri, t, data), hashlib.sha512).digest())
        headers['Content-Type'] = 'text/json'
        return headers

    def make_queue_request(self, uri, data=None):
        if data is None:
            data = {}
        t = str(int(time.time()))   
        headers = self.make_headers(uri, t, data)
        return {'url': uri, 'api_key': self.key, 'signature': headers['X-LS-Auth'], 'time': t, 'payload': base64.b64encode(data)} 
 
    def request(self, uri, t, type, data=None):
        if data is None:
            data = {}
        headers = self.make_headers(uri, t, data)
 
        if type == 'GET':
            return requests.get('%s%s' % (DOMAIN, uri), headers=headers)

        if type == 'POST':
            return requests.post('%s%s' % (DOMAIN, uri), base64.b64encode(data), headers=headers)

    def GET(self, uri):
        t = int(time.time())
        response = self.request(uri, t, 'GET')
        return response

    def POST(self, uri, data):
        t = int(time.time())
        response = self.request(uri, t, 'POST', json.dumps(data))
        return response

class Account(TurretIO):

    URI = '/latest/account'

    def __init__(self, key, secret):
        super(Account, self).__init__(key, secret)

    def get(self):
        return self.GET(self.URI)

    def set(self, outgoing_method, options={}):
        if outgoing_method == 'turret.io':
            return self.POST('%s/me' % self.URI, {'type':outgoing_method})

        if outgoing_method == 'aws':
            if 'aws_access_key' not in options or 'aws_secret_access_key' not in options:
                raise CredentialsNotProvided('AWS Credentials not provided')

            return self.POST('%s/me' % self.URI, {'type':outgoing_method, 'aws':options})

        if outgoing_method == 'smtp':
            if 'smtp_host' not in options \
            or 'smtp_username' not in options \
            or 'smtp_password' not in options:
                raise CredentialsNotProvided('SMTP credentials not provided')

            return self.POST('%s/me' % self.URI, {'type':outgoing_method, 'smtp':options})

        return None

class Target(TurretIO):

    URI = '/latest/target'

    def __init__(self, key, secret):
        super(Target, self).__init__(key, secret)

    def get(self, name):
        return self.GET('%s/%s' % (self.URI, name))

    def create(self, name, attribute_list):
        return self.POST('%s/%s' % (self.URI, name),
                         {'attributes': attribute_list})

    def update(self, name, attribute_list):
        return self.POST('%s/%s' % (self.URI, name),
                         {'attributes': attribute_list})


class TargetEmail(TurretIO):

    URI = '/latest/target'

    def __init__(self, key, secret):
        super(TargetEmail, self).__init__(key, secret)

    def get(self, target_name, email_id):
        return self.GET('%s/%s/email/%s' % (self.URI, target_name, email_id))

    def create(self, target_name, subject, html_body, plain_body):
        return self.POST('%s/%s/email' % (self.URI, target_name),
            {'subject': subject, 'html': html_body, 'plain': plain_body})

    def update(self, target_name, email_id, subject, html_body, plain_body):
        return self.POST('%s/%s/email/%s' % (self.URI, target_name, email_id),
            {'subject': subject, 'html': html_body, 'plain': plain_body})

    def sendTest(self, target_name, email_id, email_from, recipient):
        return self.POST('%s/%s/email/%s/sendTestEmail' % (self.URI, target_name, email_id),
            {'email_from': email_from, 'recipient': recipient})

    def send(self, target_name, email_id, email_from):
        return self.POST('%s/%s/email/%s/sendEmail' % (self.URI, target_name, email_id),
            {'email_from': email_from})


class User(TurretIO):

    URI = '/latest/user'

    def __init__(self, key, secret):
        super(User, self).__init__(key, secret)

    def setup_property_map(self, property_map=None):
        if property_map is None:
            property_map = {}

        return property_map 

    def get(self, email):
        return self.GET('%s/%s' % (self.URI, email))

    def set(self, email, attribute_map, property_map=None):
        attribute_map['properties'] = self.setup_property_map(property_map) 

        return self.POST('%s/%s' % (self.URI, email), attribute_map)


    def queue_set(self, email, attribute_map, property_map=None):
        attribute_map['properties'] = self.setup_property_map(property_map) 
        
        payload = self.make_queue_request('%s/%s' % (self.URI, email), json.dumps(attribute_map))
        return json.dumps({'api_key': payload['api_key'],
            'signature': payload['signature'],
            'time': payload['time'],
            'url': payload['url'],
            'payload': payload['payload']})

