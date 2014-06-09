#!/usr/bin/env python

__author__ = "Tim Henrich"
__copyright__ = "Copyright 2014, Loop Science"
__credits__ = ["Tim Henrich"]
__license__ = "Apache"
__version__ = "0.1"
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

    def build_string_to_sign(self, uri, t, data={}):
        if len(data) is not 0:
            return '%s%s%s' % (uri, data, t)

        return '%s%s' % (uri, t)

    def request(self, uri, t, type, data={}):
        headers = {}
        headers['X-LS-Time'] = t
        headers['X-LS-Key'] = self.key
        headers['X-LS-Auth'] = base64.b64encode(hmac.new(self.get_secret(), self.build_string_to_sign(uri, t, data), hashlib.sha512).digest())
        headers['Content-Type'] = 'text/json'

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

class Segment(TurretIO):

    URI = '/latest/segment'

    def __init__(self, key, secret):
        super(Segment, self).__init__(key, secret)

    def get(self, name):
        return self.GET('%s/%s' % (self.URI, name))

    def create(self, name, attribute_map):
        return self.POST('%s/%s' % (self.URI, name),
                         {'attributes': attribute_map})

    def update(self, name, attribute_map):
        return self.POST('%s/%s' % (self.URI, name),
                         {'attributes': attribute_map})


class SegmentEmail(TurretIO):

    URI = '/latest/segment'

    def __init__(self, key, secret):
        super(SegmentEmail, self).__init__(key, secret)

    def get(self, segment_name, email_id):
        return self.GET('%s/%s/email/%s' % (self.URI, segment_name, email_id))

    def create(self, segment_name, subject, html_body, plain_body):
        return self.POST('%s/%s/email' % (self.URI, segment_name),
            {'subject': subject, 'html': html_body, 'plain': plain_body})

    def update(self, segment_name, email_id, subject, html_body, plain_body):
        return self.POST('%s/%s/email/%s' % (self.URI, segment_name, email_id),
            {'subject': subject, 'html': html_body, 'plain': plain_body})

    def sendTest(self, segment_name, email_id, email_from, recipient):
        return self.POST('%s/%s/email/%s/sendTestEmail' % (self.URI, segment_name, email_id),
            {'email_from': email_from, 'recipient': recipient})

    def send(self, segment_name, email_id, email_from):
        return self.POST('%s/%s/email/%s/sendEmail' % (self.URI, segment_name, email_id),
            {'email_from': email_from})


class User(TurretIO):

    URI = '/latest/user'

    def __init__(self, key, secret):
        super(User, self).__init__(key, secret)

    def get(self, email):
        return self.GET('%s/%s' % (self.URI, email))

    def set(self, email, attribute_map, property_map={}):
        if len(property_map) > 0:
            attribute_map['properties'] = property_map

        return self.POST('%s/%s' % (self.URI, email), attribute_map)

