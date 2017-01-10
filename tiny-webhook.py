#!/usr/bin/python3
import argparse
import hashlib
import hmac
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import pprint
import os
import sys

HOOK_SECRET_KEY = os.environb[b'HOOK_SECRET_KEY']

class GithubHookHandler(BaseHTTPRequestHandler):
    """Base class for webhook handlers.

    Subclass it and implement 'handle_payload'.
    """
    def _validate_signature(self, data):
        sha_name, signature = self.headers['X-Hub-Signature'].split('=')
        if sha_name != 'sha1':
            return False

        # HMAC requires its key to be bytes, but data is strings.
        mac = hmac.new(HOOK_SECRET_KEY, msg=data, digestmod=hashlib.sha1)
        return hmac.compare_digest(mac.hexdigest(), signature)

    def do_POST(self):
        data_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(data_length)

        if not self._validate_signature(post_data):
            self.send_response(401)
            return

        payload = json.loads(post_data.decode('utf-8'))
        self.handle_payload(self.headers['X-GitHub-Event'], payload)
        self.send_response(202)
        #self.send_header('Content-type','text/html')
        self.end_headers()


class MyHandler(GithubHookHandler):
    def handle_payload(self, event_type, json_payload):
        """Simple handler for the json payload.
           Events we should support are 'ping', 'push', and 'release'"""
        print('Event: ' + event_type)

        print('JSON payload')
        pprint.pprint(json_payload)


if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='Github hook handler')
    argparser.add_argument('port', type=int, help='TCP port to listen on')
    args = argparser.parse_args()

    server = HTTPServer(('', args.port), MyHandler)
    server.serve_forever()
