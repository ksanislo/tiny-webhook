#!/usr/bin/python3
import argparse
import hashlib
import hmac
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import pprint
import os
import subprocess
import sys


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
            self.end_headers()
            return

        payload = json.loads(post_data.decode('utf-8'))
        self.handle_payload(self.headers['X-GitHub-Event'], payload)

class MyHandler(GithubHookHandler):
    def handle_payload(self, event_type, json_payload):
        """
        Simple handler for the json payload.
        """
        repo_name = json_payload['repository']['full_name']
        run_me = os.path.join(HOOK_SCRIPT_PATH, repo_name, event_type)
        try:
            subprocess.Popen(run_me)
        except FileNotFoundError:
            self.send_response(501)
            status_message = 'Missing handler for ' + repo_name + ':' + event_type
        except PermissionError:
            self.send_response(500)
            status_message = 'Permission denied on handler for ' + repo_name + ':' + event_type
        else:
            self.send_response(202)
            status_message = 'Running handler for ' + repo_name + ':' + event_type
        self.end_headers()
        self.wfile.write(status_message.encode())
 
if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='Github hook handler')
    argparser.add_argument('--secret', type=str, required=True, help='GitHub secret string')
    argparser.add_argument('--port', type=int, default=6699, help='TCP port to listen on')
    argparser.add_argument('--scripts', type=str, required=True, help='Path to handler scripts')
    args = argparser.parse_args()

#HOOK_SECRET_KEY = os.environb[b'HOOK_SECRET_KEY']
    HOOK_SECRET_KEY = args.secret.encode()
    HOOK_SCRIPT_PATH = args.scripts

    server = HTTPServer(('', args.port), MyHandler)
    server.serve_forever()
