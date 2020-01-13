"""
Licencing Agreement: MalwareTech Public Licence
This software is free to use providing the user yells "Oh no, the cyberhackers are coming!" prior to each installation.
"""

from http import server
import ssl
import logging
import logging.handlers
import os
import sys
import urllib.parse

# Set to True to detect failed directory traversal attempts and reward our friendly failed hacker with a gold star!
struggle_check = False


class CitrixHandler(server.SimpleHTTPRequestHandler):
    page_cache = {'403.html': '', 'login.html': '', 'smb.conf': '', 'gold_star.html': ''}

    def __init__(self, args, directory, kwargs):
        super().__init__(args, directory, kwargs)

    def do_HEAD(self):
        self.close_connection()

    # handle GET requests and attempt to emulate a vulnerable server
    def do_GET(self):
        self.log(logging.INFO, "GET Header: {}".format(self.path))

        if self.struggle_check(self.path):
            return

        # split the path by '/', ignoring empty string
        url_path = list(filter(None, self.path.split('/')))

        # if url is empty or path is /vpn/, display fake login page
        if len(url_path) == 0 or (len(url_path) == 1 and url_path[0] == 'vpn'):
            return self.send_response(self.get_page('login.html'))

        # check if the directory traversal bug has been tried
        if len(url_path) >= 3 and url_path[0] == 'vpn' and url_path[1] == '..':
            # collapse path to ignore extra / and .. for proper formatting
            collapsed_path = server._url_collapse_path(self.path)

            # 403 on /vpn/../vpns/ is used by some scanners to detect vulnerable hosts
            # Ex: https://github.com/cisagov/check-cve-2019-19781/blob/develop/src/check_cve/check.py
            if len(url_path) == 3 and url_path[2] == 'vpns':
                self.log(logging.WARN, "Detected type 1 CVE-2019-19781 scan attempt!")
                page_403 = self.get_page('403.html').replace('{url}', collapsed_path)
                return self.send_response(page_403)

            if len(url_path) >= 4 and url_path[2] == 'vpns' and url_path[3] == 'portal':
                self.log(logging.CRITICAL, "Detected CVE-2019-19781 completion!")
                return self.send_response("")

            # some scanners try to fetch smb.conf to detect vulnerable hosts
            # Ex: https://github.com/trustedsec/cve-2019-19781/blob/master/cve-2019-19781_scanner.py
            elif collapsed_path == '/vpns/cfg/smb.conf':
                self.log(logging.WARN, "Detected type 2 CVE-2019-19781 scan attempt!")
                return self.send_response(self.get_page('smb.conf'))

            # we got a request that sort of matches CVE-2019-19781, but it's not a know scan attempt
            else:
                self.log(logging.DEBUG, "Error: unhandled CVE-2019-19781 scan attempt: {}".format(self.path))
                self.send_response("")

        # if all else fails return nothing
        return self.send_response("")

    # handle POST requests to try and capture exploit payloads
    def do_POST(self):
        self.log(logging.INFO, "POST Header: {}".format(self.path))

        if 'Content-Length' in self.headers:
            collapsed_path = server._url_collapse_path(self.path)
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            self.log(logging.INFO, "POST body: {}".format(post_data))

            # RCE path is /vpns/portal/scripts/newbm.pl and payload is contained in POST data
            if content_length != 0 and collapsed_path == '/vpns/portal/scripts/newbm.pl':
                payload = urllib.parse.parse_qs(post_data)['title'][0]
                self.log(logging.CRITICAL, "Detected CVE-2019-19781 payload: {}".format(payload))

        if self.struggle_check(self.path):
            return

        # send empty response as we're now done
        return self.send_response('')

    def log(self, log_level, msg):
        logging.log(log_level, "({}:{}): {}".format(self.client_address[0], self.client_address[1], msg))

    def struggle_check(self, path):
        if struggle_check:
            # if the path does not contain /../ it's likely attacker was using a sanitized client which removed it
            if path in ['/vpns/portal/scripts/newbm.pl', '/vpns/cfg/smb.conf', '/vpns/']:
                self.log(logging.DEBUG, "Detected a failed directory traversal attempt")
                self.send_response(self.get_page("gold_star.html"))
                return True

        return False

    # a simple wrapper to cache files from "responses" folder
    def get_page(self, page):
        # if page is not in cache, load it from file
        if self.page_cache[page] == '':
            with open("responses/{}".format(page), 'r') as f:
                self.page_cache[page] = f.read()

        return self.page_cache[page]

    # overload base class's send_response() to set appropriate headers and server version
    def send_response(self, page, code=200, msg='OK'):
        self.wfile.write("HTTP/1.1 {} {}\r\n".format(code, msg).encode('utf-8'))
        self.send_header("Server", "Apache")
        self.send_header("Content-Length", len(page))
        self.send_header("Content-type", "text/html")
        self.send_header("Connection", "Close")
        self.end_headers()

        if page != '':
            self.wfile.write(page.encode('utf-8'))


if __name__ == '__main__':
    handler1 = logging.handlers.WatchedFileHandler(os.environ.get("LOGFILE", "logs/server.log"))
    handler2 = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
    handler1.setFormatter(formatter)
    handler2.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(os.environ.get("LOGLEVEL", "DEBUG"))
    root.addHandler(handler1)
    root.addHandler(handler2)

logging.log(logging.INFO, 'Citrix CVE-2019-19781 Honeypot by MalwareTech')

httpd = server.HTTPServer(('0.0.0.0', 443), CitrixHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
                               certfile='ssl/cert.pem',
                               keyfile='ssl/key.pem',
                               server_side=True)
httpd.serve_forever()
