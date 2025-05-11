'''
Web server to provide an encrypted ZFS key to a partner host.
This service is recommended to be installed on two hosts in a personal
home network: The main host (utilizing an encrypted ZFS filesystem) and
a partner host. In this cases, if one system boots up, the password
is retrieved from the partner host. If the partner host is not available,
a web form can be used to enter the encrypted password manually.
'''
import argparse
import urllib.request
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging


# HTML template for the index page (Bootstrap form)
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Captive Portal</title>
<link
href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css"
rel="stylesheet">
</head>
<body>
<div class="container mt-5">
<h1 class="text-center">Encrypted password not set.</h1>
<form action="/set_password" method="POST">
<div class="mb-3">
<label for="user_input" class="form-label">Enter ecrypted password</label>
<input type="text" class="form-control" id="user_input" name="user_input"
required>
</div>
<button type="submit" class="btn btn-primary">Submit</button>
</form>
</div>
</body>
</html>
'''


class ZFSRequestHandler(BaseHTTPRequestHandler):
    ''' Implementation of the HTTP request handler for the server. '''

    def __init__(self, *args, partner_host=None, encpasswd=None, **kwargs):
        ''' Initializes the request handler '''
        super().__init__(*args, **kwargs)
        self.partner_host = partner_host
        self.encpasswd = encpasswd

    def do_GET(self):
        ''' Overrides the do_GET method to handle GET requests. '''

        if self.path == '/password':
            client_ip = self.client_address[0]
            if client_ip != self.partner_host:
                self.send_response(403)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'403 Forbidden: Access denied.\n')
                return

            # If password is set, return it, otherwise redirect to index page
            if self.encpasswd is not None:
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(self.encpasswd)
            else:
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'404 Not Found: Password not set.\n')

        else:
            # For all other routes, serve the index page
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode('utf-8'))

    def do_POST(self):
        ''' Overrides the do_POST method to handle POST requests. '''

        if self.path == '/set_password':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            # Parse the form data
            form_data = urllib.parse.parse_qs(post_data.decode('utf-8'))
            user_input = form_data.get('user_input', [None])[0]

            if user_input:
                self.encpasswd = user_input.encode('utf-8')
                logging.info('Set ENCPASSWD to *%s*', self.encpasswd.decode())
            # Redirect back to the index page after setting the password
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()


def fetch_plain_text(url):
    ''' Fetches plain text from a given URL. '''
    try:
        with urllib.request.urlopen(url) as response:
            content_type = response.headers.get_content_type()
            if content_type == 'text/plain':
                return response.read()
            else:
                logging.error("Content type is not 'text/plain': %s",
                              content_type)
                return None
    except urllib.error.URLError as e:
        logging.error("Failed to retrieve URL: %s", e)
        return None


def run(port, partner_host, encpasswd):
    ''' Runs the HTTP server. '''
    server_address = ('', port)
    handler_class = partial(
        ZFSRequestHandler, partner_host=partner_host, encpasswd=encpasswd
    )
    httpd = HTTPServer(server_address, handler_class)
    logging.info('Starting server on port %d...', port)
    httpd.serve_forever()


def main():
    ''' Main function to set up and run the server. '''
    # Set up logging
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(description='VZE Key Provider')
    parser.add_argument('--port', type=int, default=8901,
                        help='Port to run the server on')
    parser.add_argument('--partner-service', type=str,
                        default='partner.example.com:8901',
                        help='Partner service address')
    args = parser.parse_args()

    port = args.port
    partner_service = args.partner_service
    partner_host = partner_service.split(':')[0]

    encpasswd = fetch_plain_text(f"http://{partner_service}/password")

    # Check if the password is already set
    if encpasswd is not None:
        logging.info('Encrypted password already set: %s', encpasswd.decode())

    run(port=port, partner_host=partner_host, encpasswd=encpasswd)
