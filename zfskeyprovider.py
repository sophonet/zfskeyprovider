import argparse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client
import logging
from functools import partial
import configparser
import os
import sys

DEFAULT_CONFIG_FILE = '/etc/zfskeyprovider.conf'

# HTML template for the index page (Bootstrap form)
HTML_ENTERPASSWORD = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZFS Key Server</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">ZFS encrypted key service</h1>
        <form action="/set_password" method="POST">
            <div class="mb-3">
                <label for="user_input" class="form-label">Enter base64-encoded SSL-encrypted ZFS password</label>
                <input type="text" class="form-control" id="user_input" name="user_input" required>
            </div>
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>
    </div>
    <div class="container mt-5">
        <h2>Instructions</h2>
        <ol class="list-group list-group-numbered">
            <li class="list-group-item d-flex justify-content-between align-items-start">
                <div class="ms-2 me-auto">
                    <div class="fw-bold">Create a good random password, store it in shared memory /dev/shm on ZFS system and use it for creating encrypted ZFS filesystems</div>
<pre><code>zfs create -o encryption=on -o keyformat=passphrase -o keylocation=file:///dev/shm/zfspwd poolname/dataset</code></pre>
                </div>
            </li>
            <li class="list-group-item d-flex justify-content-between align-items-start">
                <div class="ms-2 me-auto">
                    <div class="fw-bold">Create a public/private SSL keypair for encrypting/decrypting the password</div>
<pre><code>openssl genpkey -algorithm RSA -out private_key.pem
openssl rsa -pubout -in private_key.pem -out public_key.pem</code></pre>
                </div>
            </li>
            <li class="list-group-item d-flex justify-content-between align-items-start">
                <div class="ms-2 me-auto">
                    <div class="fw-bold">Encrypt the password with the public key and generate base64 encoded string</div>
<pre><code>openssl pkeyutl -encrypt -pubin -inkey public.key -in /dev/shm/zfspwd -out encrypted.bin
base64 encrypted.bin > encrypted.b64</code></pre>
                </div>
            </li>
            <li class="list-group-item d-flex justify-content-between align-items-start">
                <div class="ms-2 me-auto">
                    <div class="fw-bold">Copy content of <code>encrypted.b64</code> into text field above and submit.</div>
                </div>
            </li>
            <li class="list-group-item d-flex justify-content-between align-items-start">
                <div class="ms-2 me-auto">
                    <div class="fw-bold">Start another instance of this server on partner system.</div>
                </div>
            </li>
            <li class="list-group-item d-flex justify-content-between align-items-start">
                <div class="ms-2 me-auto">
                    <div class="fw-bold">Prepare loading zfs key (see <code>examples/zfs-load-key.service</code>), which retrieves the password, decrypts it with the private SSL key and unlocks zfs filesystems.</div>
                </div>
            </li>
            <li class="list-group-item d-flex justify-content-between align-items-start">
                <div class="ms-2 me-auto">
                    <div class="fw-bold">Enable services for the two key provider servers and the zfs-load-key.service.</div>
                </div>
            </li>
        </ol>
    </div>
</body>
</html>
'''

HTML_CONFIRMATION = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZFS Key server</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Thank you for entering encrypted password.</h1>
        <p class="text-center">Password is {}.</p>
        <a href="/" class="btn btn-primary" tabindex="-1" role="button" aria-disabled="true">Return to main page.</a>
    </div>
</body>
</html>
'''

class encpwdstore:
    """ A simple class to store/retrieve the encrypted password
        persistently for multiple http requests.
    """
    def __init__(self, encpasswd: bytes = None):
        self.encpasswd = encpasswd

    def set_encpasswd(self, encpasswd: bytes):
        self.encpasswd = encpasswd

    def get_encpasswd(self) -> bytes:
        return self.encpasswd


class ZFSKeyRequestHandler(BaseHTTPRequestHandler):
    """ HTTP request handler for ZFS key provider service.
    """
    def __init__(self, partner_host: str, encpwdstore: encpwdstore, *args, **kwargs):
        self.partner_host = partner_host
        self.encpwdstore = encpwdstore
        # BaseHTTPRequestHandler calls do_GET **inside** __init__ !!!
        # So we have to call super().__init__ after setting attributes.
        super().__init__(*args, **kwargs)


    def do_GET(self):
        """ Handle GET requests for the ZFS key provider service. If the path is '/password',
            it checks if the request is from the allowed partner host and returns the encrypted password.
            For all other paths, it serves the index page with instructions on how to use the service
            and set the password.
        """
        if self.path == '/password':
            client_ip = self.client_address[0]
            if (self.partner_host is not None) and (client_ip != self.partner_host):
                self.send_response(403)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'403 Forbidden: Access denied.\n')
                return
        
            # If password is set, return it, otherwise redirect to index page
            if self.encpwdstore.get_encpasswd() is not None:
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(self.encpwdstore.get_encpasswd())
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
            self.wfile.write(HTML_ENTERPASSWORD.encode('utf-8'))


    def do_POST(self):
        """ Handle POST requests to set the encrypted password.
        """
        if self.path == '/set_password':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            # Parse the form data
            form_data = urllib.parse.parse_qs(post_data.decode('utf-8'))
            user_input = form_data.get('user_input', [None])[0]

            if user_input:
                self.encpwdstore.set_encpasswd(user_input.encode('utf-8'))
                logging.info(f'Set encpasswd to *{self.encpwdstore.get_encpasswd().decode("utf-8")}*')
            # Redirect back to the index page after setting the password
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_CONFIRMATION.format(self.encpwdstore.get_encpasswd().decode(" utf-8")).encode('utf-8'))


def fetch_plain_text(parner_service: str) -> bytes:
    """ Fetch plain text content from a given partner service URL.
    """
    try:
        with urllib.request.urlopen(parner_service) as response:
            content_type = response.headers.get_content_type()
            if content_type == 'text/plain':
                return response.read()
            else:
                logging.error(f"Content type is not 'text/plain': {content_type}")
                return None
    except urllib.error.URLError as e:
        logging.error(f"Failed to retrieve URL: {e}")
        return None
    except http.client.RemoteDisconnected as e:
        logging.error(f"Remote disconnected: {e}")
        return None


def run(port: int, partner_host: str, encpasswd: bytes = None):
    """ Run the HTTP server on the specified port.
    """
    server_address = ('', port)
    myencpwdstore = encpwdstore(encpasswd)
    handler_class = partial(ZFSKeyRequestHandler, partner_host, myencpwdstore)
    httpd = HTTPServer(server_address, handler_class)
    logging.info(f'Starting server on port {port}...')
    httpd.serve_forever()


if __name__ == '__main__':
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(description='VZE Key Provider')
    parser.add_argument('--config', type=str, default=DEFAULT_CONFIG_FILE, help='Path to the configuration file')
    args = parser.parse_args()

    config_file_name = args.config

    if not os.path.exists(config_file_name):
        logging.error(f"Config file not found: %s", config_file_name)
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(config_file_name)

    if config.has_option('zfskeyprovider', 'port'):
        port = config.getint('zfskeyprovider', 'port')
    else:
        port = 8901

    if config.has_option('zfskeyprovider', 'partner_service'):
        partner_service = config.get('zfskeyprovider', 'partner_service')
        partner_host = partner_service.split(':')[0]
        encpasswd = fetch_plain_text(f"http://{partner_service}/password")

        # Check if the password is already set
        if encpasswd is not None:
            logging.info(f'Encrypted password already set: {encpasswd.decode()}')
    else:
        partner_host = None
        encpasswd = None

    run(port=port, partner_host=partner_host, encpasswd=encpasswd)
