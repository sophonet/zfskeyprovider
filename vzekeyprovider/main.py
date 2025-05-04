import json
import argparse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import logging

encpasswd = None
partner_host = None

# HTML template for the index page (Bootstrap form)
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Captive Portal</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Encrypted password not set.</h1>
        <form action="/set_password" method="POST">
            <div class="mb-3">
                <label for="user_input" class="form-label">Enter ecrypted password</label>
                <input type="text" class="form-control" id="user_input" name="user_input" required>
            </div>
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>
    </div>
</body>
</html>
'''


# Create the HTTPRequestHandler class
class RequestHandler(BaseHTTPRequestHandler):

    # Serve the index route with the HTML form
    def do_GET(self):
        global partner_host
        global encpasswd

        if self.path == '/password':
            client_ip = self.client_address[0]
            if client_ip != partner_host:
                self.send_response(403)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'403 Forbidden: Access denied.\n')
                return
        
            # If password is set, return it, otherwise redirect to index page
            if encpasswd is not None:
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(encpasswd)
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

    # Handle the form submission to set the password
    def do_POST(self):
        global encpasswd

        if self.path == '/set_password':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            # Parse the form data
            form_data = urllib.parse.parse_qs(post_data.decode('utf-8'))
            user_input = form_data.get('user_input', [None])[0]

            if user_input:
                encpasswd = user_input.encode('utf-8')
                logging.info(f'Set encpasswd to *{encpasswd}*')
            # Redirect back to the index page after setting the password
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()

def fetch_plain_text(url):
    try:
        with urllib.request.urlopen(url) as response:
            content_type = response.headers.get_content_type()
            if content_type == 'text/plain':
                return response.read()
            else:
                logging.error(f"Content type is not 'text/plain': {content_type}")
                return None
    except urllib.error.URLError as e:
        logging.error(f"Failed to retrieve URL: {e}")
        return None

# Start the HTTP server
def run(server_class=HTTPServer, handler_class=RequestHandler, port=8901):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info(f'Starting server on port {port}...')
    httpd.serve_forever()


def main():
    global encpasswd
    global partner_host

    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(description='VZE Key Provider')
    parser.add_argument('--port', type=int, default=8901, help='Port to run the server on')
    parser.add_argument('--partner-service', type=str, default='partner.example.com:8901', help='Partner service address')
    args = parser.parse_args()

    port = args.port
    partner_service = args.partner_service
    partner_host = partner_service.split(':')[0]

    encpasswd = fetch_plain_text(f"http://{partner_service}/password")

    # Check if the password is already set
    if encpasswd is not None:
        logging.info(f'Encrypted password already set: {encpasswd.decode()}')

    run(port=port)

