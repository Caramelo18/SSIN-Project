from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import sys
sys.path.append('../')
import keys
import rsa

from io import BytesIO

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Hello, world!')
        elif self.path == '/public_key':
            get_public_key(self)


    def do_POST(self):
        if self.path == '/handshake':
            handshake(self)
            self.send_response(200)
            self.end_headers()
            self.write(b'POST Received)
        else:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            self.send_response(400)
            self.end_headers()


def get_public_key(self):
    self.send_response(200)
    self.end_headers()
    global public_key
    pbk = public_key.save_pkcs1('PEM')
    self.wfile.write(pbk)

def handshake(self):
    content_length = int(self.headers['Content-Length'])
    body = self.rfile.read(content_length)
    self.send_response(200)
    self.end_headers()
    response = BytesIO()
    response.write(b'handshake')
    response.write(body)
    self.wfile.write(response.getvalue())


def load_keys():
    keys.load_keys()
    global public_key, private_key
    public_key = keys.public_key
    private_key = keys.private_key

def main():
    load_keys()
    global public_key
    httpd = HTTPServer(('localhost', 8000), SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket (httpd.socket, keyfile="./key.pem", certfile='./cert.pem', server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)

    httpd.serve_forever()

if __name__ == '__main__':
    main()
