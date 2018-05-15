from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import sys
sys.path.append('../')
import keys
import rsa

from io import BytesIO

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello, world!')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        response = BytesIO()
        response.write(b'This is POST request. ')
        response.write(b'Received: ')
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
