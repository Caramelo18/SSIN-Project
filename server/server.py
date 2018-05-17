from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import sys
sys.path.append('../')
import keys
import rsa
import cgi
import os
import base64
from random import randint


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200, "ok")
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Access-Control-Allow-Origin', 'http://localhost:8000')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header("Access-Control-Allow-Headers", "X-Requested-With, Content-type")

    def do_POST(self):
        if self.path == '/handshake':
            handshake(self)
        elif self.path == "/upload":
            save_file(self)

    def do_GET(self):
        if self.path == '/public_key':
            get_public_key(self)
        if self.path == '/restore':
            restore(self)


def save_file(self):
    content_length = int(self.headers['Content-Length'])

    directory = "backup"

    if not os.path.exists(directory):
        os.makedirs(directory)

    filename = directory + "/" + self.headers['Chunk']
    File = open(filename, 'wb')

    body = self.rfile.read(content_length)
    File.write(body)

    self.send_response(200)
    self.end_headers()
    response = bytes("ola", "utf-8")
    signature = rsa.sign(response, private_key, 'SHA-256')
    self.wfile.write(signature)

def get_public_key(self):
    self.send_response(200)
    self.send_header("Content-type", "text/xml")
    self.end_headers()
    global public_key
    pbk = public_key.save_pkcs1('PEM')
    self.wfile.write(pbk)

def restore(self):
    filename = self.headers['File']
    self.send_response(200)
    self.send_header("Content-type", "text/xml")
    self.end_headers()
    file = open("backup/" + filename, "rb")
    content = file.read()
    self.wfile.write(content)



def handshake(self):
    content_length = int(self.headers['Content-Length'])
    body = self.rfile.read(content_length)
    message = rsa.decrypt(body, private_key).decode('utf-8')
    numbers = message.split(" + ")
    a = int(numbers[0])
    b = int(numbers[1])
    response = a + b

    self.send_response(200)
    self.end_headers()
    response = bytes(str(response), "utf-8")
    signature = rsa.sign(response, private_key, 'SHA-256')
    self.wfile.write(signature)

def load_keys():
    keys.load_keys()
    global public_key, private_key
    public_key = keys.public_key
    private_key = keys.private_key


def main():
    load_keys()
    try:
        httpd = HTTPServer(('localhost', 8000), SimpleHTTPRequestHandler)
        httpd.socket = ssl.wrap_socket (httpd.socket, keyfile="./key.pem", certfile='./cert.pem', server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.socket.close()


if __name__ == '__main__':
    main()
