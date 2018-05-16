import ssl
import socket
import sys
import rsa
sys.path.append('../')
import keys
from random import randint

public_key = None
private_key = None
server_public_key = None


def load_keys():
    keys.load_keys()
    global public_key, private_key
    public_key = keys.public_key
    private_key = keys.private_key

def generate_handshake():
    a = randint(0, 1000)
    b = randint(0, 1000)
    handshake = '{} + {}'.format(a, b)
    result = a + b
    return (result, handshake)


def get_public_key():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 8000))
    s = ssl.wrap_socket (s, ssl_version=ssl.PROTOCOL_TLSv1)
    b = bytes("GET /public_key HTTP/1.1\r\nHost: localhost:8000\r\n\r\n", 'utf-8')
    s.sendall(b)

    response = bytes()
    while True:
        buffer = s.recv(4096)
        if buffer:
            response += buffer
        else:
            s.close()
            break

    global server_public_key
    server_public_key = rsa.PublicKey.load_pkcs1(response, 'PEM')

def send_file():
    print("preparing to send file")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 8000))
    s = ssl.wrap_socket (s, ssl_version=ssl.PROTOCOL_TLSv1)

    content = read_file()
    chunk_length = 245

    post_request = 'POST /upload HTTP/1.1\r\nHost: localhost:8000\r\nContent-Type: multipart/form-data; boundary=---------------------------735323031399963166993862150\r\nContent-Length: {}\r\n'.format(chunk_length)
    post_request += "---------------------------735323031399963166993862150\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n" + content + "\r\n"

    b = bytes(post_request, 'utf-8')

    s.sendall(b)
    i = 0
    while True:
        buffer = s.recv(4096)
        if buffer:
            i = i+1
        else:
            s.close()
            break

def handshake():
    (result, handshake) = generate_handshake()
    result = str(result)
    result = result.encode('utf-8')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 8000))
    s = ssl.wrap_socket (s, ssl_version=ssl.PROTOCOL_TLSv1)

    handshake = rsa.encrypt(bytes(handshake, 'utf-8'), server_public_key)
    handshake_length = 256

    post_request = 'POST /handshake HTTP/1.1\r\nHost: localhost:8000\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n'.format(handshake_length)
    b = bytes(post_request, 'utf-8')
    b += handshake

    s.sendall(b)

    i = 0
    while True:
        buffer = s.recv(4096)
        if buffer:
            if i is 1:
                server_answer = rsa.verify(result, buffer, server_public_key)
            i = i + 1
        else:
            s.close()
            break

    if server_answer:
        print("Handshake complete")


def connect():
    get_public_key()
    handshake()

def read_file():
    if len(sys.argv) > 1:
        fileName = sys.argv[1]
        F = open(fileName, "r")
        return F.read(245)
#        print (F.read(245))

def test():
    string = "Ola".encode('utf-8')
    global private_key, public_key
    crypto = rsa.encrypt(string, private_key)
    print(string)
    print(crypto)
    message = rsa.decrypt(crypto, public_key)
    print(message)


def test_sign():
    string = "Ola".encode('utf-8')
    global private_key, public_key
    sign = rsa.sign(string, private_key, 'SHA-256')
    print(string)
    print(sign)
    message = rsa.verify(string, sign, public_key)
    print(message)


def main():
    load_keys()
    connect()
    send_file()
    #test()
    #test_sign()


if __name__ == '__main__':
    main()
