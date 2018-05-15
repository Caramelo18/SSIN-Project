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


def connect():
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

    handshake = generate_handshake()

    b = bytes('POST /handshake HTTP/1.1\r\nHost: localhost:8000\r\nContent-Type: application/json\r\nContent-Length: 47\r\n\r\n{"capabilities": {}, "desiredCapabilities": {}}', 'utf-8')
    s.sendall(b)

    while True:
        buffer = s.recv(4096)
        if buffer:
            print(buffer)
        else:
            s.close()
            break



def generate_handshake():
    a = randint(0, 1000)
    b = randint(0, 1000)
    handshake = '{} + {}'.format(a, b)
    return handshake

def test():
    string = "Ola".encode('utf-8')
    global private_key, public_key
    crypto = rsa.encrypt(string, public_key)
    print(string)
    print(crypto)
    message = rsa.decrypt(crypto, private_key)
    print(message)


def main():
    load_keys()
    #test()
    connect()


if __name__ == '__main__':
    main()
