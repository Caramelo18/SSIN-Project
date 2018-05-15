from OpenSSL import crypto
from pathlib import Path
import ssl
import socket
import rsa


public_key = None
private_key = None


def create_keys():
    global public_key, private_key
    (public_key, private_key) = rsa.newkeys(2048, poolsize = 8)

    pbk = public_key.save_pkcs1('PEM')
    pvk = private_key.save_pkcs1('PEM')

    public_file = open("public.key", "wb")
    public_file.write(pbk)

    private_file = open("private.key", "wb")
    private_file.write(pvk)


def load_keys():
    public_file = Path("public.key")
    private_file = Path("private.key")

    global public_key, private_key

    if public_file.exists() is False or private_file.exists() is False:
        create_keys()
    else:
        with open('public.key', mode='rb') as public_file:
            keydata = public_file.read()
            public_key = rsa.PublicKey.load_pkcs1(keydata, 'PEM')

        with open('private.key', mode='rb') as private_file:
            keydata = private_file.read()
            private_key = rsa.PrivateKey.load_pkcs1(keydata, 'PEM')


def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 8000))
    s = ssl.wrap_socket (s, ssl_version=ssl.PROTOCOL_TLSv1)
    b = bytes("GET / HTTP/1.1\r\nHost: localhost:8000\r\nConnection: close\r\n\r\n", 'utf-8')
    s.sendall(b)

    while True:
        new = s.recv(4096)
        if not new:
            s.close()
            break
        print(new)


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
    test()
    connect()
    

if __name__ == '__main__':
    main()
