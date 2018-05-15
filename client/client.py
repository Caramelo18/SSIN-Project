import ssl
import socket
import sys
import rsa
sys.path.append('../')
import keys


public_key = None
private_key = None


def load_keys():
    keys.load_keys()
    global public_key, private_key
    public_key = keys.public_key
    private_key = keys.private_key


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
    #test()
    connect()


if __name__ == '__main__':
    main()
