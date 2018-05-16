import ssl
import socket
import sys
import rsa
sys.path.append('../')
import keys
import requests

public_key = None
private_key = None


def load_keys():
    keys.load_keys()
    global public_key, private_key
    public_key = keys.public_key
    private_key = keys.private_key


def connect():
    content = readFile()
    req = "POST / HTTP/1.1\r\nHost: localhost:8000\r\nConnection: close\r\nContent-Type: multipart/form-data; boundary=---------------------------735323031399963166993862150\r\nContent-Length: 245\r\n---------------------------735323031399963166993862150\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n" + content + "\r\n---------------------------735323031399963166993862150--"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 8000))
    s = ssl.wrap_socket (s, ssl_version=ssl.PROTOCOL_TLSv1)
    b = bytes(req, 'utf-8')
    s.sendall(b)
    print(req)

    while True:
        new = s.recv(4096)
        if not new:
            s.close()
            break
        print(new)

def readFile():
    if len(sys.argv) > 1:
        fileName = sys.argv[1]
        F = open(fileName, "r")
        return F.read(245)
#        print (F.read(245))

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
    #readFile()
    connect()


if __name__ == '__main__':
    main()
