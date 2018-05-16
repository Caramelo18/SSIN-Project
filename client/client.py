import ssl
import socket
import sys
import rsa
sys.path.append('../')
import keys
import getopt
import random
import string
from pathlib import Path


public_key = None
private_key = None
server_public_key = None
files = {}


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
    #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #s.connect(('localhost', 8000))
    #s = ssl.wrap_socket (s, ssl_version=ssl.PROTOCOL_TLSv1)
    File = None
    filename = None
    if(len(sys.argv) > 1):
        filename = sys.argv[1]
        File = open(filename, "r")

    part = 0

    while(True):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('localhost', 8000))
        s = ssl.wrap_socket (s, ssl_version=ssl.PROTOCOL_TLSv1)
        content = read_file(File)
        encryptedContent = rsa.encrypt(bytes(content, 'utf-8'), server_public_key)

        chunk_length = len(encryptedContent)
        post_request = 'POST /upload HTTP/1.1\r\nHost: localhost:8000\r\nContent-Type: multipart/form-data; boundary=---------------------------735323031399963166993862150\r\nChunk: {}-{}\r\nContent-Length: {}\r\n'.format(filename, part, chunk_length)
        post_request += "---------------------------735323031399963166993862150\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n"

        b = bytes(post_request, 'utf-8')
        b += encryptedContent

        s.sendall(b)
        i = 0
        while True:
            buffer = s.recv(4096)
            if buffer:
                s.close()
                break
            else:
                s.close()
                break
        part = part + 1
        # print(len(str(encryptedContent)))
        if(len(content) < 245):
            break

    File.close()

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

def read_file(File):
    return File.read(245)

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


def backup(file):
    f = Path(file)
    if not f.exists():
        print('File', file, 'does not exist')
        sys.exit(4)
    elif file in files:
        print('File already exists')
        sys.exit(5)

    f = open("filesb", "a")
    id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    line = '{} - {} - {}\n'.format(file, id, 3)
    f.write(line)


def restore(file):
    if file not in files:
        print('File is not backed up')
        sys.exit(3)
    (fileid, chunks) = files[file]
    print('restore', file, fileid, chunks)


def load_files():
    f = Path("filesb")

    if f.exists():
        f = open("filesb", "r")
    else:
        f = open("filesb", "w")

    lines = f.read().splitlines()

    for line in lines:
        split = line.split(" - ")
        filename = split[0]
        fileid = split[1]
        filechunks = split[2]
        files[filename] = (fileid, filechunks)


def main(argv):
    load_keys()
    load_files()

    if len(argv) is not 2:
        print("usage")
        sys.exit(2)

    option = argv[0]
    file = argv[1]

    if option == '-b':
        backup(file)
    elif option == '-r':
        restore(file)


    #connect()
    #send_file()
    #test()
    #test_sign()


if __name__ == '__main__':
    main(sys.argv[1:])
