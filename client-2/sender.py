import ssl
import socket
import sys
import rsa
sys.path.append('../')
import keys
import getopt
import random
import string
import math
import os
from random import randint
from pathlib import Path

public_key = None
private_key = None

def load_keys():
    keys.load_keys()
    global public_key, private_key
    public_key = keys.public_key
    private_key = keys.private_key

def get_public_key(s):
    response =bytes()
    while True:
        buffer = s.recv(4096)
        if buffer:
            response += buffer
        if len(buffer) < 4096:
            break
    global public_key
    public_key = rsa.PublicKey.load_pkcs1(response, 'PEM')


def send_public_key(s):
    s.send(public_key.save_pkcs1('PEM'))


def generate_handshake():
    a = randint(0, 1000)
    b = randint(0, 1000)
    handshake = '{} + {}'.format(a, b)
    result = a + b
    return (result, handshake)

def handshake(s):
    (result, handshake) = generate_handshake()
    result = str(result)
    result = result.encode('utf-8')

    handshake = rsa.encrypt(bytes(handshake, 'utf-8'), public_key)
    s.send(handshake)

    i = 0
    buffer = s.recv(256)
    if buffer:
        server_answer = rsa.verify(result, buffer, public_key)
    else:
        s.close()
        sys.exit(1)

    if server_answer:
        print("Handshake complete")
    else:
        sys.exit(1)


def respond_handshake(s):
    message = s.recv(256)
    msgDecrypted = rsa.decrypt(message, private_key)
    msgDecoded = msgDecrypted.decode()
    numbers = msgDecoded.split(" + ")
    a = int(numbers[0])
    b = int(numbers[1])
    response = a + b

    response = bytes(str(response), "utf-8")
    signature = rsa.sign(response, private_key, 'SHA-256')
    s.send(signature)



def create_socket(address):
    s = socket.socket()
    s.bind(address)
    s.listen(1)
    return s


def open_socket(address):
    s = socket.socket()
    s.connect(address)
    return s

def send(s, filename):
    print("Sending file {}...".format(filename))
    global public_key
    encryptedName = rsa.encrypt(filename.encode(), public_key)
    s.send(encryptedName)
    s.send(b'\r\n')
    File = open(filename, "rb")
    while True:
        content = File.read(245)
        c = bytes(content)
        encrypted = rsa.encrypt(c, public_key)
        s.send(encrypted)
        if(len(content) < 245):
            break

    File.close()
    print("File {} sent".format(filename))

def receive(s):
    print("waiting to receive file...")

    c, addr = s.accept()
    send_public_key(c)
    respond_handshake(c)
    f = get_name(c)
    filename = f.decode('utf-8')

    print("receiving file {}...".format(filename))

    directory = "received"

    if not os.path.exists(directory):
        os.makedirs(directory)

    dir = "{}/{}".format(directory, filename)

    File = open(dir, "wb")

    while True:
        fileChunk = c.recv(256)
        if not fileChunk:
            break
        content = rsa.decrypt(fileChunk, private_key)
        File.write(content)

    File.close()
    c.close()
    print("file {} received".format(filename))

def get_name(c):
    name = b""
    while True:
        byte = c.recv(1)
        if byte == b'\r':
            nextByte = c.recv(1)
            if(nextByte == b'\n'):
                break
            else:
                name += byte + nextByte
        else:
            name += byte
    decryptedName = rsa.decrypt(name, private_key)
    return decryptedName

def close(socket):
    socket.close()

def print_usage():
    print("Usage:")
    print(sys.argv[0] + " -s filepath")
    print(sys.argv[0] + " -r")

def main():
    if(len(sys.argv) < 2 or len(sys.argv) > 3):
        print_usage()
        sys.exit(1)

    if(sys.argv[1] == "-r"):
        load_keys()
        s = create_socket(("127.0.0.1", 3000))
        receive(s)
    elif(sys.argv[1] == "-s"):
        s = open_socket(("127.0.0.1",3000))
        get_public_key(s)
        handshake(s)
        send(s, sys.argv[2])
    else :
        print_usage()
        exit(2)
    close(s)

if __name__ == '__main__':
    main()
