import ssl
import sys
sys.path.append('../')
import keys
import rsa
import socket
import os
import base64
from random import randint

def load_keys():
    keys.load_keys()
    global public_key, private_key
    public_key = keys.public_key
    private_key = keys.private_key

def open_socket(address):
    s = socket.socket()
    s.bind(address)
    s.listen(5)
    return s

def receive(s):
    c, addr = s.accept()
    encryptedName = get_filename(c)
    print (encryptedName)
    File = open(encryptedName, "w")

    while True:
        fileChunk =c.recv(4096)
        if not fileChunk:
            break
#        print (fileChunk)
        content = fileChunk.decode()
        File.write(content)

    File.close()
    c.close()

def get_filename(c):
    name = ""
    while True:
        byte = c.recv(1)
        if byte == b'\n':
            break
        name += byte.decode('utf-8')
    return name

def close(socket):
    socket.close()

def main():
    load_keys()
    if (len(sys.argv) > 1):
        s = open_socket(sys.argv[1])
    else:
        s = open_socket(("127.0.0.1",3002))
    receive(s)
    close(s)


if __name__ == '__main__':
    main()

