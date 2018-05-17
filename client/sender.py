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
server_public_key = None

def load_keys():
    keys.load_keys()
    global public_key, private_key
    public_key = keys.public_key
    private_key = keys.private_key

def open_socket(address):
    s = socket.socket()
    s.connect(address)
    return s

def send(s, filename):
    s.send(filename.encode())
    s.send(b'\n')
    File = open(filename, "rb")
    while True:
        content = File.read(245)
        #encrypted = rsa.encrypt(content, public_key)
        #s.send(encrypted)
        s.send(content)
        if(len(content) < 245):
            break

    File.close()

def close(socket):
    socket.close()


def main():
    load_keys()
    s = open_socket(("127.0.0.1",3002))
    send(s, sys.argv[1])
    close(s)

if __name__ == '__main__':
    main()

