import rsa
from pathlib import Path
import client


def create_keys():
    global public_key, private_key
    (public_key, private_key) = rsa.newkeys(2048, poolsize = 4)

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
