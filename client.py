from OpenSSL import crypto
from pathlib import Path
import rsa

public_key = None
private_key = None

def create_keys():
    #global public_key, private_key
    (public_key, private_key) = rsa.newkeys(2048, poolsize = 8)

    pbk = public_key.save_pkcs1('PEM').decode('ascii')
    pvk = private_key.save_pkcs1('PEM').decode('ascii')

    public_file = open("public.key", "w")
    public_file.write(pbk)

    private_file = open("private.key", "w")
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

if __name__ == '__main__':
    main()
