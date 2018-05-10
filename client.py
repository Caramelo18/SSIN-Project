from OpenSSL import crypto
from pathlib import Path

public_key = None
private_key = None

def create_keys():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    global public_key
    public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, key)
    global private_key
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    public_file = open("public.key", "w+")
    public_file.write(public_key.decode("utf-8"))

    private_file = open("private.key", "w+")
    private_file.write(private_key.decode("utf-8"))

    return key

def load_keys():
    public_file = Path("public.key")
    private_file = Path("private.key")

    global public_key, private_key

    if public_file.exists() is False or private_file.exists() is False:
        create_keys()
    else:
        public_file = open("public.key", "r").read()
        private_file = open("private.key", "r").read()
        public_key = crypto.load_publickey(crypto.FILETYPE_PEM, public_file)
        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_file)
        # print(crypto.dump_publickey(crypto.FILETYPE_PEM, public_key))
        # print(crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key))


def main():
    load_keys()

if __name__ == '__main__':
    main()
