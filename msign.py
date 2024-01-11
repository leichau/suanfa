# -*- coding: utf-8 -*-

"""
Module implementing common.
"""
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

class Msign:
    """
    Class documentation goes here.
    """

    @classmethod
    def rsa_key_gen(cls):
        # random_generator = Random.new().read
        rsa = RSA.generate(2048)
        # n (integer) – RSA modulus
        print('n:', rsa.n)
        # e (integer) – RSA public exponent
        print('e:', rsa.e)
        # d (integer) – RSA private exponent
        print('d:', rsa.d)
        # p (integer) – First factor of the RSA modulus
        print('p:', rsa.p)
        # q (integer) – Second factor of the RSA modulus
        print('q:', rsa.q)
        # 生成私钥
        print(rsa.export_key(format='DER'))
        private_key = rsa.export_key()
        print(private_key.decode('utf-8'))
        # 生成公钥
        public_key = rsa.publickey().export_key()
        print(public_key.decode('utf-8'))

    @classmethod
    def ecc_key_gen(cls):
        key = ECC.generate(curve='secp256r1')
        private_key = key
        public_key = private_key.public_key()
        print('private_key:', private_key)
        print('public_key:', public_key)
        print('curve:', private_key.curve)
        print('point_x:', private_key.pointQ.x)
        print('point_y:', private_key.pointQ.y)
        print('d:', private_key.d)
        with open('myprikey.pem', 'w') as f:
            f.write(key.export_key(format='PEM'))
        with open('mypubkey.pem', 'w') as f:
            f.write(key.public_key().export_key(format='PEM'))

        # ECDSA 签名例程
        # Message to sign
        message = b"Hello, PyCryptodome!"
        print('message:', message)
        # Signing
        h = SHA256.new(message)
        print('SHA256:', h.hexdigest())
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(h)
        print('signature:', signature.hex())
        # Verification
        verifier = DSS.new(public_key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            print("Signature is valid.")
        except ValueError:
            print("Signature is invalid.")

if __name__ == '__main__':
    # print(sys.argv)
    Msign.ecc_key_gen()
