# -*- coding: utf-8 -*-

"""
Module implementing common.
"""
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC

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
        with open('myprikey.pem', 'w') as f:
            f.write(key.export_key(format='PEM'))
        with open('mypubkey.pem', 'w') as f:
            f.write(key.public_key().export_key(format='PEM'))

if __name__ == '__main__':
    # print(sys.argv)
    Msign.rsa_key_gen()
