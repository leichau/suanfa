# -*- coding: utf-8 -*-

"""
Module implementing common.
"""
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA224, SHA256, SHA384, SHA512

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
    def ecc_key_gen(cls, curve_bits):
        if curve_bits == 224:
            curve_type ='secp224r1'
        elif curve_bits == 256:
            curve_type ='secp256r1'
        elif curve_bits == 384:
            curve_type ='secp384r1'
        elif curve_bits == 521:
            curve_type ='secp521r1'
        else:
            print("ecc_key_gen error: curve bits invalid!")
            return None, None
        key = ECC.generate(curve = curve_type)
        bytesize = (curve_bits+7)//8
        public_key = key.public_key()
        print('curve:', key.curve)
        print('public_key_x:', key.pointQ.x.to_bytes(bytesize).hex())
        print('public_key_y:', key.pointQ.y.to_bytes(bytesize).hex())
        print('private_key:', key.d.to_bytes(bytesize).hex())
        with open('myprikey.pem', 'w') as f:
            f.write(key.export_key(format='PEM'))
        with open('mypubkey.pem', 'w') as f:
            f.write(key.public_key().export_key(format='PEM'))
        return key, public_key

    @classmethod
    def ecc_sign(cls, private_key, message, hash_bits, hash_message = False):
        if hash_bits == 224:
            hash_digest = SHA224
        elif hash_bits == 256:
            hash_digest = SHA256
        elif hash_bits == 384:
            hash_digest = SHA384
        elif hash_bits == 512:
            hash_digest = SHA512
        else:
            print("ecc_sign error: hash bits invalid!")
            return None
        print('message:', message)
        if hash_message:
            h = message
        else:
            h = hash_digest.new(message)
        print('SHA{}: {}'.format(hash_bits, h.hexdigest()))
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(h)
        print('signature:', signature.hex())
        return signature

    @classmethod
    def ecc_verify(cls, public_key, signature, message, hash_bits, hash_message = False):
        if hash_bits == 224:
            hash_digest = SHA224
        elif hash_bits == 256:
            hash_digest = SHA256
        elif hash_bits == 384:
            hash_digest = SHA384
        elif hash_bits == 512:
            hash_digest = SHA512
        else:
            print("ecc_verify error: hash bits invalid!")
            return False
        if hash_message:
            h = message
        else:
            h = hash_digest.new(message)
        print('SHA{}: {}'.format(hash_bits, h.hexdigest()))
        verifier = DSS.new(public_key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            print("Signature verified ok.")
            return True
        except ValueError:
            print("Signature verified failed.")
            return False

    @classmethod
    def ecc_point_add(cls, QA, QB, curve_bits):
        bytesize = (curve_bits+7)//8
        QAB = QA + QB
        print('QAB-x:', QAB.x.to_bytes(bytesize).hex())
        print('QAB-y:', QAB.y.to_bytes(bytesize).hex())
        return QAB

    @classmethod
    def ecc_point_multiply(cls, d, Q, curve_bits):
        bytesize = (curve_bits+7)//8
        dQ = d * Q
        print('dQ-x:', dQ.x.to_bytes(bytesize).hex())
        print('dQ-y:', dQ.y.to_bytes(bytesize).hex())
        return dQ

    @classmethod
    def ecc_test_case(cls):
        # 签名/验签测试
        curve_bits = 256
        hash_bits = 256
        private_key, public_key = Msign.ecc_key_gen(curve_bits)
        if private_key:
            message = b"Hello, PyCryptodome!"
            signature = Msign.ecc_sign(private_key, message, hash_bits)
            Msign.ecc_verify(public_key, signature, message, hash_bits)
        # 点加/点乘测试
        curve_bits = 521
        curve_type = 'secp{}r1'.format(curve_bits)
        # 生成公钥点
        xA = '007AC5E93871939B08AE562D4E9AC87377B63753054E44964902D8A3A69D3B8B7D2A7E0159D2EED63A807101BCE7C20211C27216172C79056AC99F448DD9A28FF078'
        yA = '01366F31D50F56E984ECF10351C107138352703F7F0FD5D3A6D789A09B6C100D8B2888CDF84DF4F527A6BB9FD18B8A58563244EB51E2216018A6FE9DA7976E546048'
        QA = ECC.EccPoint(int(xA, base=16), int(yA, base=16), curve=curve_type)
        # 私钥
        dA = '01961E7A263EA9CF4AEEFADF2E5667DF4990A2BD67FF47123DAD2F249C6B86DAFDF16C0118CED25588400F81DFA18D04B8509B0556F58A29B3B518EFEC3FEF32D19A'
        dA = int(dA, base=16)
        # 生成公钥点
        xB = '01E5BBC40344412CD30A77B8B4378718572E5DDCCFE729CBB1CC03C6B911E965DC066EAA49D6BBF46711283F47752A522E8C458E4EDC062FC3C838BC7942971466FA'
        yB = '0018B9B39485F5CC37785D2AC5D3CEC006CA0B9C03E75AEF89976660D72F2CA9157A1370A7A76B7D89D8CB48F2B747E5753A50BDAB0BA809C0BA4F4C2652DF75A777'
        QB = ECC.EccPoint(int(xB, base=16), int(yB, base=16), curve=curve_type)
        # 私钥
        dB = '011040A2EBF7FEA771F35948D7CC47C8174AA2E436150A58F0602332A32EFC14038B3CC384C613A7EE8C578E75FFD37A024E5D08089C3570049FB89A2C0A7332492F'
        dB = int(dB, base=16)
        # 点加
        Msign.ecc_point_add(QA, QB, curve_bits)
        # 点乘
        Msign.ecc_point_multiply(dA, QB, curve_bits)
        Msign.ecc_point_multiply(dB, QA, curve_bits)

if __name__ == '__main__':
    # print(sys.argv)
    Msign.ecc_test_case()
