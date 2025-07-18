# -*- coding: utf-8 -*-

"""
Module implementing common.
"""

from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA224, SHA256, SHA384, SHA512
from Crypto.Cipher import PKCS1_OAEP
# from Crypto.Cipher import PKCS1_v1_5
# from Crypto.Random import get_random_bytes
from Crypto.Util.asn1 import DerSequence
import sys

class Msign:
    """
    Class documentation goes here.
    """

    @classmethod
    def rsa_key_gen(cls):
        # random_generator = Random.new().read
        rsa_key = RSA.generate(2048)
        # n (integer) – RSA modulus
        print('n:', rsa_key.n)
        # e (integer) – RSA public exponent
        print('e:', rsa_key.e)
        # d (integer) – RSA private exponent
        print('d:', rsa_key.d)
        # p (integer) – First factor of the RSA modulus
        print('p:', rsa_key.p)
        # q (integer) – Second factor of the RSA modulus
        print('q:', rsa_key.q)
        print('dp:', rsa_key.dp)
        print('dq:', rsa_key.dq)
        print('invp:', rsa_key.invp)
        print('invq:', rsa_key.invq)
        # 生成私钥
        # print(rsa_key.export_key(format='DER'))
        private_key = rsa_key
        print(private_key.export_key().decode('utf-8'))
        # 生成公钥
        public_key = rsa_key.publickey()
        print(public_key.export_key().decode('utf-8'))
        return public_key, private_key

    @classmethod
    def rsa_public_key_encrypt(cls, publicKey, message):
        print('{}[{}]>>>>>>>'.format(sys._getframe().f_code.co_name, sys._getframe().f_lineno))
        cipher = PKCS1_OAEP.new(publicKey)
        # cipher = PKCS1_v1_5.new(publicKey)
        cryptiontext = cipher.encrypt(message)
        print(cryptiontext.hex())
        return cryptiontext

    @classmethod
    def rsa_private_key_decrypt(cls, privateKey, message):
        print('{}[{}]>>>>>>>'.format(sys._getframe().f_code.co_name, sys._getframe().f_lineno))
        cipher = PKCS1_OAEP.new(privateKey)
        cryptiontext = cipher.decrypt(message)
        # cipher = PKCS1_v1_5.new(privateKey)
        # sentinel = get_random_bytes(16)
        # cryptiontext = cipher.decrypt(message, sentinel)
        print(cryptiontext.hex())
        return cryptiontext

    @classmethod
    def rsa_public_components_encrypt(cls, n, e, message):
        print('{}[{}]>>>>>>>'.format(sys._getframe().f_code.co_name, sys._getframe().f_lineno))
        publicKey = RSA.construct((n, e))
        print('n:', hex(publicKey.n))
        print('e:', hex(publicKey.e))
        cipher = PKCS1_OAEP.new(publicKey)
        cryptiontext = cipher.encrypt(message)
        print(cryptiontext.hex())
        return cryptiontext

    @classmethod
    def rsa_private_components_decrypt(cls, n, e, d, message):
        print('{}[{}]>>>>>>>'.format(sys._getframe().f_code.co_name, sys._getframe().f_lineno))
        privateKey = RSA.construct((n, e, d))
        print('n:', hex(privateKey.n))
        print('e:', hex(privateKey.e))
        print('d:', hex(privateKey.d))
        cipher = PKCS1_OAEP.new(privateKey)
        cryptiontext = cipher.decrypt(message)
        # cipher = PKCS1_v1_5.new(privateKey)
        # sentinel = get_random_bytes(16)
        # cryptiontext = cipher.decrypt(message, sentinel)
        print(cryptiontext.hex())
        return cryptiontext

    @classmethod
    def rsa_test_case(cls):
        public_key, private_key = Msign.rsa_key_gen()
        message = b'\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x31\x32\x33\x34\x35\x36'

        ciphertext = Msign.rsa_public_key_encrypt(public_key, message)
        plaintext = Msign.rsa_private_key_decrypt(private_key, ciphertext)
        if message == plaintext:
            print('RSA test ok!')
        else:
            print('RSA test failed!')

        n = b'\xDA\x07\x50\x17\xDB\x2E\xE5\xEF\xCD\x3D\x86\xE2\x1D\x42\x9D\xC4\xB3\x5D\xD4\xB8\xC7\x31\xEA\xEC\x83\x01\xBF\xCD\xF4\xBB\x76\xFB\x89\xF0\xFA\x48\x5A\x23\xAB\xB6\xE3\x9F\xBB\x4A\x92\x87\x6C\x5E\xA1\x93\x0A\x56\x6D\x51\xC4\x13\x4C\x26\x34\x9C\xEE\x7A\x68\x10\x93\xED\x69\xD4\x4E\x64\xF8\xBC\x3C\x83\xE9\x87\x28\xEE\x36\x10\x09\x87\x87\xBD\x3C\x53\xDA\xE1\x73\xC6\xCF\xCC\x6F\x52\xFE\x30\x77\x62\xCA\x71\xAD\x80\x5E\x79\xDD\x06\xB7\xDD\x2F\x5B\x91\xD9\x9C\x04\x7C\x07\xE4\x8D\x00\xAA\x4A\xF9\xCC\x78\x20\x7D\xF7\x1D\x7A\xB3\x56\xF8\x5C\xD1\x83\x81\x23\x03\xE9\x4F\x2C\xAD\xFE\x47\x24\x52\x53\x8B\x48\xCE\xF1\x8C\xE3\xF2\x94\xA0\xB7\x5E\x5B\x86\x84\xD6\xCD\x83\x02\x38\xA1\x16\xFC\x56\x2D\xA4\x54\x1E\xFB\x5D\x37\x94\x7C\xFD\x2E\x77\x23\x74\x9E\x47\x1D\xAE\xA9\x01\x57\x63\x81\xC2\x9B\x00\x64\xD3\xBE\xB1\x40\x23\x2A\x47\x47\x49\xFB\xFD\x91\x57\x87\x81\x85\x92\x1E\x1D\x85\xF7\x3C\x1F\x71\x5D\x3A\xA8\x32\x8B\x2D\x78\x64\xE3\x33\x2A\xFB\x6C\x2C\xA0\xFA\xA0\x6F\xF3\x7B\xA4\x15\x95\x79\xC0\xBB\x2A\x4A\xFB\x0A\x6E\x39\x18\xC4\x11'
        e = b'\x00\x01\x00\x01'
        d = b'\xD3\xD1\x42\xF8\xCA\x52\x77\xC5\x4F\x8A\x34\xDE\xBC\x3A\x99\xF8\x1D\xA2\x4D\x25\xEF\x30\x09\xE2\x19\x2C\xBB\xE1\x25\xA0\x72\xE9\xD1\x8B\xB2\x3C\x54\x86\x4F\x2E\xF1\x59\x9F\xA5\xC5\x51\x97\xF1\x1F\xDC\x30\xB0\xE2\xA8\x0B\x6C\x0C\x11\x1A\x10\x54\x87\xCB\x4E\x3F\xC8\xE9\x85\xFF\x5B\x8D\x63\xA3\x0F\x2C\xF3\xC8\xCA\x14\xEF\xE3\xB2\x2E\x27\xA4\xD2\x7A\xD5\x89\x9B\x5F\x0A\x68\x25\x23\x1A\x87\x02\x0D\x57\xFF\x8D\xB5\x3B\x83\x86\x21\x5E\xDB\xC1\x84\xA2\xFB\x36\x48\x21\x8A\xE3\x89\xFF\xE7\xB3\x63\xF8\x58\xE8\xC8\x07\xA9\x75\x5F\x83\x5E\x54\x1D\x65\x5A\xB4\xEC\xC0\x51\x6C\x85\xAC\xD0\x2E\xF1\x8F\x84\x18\xAE\xAB\x5A\x03\xBC\x6B\x80\x85\x22\x26\xD8\xE5\xEA\xA2\x63\x53\x1C\x03\xD8\x35\x0D\x63\x6E\x73\xF7\x18\x21\x39\x2E\xB7\x5F\x74\x62\x7D\xAF\x1F\x98\x28\x75\x21\x5E\x07\xF0\x94\x5D\x02\x85\xF9\x8B\x3F\xA6\xEE\x42\x55\x1E\x49\xE0\x40\xFB\x22\x27\xE0\x61\xBD\xD9\xD4\xAF\x31\x97\xCA\x45\x13\x1A\xD7\x25\xE8\xCD\x12\x4E\x65\x80\xEC\x2A\x7C\x5C\xD9\x6A\xDA\x9B\x64\x67\x07\x60\x85\xCE\xB5\xB9\x4E\x9B\xB0\x09\xAC\xF5\xB7\x56\x19'
        message = b'\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x31\x32\x33\x34\x35\x36'

        ciphertext = Msign.rsa_public_components_encrypt(int.from_bytes(n, 'big'), int.from_bytes(e, 'big'),
                                               message)
        plaintext = Msign.rsa_private_components_decrypt(int.from_bytes(n, 'big'), int.from_bytes(e, 'big'),
                                               int.from_bytes(d, 'big'), ciphertext)
        
        if message == plaintext:
            print('RSA test ok!')
        else:
            print('RSA test failed!')

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
        # mode 签名模式
        # encoding 签名编码格式
        # - 'binary' 默认格式，原始的 `r` 和 `s` 组合
        # - 'der', DER 序列格式，带有 DER 标签
        # 跳转 new 查看详细参数定义
        signer = DSS.new(private_key, mode='fips-186-3')
        signature = signer.sign(h)
        print('signature:', signature.hex())
        # 签名数据为原始格式时，平分即得 r/s
        r = signature[0:len(signature)//2].hex()
        s = signature[len(signature)//2:].hex()
        # 签名数据为 DER 格式时，可按如下方式提取 r/s
        # der = DerSequence()
        # der.decode(signature)
        # r = '{:>X}'.format(der[0])
        # s = '{:>X}'.format(der[1])
        print('r:', r)
        print('s:', s)
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
        verifier = DSS.new(public_key, mode='fips-186-3')
        try:
            verifier.verify(h, signature)
            print("Signature verified ok.")
            return True
        except ValueError:
            print("Signature verified failed.")
            return False

    @classmethod
    def ecc_point_add(cls, qA, qB, curve_bits):
        bytesize = (curve_bits+7)//8
        qAB = qA + qB
        print('QAB-x:', qAB.x.to_bytes(bytesize).hex())
        print('QAB-y:', qAB.y.to_bytes(bytesize).hex())
        return qAB

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
        print('------Key Generate Test------')
        curve_bits = 256
        hash_bits = 256
        private_key, public_key = Msign.ecc_key_gen(curve_bits)
        if private_key:
            message = b"Hello, PyCryptodome!"
            signature = Msign.ecc_sign(private_key, message, hash_bits)
            Msign.ecc_verify(public_key, signature, message, hash_bits)

        # 指定公私钥签名/验签测试
        print('------Public/Private Key Sign Test------')
        hash_bits = 512
        curve_bits = 521
        curve_type = 'secp{}r1'.format(curve_bits)
        # 生成公钥
        xA = '008BA2AAD80E0552D5EF938FE6CF0708DCE42D2214F890542B8BC19D4D7FF7E6651AC6A7C462A95885F74774990A261C2B1E08F23258BB79B16E23BAA663B1ACDF26'
        yA = '002408D8253490F8B73DD276E1D442B5EB844C687FCC5273A212DF297FF11DC24769F36ADDE9E65D4CFD040A7292C16A7797871BC4DE1C668A74224BD9F2702524C6'
        public_key = ECC.construct(curve=curve_type, point_x=int(xA, base=16), point_y=int(yA, base=16))
        # 生成私钥
        dA = '008E2FF8857E11A28B7D5087912F11672216FC11FCD2238E6789C535EED3BCBD62CD21FA4F0FFFF15906D5781695DC8EC263CCAC721CC8BAFD8E4C9BE205C7694CDB'
        private_key = ECC.construct(curve=curve_type, d=int(dA, base=16))
        # 签名/验签
        message = b"Hello, PyCryptodome!"
        signature = Msign.ecc_sign(private_key, message, hash_bits)
        Msign.ecc_verify(public_key, signature, message, hash_bits)

        # 点加/点乘测试
        print('------Point Add/Multiply Test------')
        curve_bits = 521
        curve_type = 'secp{}r1'.format(curve_bits)
        # 生成公钥点
        xA = '007AC5E93871939B08AE562D4E9AC87377B63753054E44964902D8A3A69D3B8B7D2A7E0159D2EED63A807101BCE7C20211C27216172C79056AC99F448DD9A28FF078'
        yA = '01366F31D50F56E984ECF10351C107138352703F7F0FD5D3A6D789A09B6C100D8B2888CDF84DF4F527A6BB9FD18B8A58563244EB51E2216018A6FE9DA7976E546048'
        qA = ECC.EccPoint(int(xA, base=16), int(yA, base=16), curve=curve_type)
        # 私钥
        dA = '01961E7A263EA9CF4AEEFADF2E5667DF4990A2BD67FF47123DAD2F249C6B86DAFDF16C0118CED25588400F81DFA18D04B8509B0556F58A29B3B518EFEC3FEF32D19A'
        dA = int(dA, base=16)
        # 生成公钥点
        xB = '01E5BBC40344412CD30A77B8B4378718572E5DDCCFE729CBB1CC03C6B911E965DC066EAA49D6BBF46711283F47752A522E8C458E4EDC062FC3C838BC7942971466FA'
        yB = '0018B9B39485F5CC37785D2AC5D3CEC006CA0B9C03E75AEF89976660D72F2CA9157A1370A7A76B7D89D8CB48F2B747E5753A50BDAB0BA809C0BA4F4C2652DF75A777'
        qB = ECC.EccPoint(int(xB, base=16), int(yB, base=16), curve=curve_type)
        # 私钥
        dB = '011040A2EBF7FEA771F35948D7CC47C8174AA2E436150A58F0602332A32EFC14038B3CC384C613A7EE8C578E75FFD37A024E5D08089C3570049FB89A2C0A7332492F'
        dB = int(dB, base=16)
        # 点加
        Msign.ecc_point_add(qA, qB, curve_bits)
        # 点乘
        Msign.ecc_point_multiply(dA, qB, curve_bits)
        Msign.ecc_point_multiply(dB, qA, curve_bits)

if __name__ == '__main__':
    # print(sys.argv)
    Msign.ecc_test_case()
