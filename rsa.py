# -*- coding: utf-8 -*-
import Crypto.Cipher as Cipher
import Crypto.Signature as Sign
import Crypto.Hash as Hash
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_cipper
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_sign
from Crypto.Hash import SHA1


class Rsa:
    """RSA encryption & decryption signature
        """
    
    def __int__(self, ciper_lib=PKCS1_v1_5_cipper, sign_lib=PKCS1_v1_5_sign, hash_lib=SHA1,
                pub_file=None, pri_file=None, pub_skey=None, pri_skey=None, pub_key=None, pri_key=None,
                reversed_size=11):
        
        # encrypt and decrypt lib
        self.ciper_lib = ciper_lib
        self.sign_lib = sign_lib
        self.hash_lib = hash_lib
        
        # public key and private key
        if pub_key:
            self.pub_key = pub_key
        elif pub_skey:
            self.pub_key = RSA.importKey(pub_skey)
        elif pub_file:
            self.pub_key = RSA.importKey(open(pub_file).read())
        
        if pri_key:
            self.pri_key = pri_key
        elif pri_skey:
            self.pri_key = RSA.importKey(pri_skey)
        elif pri_file:
            self.pri_key = RSA.importKey(open(pri_file).read())
        
        # block and reserve size
        self.block_reversed_size = reversed_size
    
    # calculate the block size based on key length
    def get_block_size(self, rsa_key):
        try:
            # RSA only work for limited-size operation
            reserve_size = self.block_reversed_size
            key_size = rsa_key.size_in_bits()
            if (key_size % 8) != 0:
                raise RuntimeError('RSA 密钥长度非法')
            
            # private key to decrypt
            if rsa_key.has_private():
                reserve_size = 0
            
            bs = int(key_size / 8) - reserve_size
        except Exception as err:
            print('计算加解密数据块大小出错', rsa_key, err)
        return bs
    
    def block_data(self, data, rsa_key):
        bs = self.get_block_size(rsa_key)
        for i in range(0, len(data), bs):
            yield data[i:i + bs]

# encrypt
def enc_bytes(self, data, key=None):
    text = b''
    try:
        rsa_key = self.pub_key
        if key:
            rsa_key = key
        
        cipher = self.ciper_lib.new(rsa_key)
        for dat in self.block_data(data, rsa_key):
            cur_text = cipher.encrypt(dat)
            text += cur_text
    except Exception as err:
        print('RSA加密失败', data, err)
    return text

# decrypt
def dec_bytes(self, data, key=None):
    text = b''
    try:
        rsa_key = self.pri_key
        if key:
            rsa_key = key
        
        cipher = self.ciper_lib.new(rsa_key)
        for dat in self.block_data(data, rsa_key):
            if type(self.ciper_lib) == Cipher.PKCS1_OAEP:
                cur_text = cipher.decrypt(dat)
            else:
                cur_text = cipher.decrypt(dat, '解密异常')
            text += cur_text
    except Exception as err:
        print('RSA解密失败', data, err)
    return text

# RSA signature
def sign_bytes(self, data, key=None):
    signature = ''
    try:
        rsa_key = self.pri_key
        if key:
            rsa_key = key
        
        h = self.hash_lib.new(data)
        signature = self.sign_lib.new(rsa_key).sign(h)
    except Exception as err:
        print('RSA签名失败', '', err)
    return signature

# RSA signature examine
def sign_verify(self, data, sig, key=None):
    try:
        rsa_key = self.pub_key
        if key:
            rsa_key = key
        h = self.hash_lib.new(data)
        self.sign_lib.new(rsa_key).verify(h, sig)
        ret = True
    except (ValueError, TypeError):
        ret = False
    return ret


def main():
    pass

if __name__ == '__main__':
    main()
