#!/usr/bin/env python
#! usr/bin/python #coding=utf-8
from Crypto.Cipher import AES
from Crypto import Random
import time

class Crypts(object):
    """
    This encryption class use AES.CBC MODE(128 bit) as default. 
    @param key: your private key. We don't save user's key, so keep it safe or your data will never be decrypted :(
    """
    def __init__(self, key):
        self.key = key
        self.first_iv = Random.new().read(AES.block_size)
        self.calc_iv = ""
        self.block_size = 16
        self.pad_num = 0
        self.part_num = 0
        self.iv_dict = {}
        self.pad_dict = self.init_pad_dict()
        self.calc_md5 = True
        self.action_info = ""
        self.is_last_part = False

    def init_pad_dict(self):
        temp_dict={}
        gap = ord('a')-10
        for i in range(1, 10):
            temp_dict[i] = str(i)
        for i in range(10, 17):
            temp_dict[i] = chr(gap+i)
        return temp_dict

    def set_calc_iv(self,calc_iv):
        self.calc_iv = calc_iv

    def encrypt_without_padding(self, content, iv):
        """
        For those part those size are definitly multiple of 16, use this function. If you need data padding, use the encrypt() func.
        """
        cryptor = AES.new(self.key,AES.MODE_CBC,iv)
        return cryptor.encrypt(content) 

    def encrypt(self, content, iv):
        cryptor = AES.new(self.key,AES.MODE_CBC,iv)
        pad_num = self.block_size-(len(content)%(self.block_size))
        pad_content_char = self.pad_dict[pad_num]
        pad = lambda s: s + ((AES.block_size - len(s) % AES.block_size) * pad_content_char).encode()
        self.pad_num = pad_num
        #identifier + content may still not a multiple of 16, add extra '0' after the first pad
        return cryptor.encrypt(pad(content))

    def decrypt(self, content, iv):
        cryptor = AES.new(self.key,AES.MODE_CBC,iv)
        full_content = cryptor.decrypt(content)
        return full_content

    @staticmethod
    def generate_key(path, file_name):
        sk = Random.new().read(16)
        f = open(path+"/"+file_name,"wb")
        f.write(sk)
        f.close()
    
if __name__ == '__main__':
    # cry = Crypts.generate_key('./', 'try_key')
    cry = Crypts("1234567890123456")
    str0 = ""
    # str0 = "16161616161616161616161616161616"
    # e0 = cry.encrypt(str0,cry.first_iv)
    # print "e0:"+cry.decrypt(e0,cry.first_iv)
    # str1 = "123456789012345"
    # str2 = "sdf1234565432121"
    # str_all="1234567890123456sdf1234565432123"
    # e1 = cry.encrypt(str1,cry.first_iv)
    # e2 = cry.encrypt(str2,e1)
    # e3 = cry.encrypt(str_all,cry.first_iv)
    #
    #
    # r1=cry.decrypt(e1,cry.first_iv)
    # print r1,len(r1)
    # print cry.decrypt(e2,e1)
    # print cry.decrypt(e3,cry.first_iv)
    
