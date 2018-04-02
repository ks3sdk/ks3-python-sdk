import io
import os
from ks3.encrypt import Crypts

SEEK_SET = getattr(io, 'SEEK_SET', 0)
SEEK_CUR = getattr(io, 'SEEK_CUR', 1)
SEEK_END = getattr(io, 'SEEK_END', 2)

class EncryptFp (io.FileIO):
    """
    A class will return you a fp inside which data are encrypted.
    """
    def __init__(self, fp, iv, key, type, isUploadFirstPart=False, isUploadLastPart=False):
        self.fp = fp
        self.first_iv = iv
        self.calc_iv = ""
        self.crypt_handler = Crypts(key)
        self.type = type
        self.block_size = 16
        self.isUploadFirstPart = isUploadFirstPart
        self.isUploadLastPart = isUploadLastPart

    def read(self, n):
        data = super(EncryptFp, self).read(n)
        if self.type == "put":              
            if not self.calc_iv:
                encrypt_data = crypt_handler.encrypt(data,self.first_iv)
                self.calc_iv = encrypt_data[-self.block_size:]
                encrypt_data = self.first_iv+encrypt_data
            else:
                encrypt_data = crypt_handler.encrypt(data,self.calc_iv)
                self.calc_iv = encrypt_data[-self.block_size:]
        if self.type == "upload_part":
            if self.isUploadFirstPart:
            #For multi, the first part's first part will add a prefix of iv.
                if not self.calc_iv:
                    encrypt_data = crypt_handler.encrypt_part(data,self.first_iv)
                    encrypt_data = self.first_iv+encrypt_data
                else:
                    encrypt_data = crypt_handler.encrypt(data,self.calc_iv)
            elif not isUploadLastPart:
                if not self.calc_iv:
                    encrypt_data = crypt_handler.encrypt_part(data,self.first_iv)
                else:
                    encrypt_data = crypt_handler.encrypt_part(data,self.calc_iv)
            else:
            #And the last part's parts use 'encrypt' instead of 'encrypt_part' because the last part's last part need paddling.
                if not self.calc_iv:
                    encrypt_data = crypt_handler.encrypt_part(data,self.first_iv)
                else:
                    encrypt_data = crypt_handler.encrypt(data,self.calc_iv)
            self.calc_iv = encrypt_data[-self.block_size:]
        return encrypt_data
