import io
import math
from ks3.encryption import Crypts

SEEK_SET = getattr(io, 'SEEK_SET', 0)
SEEK_CUR = getattr(io, 'SEEK_CUR', 1)
SEEK_END = getattr(io, 'SEEK_END', 2)

class EncryptFp (object):
    """
    A class will return you a fp inside which data are encrypted.
    """
    def __init__(self, fp, crypt_context, type,isUploadFirstPart=False, isUploadLastPart=False):
        self.fp = fp
        self.first_iv = crypt_context.first_iv
        self.calc_iv = ""
        self.crypt_context = crypt_context
        self.crypt_handler = Crypts(crypt_context.key)
        self.type = type
        self.block_size = 16
        self.isUploadFirstPart = isUploadFirstPart
        self.isUploadLastPart = isUploadLastPart
        self.seek_pos = SEEK_SET
        self.block_count = 0
        self.block_total_count = self.get_total_count(fp)

    def get_total_count(self, fp):
        fp.seek(0, SEEK_END)
        count = math.ceil(float(fp.tell())/8192)
        fp.seek(0, SEEK_SET)
        return count

    def __getattr__(self, name):
        func = getattr(self.__dict__['fp'], name)
        if callable(func):
            if name == "read":
                def my_wrapper(*args, **kwargs):
                    data = func(*args, **kwargs)
                    self.block_count += 1
                    if len(data) == 0:
                        return None
                    # print len(data)
                    if self.type == "put":              
                        if self.block_count == 1:
                            if self.block_total_count == 1:
                                encrypt_data = self.crypt_handler.encrypt(data,self.first_iv)
                            else:
                                encrypt_data = self.crypt_handler.encrypt_without_padding(data,self.first_iv)
                            self.calc_iv = encrypt_data[-self.block_size:]
                            self.crypt_context.calc_iv = self.calc_iv
                            encrypt_data = self.first_iv+encrypt_data
                        elif self.block_count == self.block_total_count:
                            encrypt_data = self.crypt_handler.encrypt(data,self.calc_iv)
                        else:
                            encrypt_data = self.crypt_handler.encrypt_without_padding(data, self.calc_iv)
                            self.calc_iv = encrypt_data[-self.block_size:]
                            self.crypt_context.calc_iv = self.calc_iv
                    elif self.type == "upload_part":
                        need_prefix = False
                        if self.isUploadFirstPart and self.block_count == 1:
                            pre_iv = self.first_iv
                            need_prefix = True
                        else:
                            last_part_num = self.crypt_context.part_num - 1
                            if last_part_num > 0 and self.block_count == 1:
                                if self.crypt_context.iv_dict.get(last_part_num):
                                    self.calc_iv = self.crypt_context.iv_dict.get(last_part_num)
                            else:
                                if not self.calc_iv:
                                    raise ValueError(
                                        "upload part[%d] encryption error:calc_vi miss" % self.crypt_context.part_num)
                            pre_iv = self.calc_iv
                        if self.isUploadLastPart and self.block_count == self.block_total_count:
                            encrypt_data = self.crypt_handler.encrypt(data, pre_iv)
                        else:
                            encrypt_data = self.crypt_handler.encrypt_without_padding(data, pre_iv)
                        if need_prefix:
                            encrypt_data = self.first_iv + encrypt_data
                        self.calc_iv = encrypt_data[-self.block_size:]
                        self.crypt_context.iv_dict[self.crypt_context.part_num] = self.calc_iv
                        # if self.isUploadFirstPart:
                        #     # For multi, the first part's first part will add a prefix of iv.
                        #     if not self.calc_iv:
                        #         if self.isUploadLastPart and self.block_count == self.block_total_count:
                        #             # A very special circumstance: a short piece of data that is both the first of the
                        #             # first and the last of the last.
                        #             encrypt_data = self.crypt_handler.encrypt(data, self.first_iv)
                        #             encrypt_data = self.first_iv + encrypt_data
                        #         else:
                        #             encrypt_data = self.crypt_handler.encrypt_without_padding(data,self.first_iv)
                        #             encrypt_data = self.first_iv+encrypt_data
                        #     elif not self.isUploadLastPart:
                        #         encrypt_data = self.crypt_handler.encrypt_without_padding(data, self.calc_iv)
                        #     elif self.isUploadLastPart and self.block_count == self.block_total_count:
                        #         # When the part is the firstPart AND the lastPart.
                        #         encrypt_data = self.crypt_handler.encrypt(data, self.calc_iv)
                        #     elif self.isUploadLastPart:
                        #         encrypt_data = self.crypt_handler.encrypt_without_padding(data, self.calc_iv)
                        #     else:
                        #         raise Exception
                        # elif not self.isUploadLastPart:
                        #     # The normal part that is neither the first nor the last one.
                        #     if self.block_count == 1:
                        #         self.calc_iv = self.crypt_context.iv_dict[self.crypt_context.part_num-1]
                        #     encrypt_data = self.crypt_handler.encrypt_without_padding(data, self.calc_iv)
                        # else:
                        #     # The last part.
                        #     # The last part's parts use 'encrypt' instead of 'encrypt_without_padding'
                        #     # because the last part's last part need paddling.
                        #     if self.block_count == 1 and self.block_count != self.block_total_count:
                        #         encrypt_data = self.crypt_handler.encrypt_without_padding(data, self.crypt_context.iv_dict[self.crypt_context.part_num-1])
                        #     elif self.block_count == 1 and self.block_count == self.block_total_count:
                        #         encrypt_data = self.crypt_handler.encrypt(data, self.crypt_context.iv_dict[self.crypt_context.part_num-1])
                        #     elif self.block_count == self.block_total_count:
                        #         encrypt_data = self.crypt_handler.encrypt(data, self.calc_iv)
                        #     else:
                        #         encrypt_data = self.crypt_handler.encrypt_without_padding(data,self.calc_iv)
                        # self.calc_iv = encrypt_data[-self.block_size:]
                        # self.crypt_context.iv_dict[self.crypt_context.part_num] = self.calc_iv
                        # print len(encrypt_data), self.block_count, self.block_total_count
                    return encrypt_data
            if name == "seek":
                def my_wrapper(*args, **kwargs):
                    ret = func(*args, **kwargs)
                    # self.seek_pos = args[1]
                    return ret
            if name == "tell":
                def my_wrapper(*args, **kwargs):
                    ret = func(*args, **kwargs)
                    if self.type == "upload_part":
                        if self.isUploadFirstPart:
                            return ret + 16
                        else:
                            return ret
                    return ret+16

            return my_wrapper
        else:
            return func

    def __len__(self):
        self.seek(0,SEEK_END)
        length = self.tell()
        self.seek(0,SEEK_SET)
        blocksize = 16
        if self.type == "put" or (self.type=="upload_part" and self.isUploadLastPart==True):
            pad = blocksize - length % blocksize
            return length+pad
        else:
            return length
