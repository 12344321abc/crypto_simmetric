from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from enum import Enum, StrEnum
import operator


class Banana:
    def __init__(self):
        class MODES(StrEnum):
            ECB = 'ECB'
            CBC = 'CBC'
            CFB = 'CFB'
            OFB = 'OFB'
            CTR = 'CTR'

        self.MODES = MODES
        self.KEY_SIZE = 16
        self.BLOCK_SIZE = 16
        self.key = get_random_bytes(self.KEY_SIZE)
        self.mode = self.MODES.ECB
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.iv = get_random_bytes(self.BLOCK_SIZE)
        self.last_block = b''

    def SetKey(self, new_key: bytes):
        if isinstance(new_key, type(self.key)) and len(new_key) == self.KEY_SIZE:
            self.key = new_key
        else:
            raise ValueError("Длина ключа должна быть %d байт(переданный %d) И он должен \
             быть из <class 'bytes'>" % (self.KEY_SIZE, len(new_key)))

    def SetMode(self, new_mode: str):
        if new_mode in self.MODES:
            self.mode = self.MODES[new_mode]
        else:
            raise ValueError("Mode должен принимать только допустимые строковые значения 'ECB', 'CBC', 'CFB', 'OFB', "
                             "'CTR', а не '%s'" % new_mode)

    def BlockCipherEncrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)

    def BlockCipherDecrypt(self, data: bytes) -> bytes:
        return self.cipher.decrypt(data)

    def ProcessBlockEncrypt(self, data: bytes, isFinalBLock: bool) -> bytes:
        return_one_block_flag = True
        if isFinalBLock and self.mode in [self.MODES.ECB, self.MODES.CBC]:  # PKCS7
            if self.BLOCK_SIZE - len(data) > 0:
                data = bytearray(data)
                data.extend(bytearray([self.BLOCK_SIZE - len(data)] * (self.BLOCK_SIZE - len(data))))
                data = bytes(data)
            else:
                return_one_block_flag = False
        if self.mode == self.MODES.ECB:
            if return_one_block_flag:
                return self.BlockCipherEncrypt(data)
            first_block_to_return = self.BlockCipherEncrypt(data)
            return first_block_to_return + self.ProcessBlockEncrypt(b'', True)
        elif self.mode == self.MODES.CBC:
            data = bytes(map(operator.xor, self.last_block, data))
            self.last_block = self.BlockCipherEncrypt(data)
            if return_one_block_flag:
                return self.last_block
            first_block_to_return = self.last_block
            return first_block_to_return + self.ProcessBlockEncrypt(b'', True)
        elif self.mode == self.MODES.CFB:
            self.last_block = bytes(map(operator.xor, data, self.BlockCipherEncrypt(self.last_block)[:len(data)]))
            return self.last_block
        elif self.mode == self.MODES.OFB:
            self.last_block = self.BlockCipherEncrypt(self.last_block)
            return bytes(map(operator.xor, data, self.last_block[:len(data)]))
        elif self.mode == self.MODES.CTR:
            n = int.from_bytes(self.last_block, 'big')
            data = bytes(map(operator.xor, data, self.BlockCipherEncrypt(self.last_block)[:len(data)]))
            self.last_block = (n + 1).to_bytes(self.BLOCK_SIZE, 'big')
            return data
        else:
            raise ValueError("Something went wrong,[Undefined mode {}] sorry".format(self.mode))

    def ProcessBlockDecrypt(self, data: bytes, isFinalBLock: bool) -> bytes:
        if self.mode == self.MODES.ECB:
            data1 = self.BlockCipherDecrypt(data)
        elif self.mode == self.MODES.CBC:
            data1 = bytes(map(operator.xor, self.last_block, self.BlockCipherDecrypt(data)))
            self.last_block = data
        elif self.mode == self.MODES.CFB:
            data1 = bytes(map(operator.xor, data, self.BlockCipherEncrypt(self.last_block)[:len(data)]))
            self.last_block = data
        elif self.mode == self.MODES.OFB:
            data1 = bytes(map(operator.xor, data, self.BlockCipherEncrypt(self.last_block)[:len(data)]))
            self.last_block = self.BlockCipherEncrypt(self.last_block)
        elif self.mode == self.MODES.CTR:
            n = int.from_bytes(self.last_block, 'big')
            data1 = bytes(map(operator.xor, data, self.BlockCipherEncrypt(self.last_block)[:len(data)]))
            self.last_block = (n + 1).to_bytes(self.BLOCK_SIZE, 'big')
        else:
            raise ValueError("Something went wrong,[Undefined mode {}] sorry".format(self.mode))
        if isFinalBLock:
            if self.mode in [self.MODES.ECB, self.MODES.CBC]:  # PKCS7
                data1 = data1[:len(data1) - data1[-1]]
            else:  # NON
                pass
        return data1

    def Encrypt(self, data: bytes, iv_real=b'') -> bytes:
        if iv_real != b'':
            self.iv = iv_real
        elif self.mode == self.MODES.CTR:
            self.iv = get_random_bytes(self.BLOCK_SIZE)[:-4] + bytes.fromhex('00000000')
        else:
            self.iv = get_random_bytes(self.BLOCK_SIZE)
        self.last_block = self.iv
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        tmp = bytearray()
        for i in range((len(data) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE):
            tmp.extend(self.ProcessBlockEncrypt(data[i * self.BLOCK_SIZE:(i + 1) * self.BLOCK_SIZE],
                                                (i + 1) * self.BLOCK_SIZE >= len(data)))
        return bytes(tmp)

    def Decrypt(self, data: bytes, iv_real=b'') -> bytes:
        if iv_real != b'':
            self.iv = iv_real
        else:
            pass
        self.last_block = self.iv
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        tmp = bytearray()
        for i in range((len(data) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE):
            tmp.extend(self.ProcessBlockDecrypt(data[i * self.BLOCK_SIZE:(i + 1) * self.BLOCK_SIZE],
                                                (i + 1) * self.BLOCK_SIZE >= len(data)))
        return bytes(tmp)


# Example usage
plaintext = b"This is the message to be encrypted only"
b = Banana()
#################################################################################
###                                ECB
#################################################################################
print("_" * 20 + "ECB" + "_" * 20)
en = b.Encrypt(plaintext)
de = b.Decrypt(en)
print(de)
#################################################################################
###                                CBC
#################################################################################
print("_" * 20 + "CBC" + "_" * 20)
iv = get_random_bytes(16)
b.SetMode('CBC')
en = b.Encrypt(plaintext, iv)
de = b.Decrypt(en)
print(de)
key = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')
b.SetKey(key)
c1 = bytes.fromhex(
    '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')
c2 = bytes.fromhex(
    '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')
x = AES.new(key, AES.MODE_CBC, c1[:16])
print(b.Decrypt(c1[16:], c1[:16]))
print(x.decrypt(c1[16:]))
x = AES.new(key, AES.MODE_CBC, c2[:16])
print(b.Decrypt(c2[16:], c2[:16]))
print(x.decrypt(c2[16:]))
x = AES.new(key, AES.MODE_CBC, b'0000000000000000')
c3 = b.Encrypt(b'didn\'tforget2.5', b'0000000000000000')  # <----------------------------------------THERE IS 2.5
print(x.decrypt(c3))
#################################################################################
###                                CFB
#################################################################################
print("_" * 20 + "CFB" + "_" * 20)
iv = get_random_bytes(16)
b.SetMode('CFB')
en = b.Encrypt(plaintext, iv)
de = b.Decrypt(en)
print(de)
#################################################################################
###                                OFB
#################################################################################
print("_" * 20 + "OFB" + "_" * 20)
iv = get_random_bytes(16)
b.SetMode('OFB')
en = b.Encrypt(plaintext, iv)
de = b.Decrypt(en)
print(de)
#################################################################################
###                                CTR
#################################################################################
print("_" * 20 + "CTR" + "_" * 20)
iv = get_random_bytes(16)
b.SetMode('CTR')
en = b.Encrypt(plaintext, iv)
de = b.Decrypt(en)
print(de)
key = bytes.fromhex('36f18357be4dbd77f050515c73fcf9f2')
b.SetKey(key)
c1 = bytes.fromhex(
    '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')
c2 = bytes.fromhex(
    '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')
print(b.Decrypt(c1[16:], c1[:16]))
print(b.Decrypt(c2[16:], c2[:16]))
