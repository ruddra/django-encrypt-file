"""
-------------------
Django File Encrypt
-------------------

A simple package which will encrypt in memory File objects(django.core.files.File) and decrypt them

Copyright ruddra <me@ruddra.com>
"""
import os
import sys
from hashlib import md5
try:
    from Crypto.Cipher import AES
except ImportError:
    print('Require Pycrypto to use this. Install it using: pip install pycrypto==2.6.1')
    sys.exit(0)
try:
    from django.core.files import File
except ImportError:
    print('Require Django to use this. Install it using: pip install django==1.10.4')
    sys.exit(0)

check_version = sys.version_info[0]


class ValidationError(Exception):
    pass


class EncryptionService(object):
    def __init__(self, raise_exception=True):
        self.errors = list()
        self.raise_exception = raise_exception

    def _derive_key_and_iv(self, password, salt, key_length, iv_length):
        d = d_i = b''
        while len(d) < key_length + iv_length:
            d_i = md5(d_i + str.encode(password) + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length + iv_length]

    def encrypt_file(self, in_file, password, extension='enc', salt_header='', key_length=32):
        if not self._validate(in_file, password):
            return False
        try:
            infile_name = in_file.name
            outfile_name = '{}.{}'.format(infile_name, extension)
            with open(outfile_name, 'wb') as out_file:
                bs = AES.block_size
                salt = os.urandom(bs - len(salt_header))
                key, iv = self._derive_key_and_iv(password, salt, key_length, bs)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                out_file.write(str.encode(salt_header) + salt)
                finished = False
                while not finished:
                    chunk = in_file.read(1024 * bs)
                    if len(chunk) == 0 or len(chunk) % bs != 0:
                        padding_length = (bs - len(chunk) % bs) or bs
                        chunk += str.encode(
                            padding_length * chr(padding_length)
                        )
                        finished = True
                    out_file.write(cipher.encrypt(chunk))
                out_file.close()
            reopen = self._open_file(outfile_name)

            return self._return_file(reopen, outfile_name)

        except TypeError:
            return self._return_or_raise("Invalid File input. Expected Django File Object")

        except AttributeError:
            return self._return_or_raise('You must enter Django File Type Object: from django.core.files import File')

        except IOError:
            return self._return_or_raise('File does not exist')

        except ValueError:
            return self._return_or_raise('You must enter Django File Type Object: from django.core.files import File')

        except Exception as e:
            if sys.version_info[0] > 2:
                return self._return_or_raise(str(e))
            return self._return_or_raise(e.message)

    def decrypt_file(self, file_object, password, extension='enc', salt_header='', key_length=32):
        try:
            if not self._validate(file_object, password):
                return False
            filename = file_object.name
            outfile_name = filename.replace('.{}'.format(extension), '')
            with open(filename, 'rb') as in_file:
                bs = AES.block_size
                salt = in_file.read(bs)[len(salt_header):]
                key, iv = self._derive_key_and_iv(password, salt, key_length, bs)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                next_chunk = b''
                finished = False
                with open(outfile_name, 'wb') as out_file:
                    while not finished:
                        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
                        if len(next_chunk) == 0:
                            if check_version == 2:
                                padding_length = chunk[-1]
                                chunk = chunk.replace(padding_length, '')
                            else:
                                padding_length = chunk[-1]
                                chunk = chunk[:-padding_length]
                            finished = True
                        out_file.write(chunk)
                    out_file.close()
            reopen = self._open_file(outfile_name)
            return self._return_file(reopen, outfile_name)

        except TypeError:
            return self._return_or_raise("Invalid File input. Expected Django File Object")

        except AttributeError:
            return self._return_or_raise('You must enter Django File Type Object')

        except IOError:
            return self._return_or_raise('File does not exist')

        except ValueError:
            return self._return_or_raise('You must enter Django File Type Object')

        except Exception as e:
            if check_version > 2:
                return self._return_or_raise(str(e))
            return self._return_or_raise(e.message)

    def _open_file(self, filename):
        return open(filename, 'rb')

    def _return_file(self, filename, name):
        return File(filename, name)

    def _validate(self, file_object=None, password=None):
        if not file_object:
            return self._return_or_raise('File can not be null')

        if not password:
            return self._return_or_raise('Password can not be None')
        return True

    def _return_or_raise(self, msg):
        if self.raise_exception:
            raise ValidationError(msg)
        else:
            self.errors.append(msg)
            return False
