import os
from hashlib import md5
from Crypto.Cipher import AES
from django.core.files import File
from django.utils.translation import ugettext_lazy as _

from exceptions import ValidationError



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

    def encrypt_file(self, in_file, password, extension='', prefix='', salt_header='', key_length=32):
        if not self._validate(in_file, password):
            return False
        try:
            filename = in_file.name
            with open(filename, 'wb') as out_file:
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
            reopen = self._open_file(filename)
            if extension:
                new_filename = filename + extension
                os.rename(filename, new_filename)
                return self._return_file(reopen, new_filename)

            return self._return_file(reopen, filename)

        except AttributeError:
            return self._return_or_raise('You must enter Django File Type Object: from django.core.files import File')

        except IOError:
            return self._return_or_raise('File does not exist')

        except ValueError:
            return self._return_or_raise('You must enter Django File Type Object: from django.core.files import File')

        except Exception as e:
            return self._return_or_raise(str(e))

    def decrypt_file(self, filename, password, extension='', salt_header='', key_length=32):
        try:
            if not self._validate(filename, password):
                return False
            with open(filename, 'rb') as in_file:
                bs = AES.block_size
                salt = in_file.read(bs)[len(salt_header):]
                key, iv = self._derive_key_and_iv(password, salt, key_length, bs)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                next_chunk = b''
                finished = False
                with open(filename, 'wb') as out_file:
                    while not finished:
                        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
                        if len(next_chunk) == 0:
                            padding_length = chunk[-1]
                            chunk = chunk[:-padding_length]
                            finished = True
                        out_file.write(chunk)
                    out_file.close()

            reopen = self._open_file(filename)
            if extension:
                base_file, ext = os.path.splitext(filename)
                os.rename(filename, base_file)
                return self._return_file(reopen, base_file)

            return self._return_file(reopen, filename)

        except AttributeError:
            return self._return_or_raise('You must enter Django File Type Object: from django.core.files import File')

        except IOError:
            return self._return_or_raise('File does not exist')

        except ValueError:
            return self._return_or_raise('You must enter Django File Type Object: from django.core.files import File')

        except Exception as e:
            return self._return_or_raise(e)

    def _open_file(self, filename):
        return open(filename, 'rb')

    def _return_file(self, file, name):
        return File(file, name)

    def _validate(self, filename=None, password=None):
        if not filename:
            return self._return_or_raise('File can not be null')

        if not password:
            return self._return_or_raise('Password can not be None')
        return True

    def _return_or_raise(self, msg):
        if self.raise_exception:
            raise ValidationError(msg=_(msg))
        else:
            self.errors.append(_(msg))
            return False

