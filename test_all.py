import copy
import unittest
from django.core.files.uploadedfile import SimpleUploadedFile
from djangoencryptfile import EncryptionService, ValidationError


class Test(unittest.TestCase):
    def setUp(self):
        self.password = '1234'
        self.wrong_password = '4321'
        self.file = SimpleUploadedFile('test.pdf', b'these are the file contents!', content_type="application/pdf")
        self.invalid_file = 'output.pdf'

    def test_encryption_decryption_roundup(self):
        file_name = copy.deepcopy(self.file)
        encrypted_file = EncryptionService().encrypt_file(file_name, self.password)
        self.assertNotEqual(file_name.read(), encrypted_file.read())
        decrypted_file = EncryptionService().decrypt_file(encrypted_file, self.password)
        self.assertEqual(self.file.read(), decrypted_file.read())

    def test_encrypt_decrypt_with_extension_success(self):
        file_name = copy.deepcopy(self.file)
        encrypted_file = EncryptionService().encrypt_file(file_name, self.password, extension='enc')
        self.assertNotEqual(file_name.read(), encrypted_file.read())
        decrypted_file = EncryptionService().decrypt_file(encrypted_file, self.password, extension='enc')
        self.assertEqual(self.file.read(), decrypted_file.read())

    def test_decrypt_with_wrong_password_fails(self):
        file_name = copy.deepcopy(self.file)
        encrypted_file = EncryptionService().encrypt_file(file_name, self.password, extension='enc')
        self.assertNotEqual(file_name.read(), encrypted_file.read())
        decrypted_file = EncryptionService().decrypt_file(encrypted_file, self.wrong_password, extension='enc')
        self.assertNotEquals(self.file.read(), decrypted_file.read())

    def test_encrypt_decrypt_fail_without_password(self):
        file_name = copy.deepcopy(self.file)
        self.assertRaises(ValidationError, EncryptionService().encrypt_file, file_name, None)
        self.assertRaises(ValidationError, EncryptionService().decrypt_file, file_name, None)

    def test_encrypt_decrypt_fail_without_filename(self):
        self.assertRaises(ValidationError, EncryptionService().encrypt_file, None, self.password)
        self.assertRaises(ValidationError, EncryptionService().decrypt_file, None, self.password)

    def test_enrypt_decrypt_fail_for_invalid_file_type(self):
        self.assertRaises(ValidationError, EncryptionService().encrypt_file, self.invalid_file, self.password)
        self.assertRaises(ValidationError, EncryptionService().decrypt_file, self.invalid_file, self.password)

    def test_encrypt_decrypt_return_false_for_raise_exception_false_for_invalid_input(self):
        self.assertEqual(False, EncryptionService(raise_exception=False).encrypt_file(
                          self.invalid_file, self.password))
        self.assertEqual(False, EncryptionService(raise_exception=False).decrypt_file(
                          self.invalid_file, self.password))

if __name__ == '__main__':
    unittest.main()
