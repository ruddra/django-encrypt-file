from distutils.core import setup
setup(
  name='djangoencryptfile',
  packages=['djangoencryptfile'],
  version='0.3',
  description='A simple package to encrypt Django uploaded or downloading files(Django File Object)',
  author='Arnab Kumar Shil',
  author_email='me@ruddra.com',
  license='MIT',
  url='https://github.com/ruddra/django-encrypt-file',
  download_url='https://github.com/ruddra/django-encrypt-file/archive/0.2.tar.gz',
  keywords=['django', 'encryption', 'decrypt', 'decryption', 'encrypt', 'file', 'django file', 'upload', 'download', 'inmemoryfile', 'models.filefield'],
  classifiers=[],
  platform = ['Windows', 'Linux', 'OSX'],
  install_requires=[
          'django>=1.7',
          'pycrypto>=2.6.1'
      ],
)
