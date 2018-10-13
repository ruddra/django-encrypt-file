Django File Encrypt
~~~~~~~~~~~~~~~~~~~
|Build Status|

.. |Build Status| image:: https://travis-ci.org/travis-ci/travis-web.svg?branch=master
   :target: https://travis-ci.org/travis-ci/travis-web
|image0|

.. |image0| image:: https://img.shields.io/pypi/v/djangoencryptfile.svg
   :target: https://pypi.python.org/pypi/djangoencryptfile

.. image:: https://landscape.io/github/ruddra/django-encrypt-file/master/landscape.svg?style=flat
   :target: https://landscape.io/github/ruddra/django-encrypt-file/master
   :alt: Code Health
   
This package can be used to encrypt Django’s in memory files to encrypt
them.

Documentation
~~~~~~~~~~~~~
Go to this url: http://ruddra.com/documentation-of-django-encrypt-file/

Download
~~~~~~~~

Use ``pip install djangoencryptfile``

Basic Usage:
------------

::

    from djangoencryptfile import EncryptionService
    from django.core.files import File

    password = '1234'
    service = EncryptionService(raise_exception=False)

    open('readme.md', 'rb') as inputfile:
        usefile = File(inputfile, name='readme.md')
        encrypted_file = service.encrypt_file(useFile, password, extension='enc')  # it will save readme.md.enc
        decrypt_file = service.decrypt_file(encrypted_file, password, extension='enc') # it will remove .enc extension

Using in Views:
~~~~~~~~~~~~~~~

::

    from django_encrypt_file import EncryptionService, ValidationError


    def some_view(request):
       try:
           myfile = request.FILES.get('myfile', None)
           password = request.POST.get('password', None)
           encrypted_file = EncryptionService().encrypt_file(myfile, password, extension='enc')
           decrypt_file = service.decrypt_file(encrypted_file, password, extension='enc') # it will remove .enc extension
       except ValidationError as e:
           print(e)

Input file here can be any kind of Django File Object like
``models.FileField`` or ``forms.FileFiled``.
raise\_exception will throw ``ValidationError`` error which can be
imported ``from django_encrypt_file import ValidationError``
