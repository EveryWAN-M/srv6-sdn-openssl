# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Arguments marked as "Required" below must be included for upload to PyPI.
# Fields marked as "Optional" may be commented out.
setup(
    name='srv6-sdn-openssl',  
    version='1.0-beta',
    description='OpenSSL library for SDN-SRv6 projects',  # Required
    long_description=long_description,
    long_description_content_type='text/markdown',  # Optional (see note above)
    url='',  # Optional
    packages=['srv6_sdn_openssl'],  # Required
    install_requires=[
        'setuptools',
        'six',
        'grpcio>=1.19.0',
        'grpcio-tools>=1.19.0',
        'protobuf>=3.7.1'
    ]
)