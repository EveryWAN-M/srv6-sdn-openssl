#!/usr/bin/python

# General imports
import logging
import six
import os
from datetime import datetime, timedelta
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def get_cert_expiration(crt_pem):
    # Get the certificate
    crt = x509.load_pem_x509_certificate(crt_pem, default_backend())
    # Return the expiration
    return crt.not_valid_after


def validate_cert(crt_pem):
    # Get the certificate
    crt = x509.load_pem_x509_certificate(crt_pem, default_backend())
    # Get the current datetime
    now = datetime.utcnow()
    if now < crt.not_valid_before:
        logging.info('Certificate not yet valid')
        return False
    if now > crt.not_valid_after:
        logging.info('Certificate is expired')
        return False
    # Certificate is valid
    return True


def generate_rsa_key(public_exponent=65537, key_size=2048):
    key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend()
    )
    return key


def generate_selfsigned_cert(hostname, ip_addresses=None, key=None):
    # Parameters sanitization
    hostname = six.text_type(hostname)
    if ip_addresses is not None:
        ip_addresses = [six.text_type(addr)
                        for addr in ip_addresses]
    # Generate the key
    if key is None:
        key = generate_rsa_key()
    # Define Common Name
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])
    # Include the hostname in SAN
    alt_names = [x509.DNSName(hostname)]
    # Allow addressing by IP
    if ip_addresses is not None:
        for addr in ip_addresses:
            # openssl wants DNSnames for ips...
            alt_names.append(x509.DNSName(addr))
            # ... whereas golang's crypto/tls is stricter,
            # and needs IPAddresses
            # note: older versions of cryptography
            # do not understand ip_address objects
            alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))
    san = x509.SubjectAlternativeName(alt_names)
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    # Establish the validity of the certificate
    now = datetime.utcnow()
    # Generate the certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10*365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    # Encode in PEM format
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    # Get private key and encode it in PEM format
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Return the certificate and the private key
    return cert_pem, key_pem


def generate_csr(hostname, ip_addresses=None, key=None):
    # Parameters sanitization
    hostname = six.text_type(hostname)
    if ip_addresses is not None:
        ip_addresses = [six.text_type(addr)
                        for addr in ip_addresses]
    # Generate the key
    if key is None:
        key = generate_rsa_key()
    # Define Common Name
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])
    # Include the hostname in SAN
    alt_names = [x509.DNSName(hostname)]
    # Allow addressing by IP
    if ip_addresses is not None:
        for addr in ip_addresses:
            # openssl wants DNSnames for ips...
            alt_names.append(x509.DNSName(addr))
            # ... whereas golang's crypto/tls is stricter,
            # and needs IPAddresses
            # note: older versions of cryptography
            # do not understand ip_address objects
            alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))
    san = x509.SubjectAlternativeName(alt_names)
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    # Generate the certificate
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    # Encode in PEM format
    csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)
    # Get private key and encode it in PEM format
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Return the CSR and the private key
    return csr_pem, key_pem


def generate_cert(csr_pem, ca_crt_pem, key=None, expires_after=None):
    # Load CSR PEM and generate a CSR object
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())
    # Load CA cert PEM and generate a cert object
    ca_crt = x509.load_pem_x509_certificate(ca_crt_pem, default_backend())
    # 
    #hostname = csr.extensions.get_extension_for_oid(NameOID.COMMON_NAME)
    
    hostname = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    basic_contraints = csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    basic_contraints = basic_contraints.value
    
    san = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    san = san.value
    
    #exit()
    
    # Parameters sanitization
    #hostname = six.text_type(hostname)
    #ip_addresses = [six.text_type(ip_address)
    #                for ip_address in ip_addresses]
    # Generate the key)
    if key is None:
        key = generate_rsa_key()
    else:
        key = serialization.load_pem_private_key(key, None, default_backend())
        
    key = load_key('/tmp/ewCont/ca.key')
                   
    # Define Common Name
    #name = x509.Name([
    #    x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    #])
    # Include the hostname in SAN
    #alt_names = [x509.DNSName(hostname)]
    # Allow addressing by IP
     #if ip_addresses:
    #    for addr in ip_addresses:
    #        # openssl wants DNSnames for ips...
    #        alt_names.append(x509.DNSName(addr))
    #        # ... whereas golang's crypto/tls is stricter,
    #        # and needs IPAddresses
    #        # note: older versions of cryptography
    #        # do not understand ip_address objects
    #        alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))
    #san = x509.SubjectAlternativeName(alt_names)
    # path_len=0 means this cert can only sign itself, not other certs.
    #basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    # Establish the validity of the certificate
    now = datetime.utcnow()
    # Compute certificate expiration
    if expires_after is None:
        expires_after = 10*365    
    # Generate the certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_crt.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=expires_after))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    # Encode in PEM format
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    # Get private key and encode it in PEM format
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Return the certificate and the private key
    return cert_pem, key_pem


#def sign_cert(csr_pem, key):
#    cert = x509.load_pem_x509_csr(csr_pem, default_backend())
#    return cert.sign(key, hashes.SHA256(), default_backend())


def save_to_file(obj, filename):
    with open(filename, 'wb') as f:
        f.write(obj)


def load_cert(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = x509.load_pem_x509_certificate(
        pemlines, default_backend())
    return private_key


def load_csr(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = x509.load_pem_x509_csr(
        pemlines, default_backend())
    return private_key


def load_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = serialization.load_pem_private_key(
        pemlines, None, default_backend())
    return private_key


if __name__ == '__main__':
    hostname = six.text_type('prova')
    #cert, key = generate_selfsigned_cert(hostname)
    csr, key = generate_csr(hostname, ['9.9.9.9', '4.4.4.4'])
    save_to_file(csr, '/home/user/python-csr.crt')
    crt, k = generate_cert(csr, key)    # TODO Fix this line!!!
    save_to_file(crt, '/home/user/signed.crt')
    c, k = generate_selfsigned_cert('clalsl')
    save_to_file(c, '/home/user/self signed.crt')
