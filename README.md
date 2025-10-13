# Automated-SSL-TLS-X.509-certificate

This project automates the generation, renewal, and deployment of SSL/TLS x509 certificates. 

## Description

This script creates a private key using the cryptography library, generates name attributes for the certificate, then initializes the certificate using the private key and encryting it using SHA256. 

Depending on the browser used to access the certificate, browsers like Chrome require an alternative name, so the host name and IP address of the server is used instead. Basic constraints like requiring Certificate Authority means the certificate can be used to create other certifcates and setting the path_lenth to 0 means the certificate can only be issued to end-entities (users, devices, services).

The PEM (Privacy-Enhanced Mail) certificate is then saved as 'X.509_Cert.crt' into the "etc/ssl/certs" directory and the 'X.509_Key.key' file containing the serialzed private key is saved to the "etc/ssl/private" directory.

## Process of RSA Certificate Authentication

After initializing a TCP handshake between client and server, a TLS handshake begins with the client requesting which cipher suit and TLS version it can use, then the server responds with the answers and the server’s public key.

The digital signature creation process will be conducted using a public-key system called RSA which creates two large prime numbers for the process. The client will encrypt the server’s public key it received with its own RSA session key to send back to the server. The server will decrypt the data using its own private key to uncover the session key for further data transmission.

### Dependencies

* Linux
* Apache2
* Python3
* cryptography
* os
* datetime

### Executing program

* python3 Certificate_Automation.py
