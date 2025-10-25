#!/usr/bin/env python3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives import hashes
import datetime, os, subprocess

Server_IP = "127.0.0.1"
Host_Name = "localhost"
# Identify IP and host name of the http server.

Key_Dir = "/etc/ssl/private/"
Cert_Dir = "/etc/ssl/certs/"
# Identify Apache directory for key and cirt.

def Generate_Key():
    Private_Key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend) 
    # Create a private key.
    # public_exponent value must be an odd integer and is typically chosen to be a small, fast value like 65537 for efficiency.
    # Key_size determines the strength of the key. Usually 2048 or 4096.
    return Private_Key


def Generate_Cirtificate(Host_Name, Private_Key):
    Name_Attributes = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, Host_Name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Temecula"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "elliotmollman@yahoo.com")
        ])
    # Declare attributes for cirtification within an X.509 Distinguished Name (DN).
    # These attributes are all passed into the X.509.Name object. 'NameOID' specifies attribute types.

    alt_names = [x509.DNSName(Host_Name)]
    alt_names.append(x509.DNSName(Server_IP))
    # This is for browsers like Chrome that might not interpret the common_name and generate an error. 

    Basic_Constraints = x509.BasicConstraints(ca=True, path_length=0)
    # The 'ca' (Certificate Authority) flag means the certificate can be used to create other certificates.
    # The 'path_length=0' signifies that the CA certificate can only issue certificates to end-entities (users, devices, services)

    Cert = (x509.CertificateBuilder()
                   .subject_name(Name_Attributes)
                   .issuer_name(Name_Attributes)
                   .public_key(Private_Key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                   .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
                   .add_extension(Basic_Constraints, True)
                   .add_extension(x509.SubjectAlternativeName(alt_names), False)
                   .sign(Private_Key, hashes.SHA256(), default_backend())
                   )
    Pem_Cert = Cert.public_bytes(encoding=serialization.Encoding.PEM)
    Pem_Private_key = Private_Key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return Pem_Cert, Pem_Private_key


def Create_Files(Cert_Dir, Key_Dir):
    Check_Cirt_Dir = os.makedirs(Cert_Dir, exist_ok=True)
    Check_Key_Dir = os.makedirs(Key_Dir, exist_ok=True)
    # Checking to see if the directories exist.
    if Check_Cirt_Dir == True and Check_Key_Dir == True:
        try:
            Full_Key_Path = os.path.join(Key_Dir, 'X.509_Key.key')
            Full_Cert_Path = os.path.join(Cert_Dir, 'X.509_Cert.crt')
            # Creating full path for 
            with open (Full_Cert_Path, 'wb') as e:
                e.write(Cert)
            with open (Full_Key_Path, 'wb') as e:
                e.write(Key)
            # Using 'wb' to write in binary mode.
        except Exception as e:
            print(f"An error occured: {e}")
    else:
        print("Apache2 is not installed or the path 'etc/ssl/private' and 'etc/ssl/certs' do not exist.\n")        


def Check_Services():
    Apache2_Return_Code = subprocess.run("which apache2", shell=True, check=True, capture_output=True)
    Apache2_Return_Code_As_Int = int(Apache2_Return_Code.returncode)
    return Apache2_Return_Code_As_Int

if __name__ == "__main__":
    try:
        Check_Services_Output = Check_Services()
        print(Check_Services_Output)
    except Exception as e:
        print(e)
        exit

    if Check_Services_Output != 0:
        print("Apache2 is not installed\n")
        exit    
    else:
        Private_Key = Generate_Key()
        Cert, Key = Generate_Cirtificate(Host_Name, Private_Key)
        Create_Files(Cert_Dir, Key_Dir)
        #If Apache exists, then continue with creating cirtificate






