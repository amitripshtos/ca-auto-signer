#!/usr/bin/python

import os
import subprocess
import getpass
import socket
import logging
import logging.config
import string
import time
import argparse


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'default': {
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        '': {
            'handlers': ['default'],
            'level': 'INFO',
            'propagate': True
        }
    }
}

logging.config.dictConfig(LOGGING)
logger = logging.getLogger(__name__)

# Making input backward compatible to python2
try:
    # noinspection PyUnresolvedReferences
    input = raw_input
except NameError:
    pass

MSCA = ''  # Internal Microsoft Certification Authority
CERTIFICATE_ATTRIBUTE = ''

OPENSSL_CONFIG_TEMPLATE = """
prompt = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
C                      = US
ST                     = NY
L                      = New York
O                      = company
OU                     = Your company
CN                     = %(domain)s
emailAddress           = your@email.com
"""

# SSL related configurations
CA_CERT = 'ca.crt'
INSTANCE_PRIVATE_KEY = 'server.key'
INSTANCE_CERTIFICATE = 'server.crt'
INSTANCE_CERTIFICATE_REQUEST = 'server.csr'
INSTANCE_CERTIFICATE_CONFIG_FILE = 'server.config'
OPENSSL = '/usr/bin/openssl'
KEY_SIZE = 4096
DAYS = 3650

FNULL = open(os.devnull, 'w')


def create_dirs_recursive(path):
    """
    Create directories and sub-directories

    :param path:
    :return:
    """
    logger.debug('Creating directory {}'.format(path))
    if not os.path.isdir(path):
        os.makedirs(path)


def openssl(*args):
    cmdline = [OPENSSL] + list(args)
    subprocess.check_call(cmdline, stdout=FNULL, stderr=subprocess.STDOUT)


def create_openssl_config_file(config_file_path, domain):
    # Create config file\
    config = open(config_file_path, 'w')
    config.write(OPENSSL_CONFIG_TEMPLATE % {'domain': domain})
    config.close()


def create_private_key(private_key_path, password):
    """
    Create instance`s private key and saves it in the dedicated folder.

    :param path: str
    :param password: int
    :return:
    """
    openssl('genrsa', '-des3', '-passout', 'pass:{}'.format(password), '-out', private_key_path, str(KEY_SIZE))


def create_certificate_request_file(private_key_path, certificate_request_file_path, config_file_path, password):
    """
    Create certificate request file (to be sent later to our CA server)
    :param private_key_path: str
    :param certificate_request_file_path: str
    :param config_file_path: str
    :param password: str
    :return:
    """
    x509_password = ['-passin', 'pass:{}'.format(password)]
    openssl('req', '-new',
            '-key', private_key_path,
            '-out', certificate_request_file_path,
            '-config', config_file_path,
            *x509_password)

    assert os.path.exists(certificate_request_file_path), 'Could not create certificate request file.'


def save_signed_certificate(operation_username, operation_password, certificate_file_path, link):
    """
    After we request a certificate, we should get a link and download our certificate.
    So, this method gets a link from the CA server and downloads that link into the certificate file path.
    :param operation_username: str
    :param operation_password: str
    :param certificate_file_path: str
    :param link: str
    :return:
    """
    command = 'curl -k -u "{operation_username}:{operation_password}" --ntlm \
        -o {certificate_file_path} \
        --noproxy {MSCA} \
        {link} \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        -H "Accept-Encoding: gzip, deflate" \
        -H "Accept-Language: en-US,en;q=0.5" \
        -H "Connection: keep-alive" \
        -H "Host: {MSCA}" \
        -H "Referer: https://{MSCA}/certsrv/certrqxt.asp" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko" \
        -H "Content-Type: application/x-www-form-urlencoded"'.format(
        link=link,
        operation_username=operation_username,
        operation_password=operation_password,
        MSCA=MSCA,
        certificate_file_path=certificate_file_path)

    subprocess.call(command, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)

    time.sleep(1)
    assert os.path.exists(certificate_file_path) , 'Could not save the signed certificate from the CA server response'


def sign_certificate(operation_username, operation_password, certificate_request_file_path, certificate_file_path):
    """
    This method sends the sign request to the CA server, and downloads the certificate created for us.
    :param operation_username: str
    :param operation_password: str
    :param certificate_request_file_path: str
    :param certificate_file_path: str
    :return:
    """
    with open(certificate_request_file_path) as file:
        certificate_request_content = file.readlines()

    certificate_request_content = ''.join(
        [line.strip().replace('+', '%2B').translate(string.maketrans(" ", "+")) for line in
         certificate_request_content])

    command = 'curl -k -u "{operation_username}:{operation_password}" --ntlm \
        --noproxy {MSCA} \
        "https://{MSCA}/certsrv/certfnsh.asp" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        -H "Accept-Encoding: gzip, deflate" \
        -H "Accept-Language: en-US,en;q=0.5" \
        -H "Connection: keep-alive" \
        -H "Host: {MSCA}" \
        -H "Referer: https://{MSCA}/certsrv/certrqxt.asp" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data "Mode=newreq&CertRequest={cert}&CertAttrib={certificate_attribute}&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=" | grep -A 1 "function handleGetCert() {{" | tail -n 1 | cut -d \'"\' -f 2'.format(
        operation_username=operation_username,
        operation_password=operation_password,
        MSCA=MSCA,
        cert=certificate_request_content,
        certificate_attribute=CERTIFICATE_ATTRIBUTE)

    certificate_url = subprocess.check_output(command, shell=True).strip()
    assert certificate_url != '', 'Could not request a sign for certificate from the CA server. ' \
                                  'Got a bad response, please check that you are able to connect your DC server ' \
                                  'from this server and check your proxy settings in the server (if needed)'

    link = 'https://{MSCA}/certsrv/{certificate_url}Enc=b64'.format(MSCA=MSCA, certificate_url=certificate_url)
    save_signed_certificate(operation_username=operation_username,
                            operation_password=operation_password,
                            certificate_file_path=certificate_file_path,
                            link=link)


def fetch_ca_certificate(operation_username, operation_password, ca_certificate_path):
    """
    Fetch the public CA certificate and saves it in the right place.

    :param operation_username: str
    :param operation_password: str
    :param ca_certificate_path: str
    :return:
    """
    link = "https://{MSCA}/certsrv/certnew.cer?ReqID=CACert&Renewal=0&Enc=b64".format(MSCA=MSCA)

    command = [
        'curl',
        '-o', ca_certificate_path,
        '-k',
        '--noproxy', MSCA,
        '-u', '"{operation_username}:{operation_password}"'.format(operation_username=operation_username,
                                                                   operation_password=operation_password),
        '--ntlm',
        '-H', '"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"',
        '-H', '"Accept-Encoding: gzip, deflate"',
        '-H', '"Accept-Language: en-US,en;q=0.5"',
        '-H', '"Connection: keep-alive"',
        '-H', '"Host: {MSCA}"'.format(MSCA=MSCA),
        link
    ]
    subprocess.call(' '.join(command), shell=True, stdout=FNULL, stderr=subprocess.STDOUT)

    time.sleep(1)
    assert os.path.exists(ca_certificate_path) , 'Could not fetch CA public certificate from the CA server'


def verify_certificate(ca_certificate_path, certificate_file_path):
    """
    Verify the created certificate against our public CA certificate.

    :param ca_certificate_path: str
    :param certificate_file_path: str
    :return:
    """
    try:
        time.sleep(1)
        openssl('verify', '-CAfile', ca_certificate_path, '-verbose', certificate_file_path)
    except Exception as e:
        logger.error('Could not verify our created certificate. Error was {}'.format(repr(e)))


def clean_process(certificate_request_file_path, config_file_path):
    """
    Cleaning some not used files (config and request files)

    :param certificate_request_file_path: str
    :param config_file_path: str
    :return:
    """
    os.remove(certificate_request_file_path)
    os.remove(config_file_path)


def remove_pass_phrase_from_private_key(private_key_path, password):
    """
    Removing the pass phrase from the private key (by running rsa command on the existing private key)

    :param private_key_path: str
    :param password: str
    :return:
    """
    x509_password = ['-passin', 'pass:{}'.format(password)]
    openssl('rsa',
            '-in', private_key_path,
            '-out', private_key_path,
            *x509_password)


def main():
    global CERTIFICATE_ATTRIBUTE
    global MSCA

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--path', default='/etc/certs.d/', type=str.lower,
                        help="Path to save certificates")

    parser.add_argument('-s', '--server', type=str.lower,
                        help="The DC server")

    parser.add_argument('-f', '--fqdn', default=socket.getfqdn(), type=str.lower,
                        help="The FQDN of the server you want to create certificates for")

    parser.add_argument('-a', '--attribute', default='CertificateTemplate:Server', type=str.lower,
                        help="The certificate attribute wanted (A.K.A template)")

    args, optional = parser.parse_known_args()

    private_key_path = os.path.join(args.path, INSTANCE_PRIVATE_KEY)
    config_file_path = os.path.join(args.path, INSTANCE_CERTIFICATE_CONFIG_FILE)
    certificate_request_file_path = os.path.join(args.path, INSTANCE_CERTIFICATE_REQUEST)
    certificate_file_path = os.path.join(args.path, INSTANCE_CERTIFICATE)
    ca_certificate_path = os.path.join(args.path, CA_CERT)

    operations_username = input('Enter domain admin username: ')
    operations_password = getpass.getpass('Enter domain admin password: ')
    private_key_password = getpass.getpass('Enter a password for private key: ')
    domain = args.fqdn
    MSCA = args.server

    CERTIFICATE_ATTRIBUTE = args.attribute

    create_dirs_recursive(path=args.path)
    logger.info('Creating private key')
    create_private_key(
        private_key_path=private_key_path,
        password=private_key_password)

    logger.info('Creating configuration file')
    create_openssl_config_file(
        config_file_path=config_file_path,
        domain=domain)

    logger.info('Creating request file')
    create_certificate_request_file(
        private_key_path=private_key_path,
        certificate_request_file_path=certificate_request_file_path,
        config_file_path=config_file_path,
        password=private_key_password)

    logger.info('Signing our certificate')
    sign_certificate(
        operation_username=operations_username,
        operation_password=operations_password,
        certificate_request_file_path=certificate_request_file_path,
        certificate_file_path=certificate_file_path)

    logger.info('Fetching the public CA certificate')
    fetch_ca_certificate(
        operation_username=operations_username,
        operation_password=operations_password,
        ca_certificate_path=ca_certificate_path)

    logger.info('Verifying our certificate')
    verify_certificate(
        ca_certificate_path=ca_certificate_path,
        certificate_file_path=certificate_file_path)

    logger.info('Cleaning not used files')
    clean_process(
        certificate_request_file_path=certificate_request_file_path,
        config_file_path=config_file_path)

    logger.info('Removing the passphrase from the private key (for security measures)')
    remove_pass_phrase_from_private_key(
        private_key_path=private_key_path,
        password=private_key_password)

    logger.info('Completed creating all needed certificates!')


main()


if __name__ == '__main__':
    main()
