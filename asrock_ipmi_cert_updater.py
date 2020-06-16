# This script updates the certificate for the ASRock Rack IPMI web interface. ASRock does not use the standard Redfish
# API schema so we can"t just run the redfish Python module.

import os
import sys
import argparse
import configparser
import logging
import requests
import json
from urllib.parse import urlparse

REQUEST_TIMEOUT = 10
LOGIN_URL = "/api/session"
CERT_INFO_URL = "/api/settings/ssl/certificate"
# Current version of API has the same URL for getting the current certificate and updating the certificate, just using
# GET and POST respectively
UPLOAD_CERT_URL = "/api/settings/ssl/certificate"


def login(session, rhost, username, password):
    """
    Log into IPMI interface

    :param session: current session object
    :type session: requests.session
    :param rhost: remote host
    :type rhost: string
    :param username: username to use for logging in
    :type username: string
    :param password: password to use for logging in
    :type username: string
    :rtype: bool
    """
    login_data = {
        "username": username,
        "password": password,
        "certlogin": 0
    }

    login_url = rhost + LOGIN_URL
    try:
        # We don"t want to verify the certificate as it may not be valid
        result = session.post(login_url, login_data, timeout=REQUEST_TIMEOUT, verify=False)
    except ConnectionError:
        return False
    if not result.ok:
        return False
    # Set CRSF token for future requests
    decoded_result = json.loads(result.text)
    session.headers.update({"X-CSRFTOKEN": decoded_result["CSRFToken"]})
    # Required QSESSIONID cookie is automatically passed to future requests in the same session
    return True


def logout(session, rhost):
    """
    Log out of IPMI interface

    :param session: current session object
    :type session: requests.session
    :param rhost: remote host
    :type rhost: string
    :rtype: bool
    """

    logout_url = rhost + LOGIN_URL
    try:
        result = session.delete(logout_url, timeout=REQUEST_TIMEOUT, verify=False)
    except ConnectionError:
        return False
    if not result.ok:
        return False
    return True


def get_cert_info(session, rhost):
    """
    Cet current certificate information

    :param session: current session object
    :type session: requests.session
    :param rhost: remote host
    :type rhost: string
    :rtype: dict
    """

    cert_info_url = rhost + CERT_INFO_URL
    try:
        result = session.get(cert_info_url, timeout=REQUEST_TIMEOUT, verify=False)
    except ConnectionError:
        return False
    if not result.ok:
        return False
    decoded_result = json.loads(result.text)
    # As there"s no way to remove a certificate, we always have one certificate to handle.
    cert_info = {
        "from_common_name": decoded_result["from_common_name"],
        "serial_number": decoded_result["serial_number"],
        "valid_till": decoded_result["valid_till"]
    }
    return cert_info


def upload_cert(session, rhost, key_file, cert_file):
    """
    Upload X.509 private key and certificate to server

    :param session: current session object
    :type session: requests.session
    :param rhost: remote host
    :type rhost: string
    :param key_file: X.509 key file (PEM format) to upload
    :type key_file: string
    :param cert_file: X.509 certificate file (PEM format) to upload
    :type cert_file: string
    :rtype: bool
    """
    with open(cert_file, "rb") as file_handle:
        cert_data = file_handle.read()
    with open(key_file, "rb") as file_handle:
        key_data = file_handle.read()
    files = [
        ("new_certificate", ("cert.pem", cert_data, "application/octet-stream")),
        ("new_private_key", ("key.pem", key_data, "application/octet-stream"))
    ]

    upload_cert_url = rhost + UPLOAD_CERT_URL
    try:
        result = session.post(upload_cert_url, files=files, timeout=REQUEST_TIMEOUT, verify=False)
    except ConnectionError:
        return False
    if not result.ok:
        return False
    return True


def update_certificate(rhost, key_file, cert_file, username, password, verbosity=1):
    """
    Main function for updating the certificate on the remote IPMI host

    :param rhost: remote host
    :type rhost: string
    :param key_file: X.509 key file (PEM format) to upload
    :type key_file: string
    :param cert_file: X.509 certificate file (PEM format) to upload
    :type cert_file: string
    :param username: username used for IPMI authentication
    :type username: string
    :param password: password used for IPMI authentication
    :type password: string
    :param verbosity: verbosity level (0 = quiet, 1 = normal, 2 = verbose)
    :type verbosity: int
    :rtype: bool
    """

    # Remove trailing slash if it exists
    if rhost[-1] == "/":
        rhost = rhost[0:-1]

    # Check validity of files
    if not os.path.isfile(key_file):
        print("Private key file '%s' does not exist!" % key_file)
        return False
    if not os.path.isfile(cert_file):
        print("Certificate file '%s' does not exist!" % cert_file)
        return False
    # There doesn't seem to be any certificate handling in the Python standard libraries, so we just check the extension
    if not key_file.endswith(".pem"):
        print("Private key file '%s' may not be a PEM file!" % key_file)
        return False
    if not cert_file.endswith(".pem"):
        print("Certificate file '%s' may not be a PEM file!" % key_file)
        return False

    if verbosity == 2:
        # Enable request logging
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        request_logger = logging.getLogger("requests.packages.urllib3")
        request_logger.setLevel(logging.DEBUG)
        request_logger.propagate = True

    # Don't warn about not verifying certificates
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    # Start session
    session = requests.session()

    #  As login can take several seconds, we print a message to indicate the script is running
    if verbosity > 0:
        print("Connecting to %s." % rhost)

    # Log in
    if not login(session, rhost, username, password):
        print("Login failed!")
        return False
    elif verbosity > 0:
        print("Logged in.")

    # Get current certificate information
    cert_info = get_cert_info(session, rhost)
    if not cert_info:
        print("Could not get certificate information from IPMI!")
        # We don"t care if logout fails
        logout(session, rhost)
        return False
    elif verbosity > 0:
        print("The current certificate is valid until: %s" % cert_info["valid_till"])

    # Update certificate
    if not upload_cert(session, rhost, key_file, cert_file):
        print("Could not upload X.509 files to IPMI!")
        logout(session, rhost)
        return False

    if verbosity > 0:
        print("Certificate file has been uploaded.")

    cert_info = get_cert_info(session, rhost)
    if not cert_info:
        print("Could not get certificate information from IPMI!")
        logout(session, rhost)
        return False
    if verbosity > 0:
        print("After upload, the current certificate is valid until: %s" % cert_info["valid_till"])

    # Logout
    # This must happen within 2 seconds of the certificate update request, otherwise it fails for some reason (perhaps
    # due to certificate change/BMC soft reset). As we are at the end of the script, we don't care if logout fails as
    # we're done and the session will eventually expire.
    if not logout(session, rhost):
        print("Logout failed, ignoring.")
    elif verbosity > 0:
        print("Logged out.")

    return True


def update_certificate_config_file(config_file, verbosity=1):
    """
    Helper function for passing arguments using a configuration file

    :param config_file: path to configuration file
    :type config_file: string
    :param verbosity: verbosity level (0 = quiet, 1 = normal, 2 = verbose)
    :type verbosity: int
    :rtype: bool
    """
    if not os.path.isfile(config_file):
        print("Configuration file '%s' does not exist!" % config_file)
        return False
    config = configparser.ConfigParser()
    config.read(config_file)
    rhost = config['DEFAULT']['rhost']
    key_file = config['DEFAULT']['key-file']
    cert_file = config['DEFAULT']['cert-file']
    username = config['DEFAULT']['username']
    password = config['DEFAULT']['password']
    result = update_certificate(rhost, key_file, cert_file, username, password, verbosity)
    return result


def main():
    parser = argparse.ArgumentParser(description="Update ASRock Rack IPMI SSL certificate")
    # We can't nest argument groups or mutually exclusive groups, so we need to use subparsers to get the same effect.
    # The help output is less useful in this case though.
    subparsers = parser.add_subparsers()
    cli_parser = subparsers.add_parser("cli", help="specify arguments through the command-line")
    config_parser = subparsers.add_parser("config", help="specify arguments using a configuration file")

    cli_parser.add_argument("-r", "--rhost",
                            help="remote hostname or IP:port",
                            required=True)
    cli_parser.add_argument("-u", "--username",
                            help="username used for IPMI authentication",
                            required=True)
    cli_parser.add_argument("-p", "--password",
                            help="password used for IPMI authentication",
                            required=True)
    cli_parser.add_argument("--key-file",
                            help="X.509 private key filename",
                            required=True)
    cli_parser.add_argument("--cert-file",
                            help="X.509 certificate filename",
                            required=True)
    config_parser.add_argument("--config-file",
                               help="configuration file",
                               required=True)
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("-q", "--quiet",
                              help="quiet mode, suppresses output",
                              action="store_true")
    output_group.add_argument("-v", "--verbose",
                              help="verbose output",
                              action="store_true")
    args = parser.parse_args()

    # Set verbosity
    verbosity = 1
    if args.quiet:
        verbosity = 0
    if args.verbose:
        verbosity = 2
    if "config_file" in vars(args):
        config_file = args.config_file
        if not update_certificate_config_file(config_file, verbosity):
            # Exit with abnormal termination as script was not successful
            sys.exit(1)
    else:
        rhost = args.rhost
        key_file = args.key_file
        cert_file = args.cert_file
        username = args.username
        password = args.password
        if not update_certificate(rhost, key_file, cert_file, username, password, verbosity):
            sys.exit(1)


if __name__ == "__main__":
    main()
