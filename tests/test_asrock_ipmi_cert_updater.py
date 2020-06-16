# This script tests the python module functionality of asrock_ipmi_cert_updater

import sys
import asrock_ipmi_cert_updater


def main():
    if len(sys.argv) != 2:
    	print("test_asrock_ipmi_cert_updater.py {cli|config}")
    	sys.exit(1)
    if sys.argv[1] == "cli":
        rhost = "https://www.example.com"
        key_file = "/etc/letsencrypt/live/www.example.com/privkey.pem"
        cert_file = "/etc/letsencrypt/live/www.example.com/fullchain.pem"
        username = "myusername"
        password = "mypassword"
        verbosity = 1
        asrock_ipmi_cert_updater.update_certificate(rhost, key_file, cert_file, username, password, verbosity)
    elif sys.argv[1] == "config":
        config_file = "asrock_ipmi_cert_updater.ini"
        verbosity = 1
        asrock_ipmi_cert_updater.update_certificate_config_file(config_file, verbosity)


if __name__ == "__main__":
    main()
