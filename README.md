# Various scripts for working with Let's Encrypt

This repository contains various scripts written to support Let's Encrypt certificates on non-traditional platforms (such as IPMI controllers).

# asrock_ipmi_cert_updater

asrock_ipmi_cert_updater.py is a Python script that lets you update the IPMI certificate on ASRock Rack motherboards. This works with the ASRock Rack X470D4U motherboard, but has not been tested with any other motherboard.

## Usage
`> python asrock_ipmi_cert_updater.py cli --rhost https://www.example.com --username myusername --password mypassword --cert-file fullchain.pem --key-file privkey.pem`

`> python asrock_ipmi_cert_updater.py config --config-file asrock_ipmi_cert_updater.ini`

asrock_ipmi_cert_updater.ini.example shows an example INI configuration file.

tests\test_asrock_ipmi_cert_updater.py is an example script to test the Python module functionality of asrock_ipmi_cert_updater.py.

# cert_updater

cert_updater.py is a Python script that can be called by CertBot upon successful renewal of a certificate.

## Usage
`> certbot renew --deploy-hook 'python cert_updater.py'`