# Launch various certificate update scripts based on what CertBot renewed

import os
import subprocess


def main():
    # "certbot renew --deploy-hook" provides a RENEWED_LINEAGE shell variable containing the folder path for successful renewals
    lineage = os.environ.get("RENEWED_LINEAGE")
    if lineage.endswith("/www.example.com"):
        subprocess.run(["python3",
            "/root/asrock_ipmi_cert_updater.py",
            "config",
            "--config-file",
            "/root/.secrets/asrock_ipmi_cert_updater.ini"])


if __name__ == "__main__":
        main()
