

import flask

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from dnslib import RR, QTYPE, A

from acme_client import ACMEClient
from dns_server import ACME_DNSServer
from httpchallenge_server import  httpchallenge_server
import threading
from pathlib import Path
import argparse



#This method calls all the methods of the ACME client to obtain the certificate
def get_certificate(args):

    validate_urls = []
    # Create DNS server object
    dns_server = ACME_DNSServer(dns_records=[])
    # Start the HTTP challenge server
    threading.Thread(target=lambda: httpchallenge_server.run(
        host="0.0.0.0", port= 5002, debug=False, threaded=True), daemon=True).start()


    # Add the domain to the DNS server zone
    for domain in args.domain:
        dns_server.dns_records.append(RR(domain, QTYPE.A, rdata=A(args.record), ttl=300))





    # Create the ACME client and use the methods defined in acme_client.py
    acme_client = ACMEClient(args.dir, dns_server)

    acme_client.get_directory_urls()


    threading.Thread(target=dns_server.server.start, daemon=True).start()
    acme_client.get_account()


    certificate_order, order_url = acme_client.set_domains(args.domain)




    finalize_url = certificate_order["finalize"]

    for auth in certificate_order["authorizations"]:
        if args.challenge == "dns01" :
            certificate_authorization = acme_client.challenge_dns(auth, args.challenge)
        elif args.challenge == "http01":
            certificate_authorization = acme_client.http_challenge(auth, args.challenge)


        validate_urls.append(certificate_authorization["url"])

    for url in validate_urls:
        acme_client.validate_certificate(url)


    key, certificate = acme_client.get_certificate(order_url, finalize_url, args.domain)


    # Write certifcate and key to files with paths relatively to the file executing .

    with open(Path(__file__).parent.absolute() / "key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(Path(__file__).parent.absolute() / "cert.pem", "wb") as f:
        f.write(certificate)





    if args.revoke:
        acme_client.revoke_certificate(certificate)

    return key, certificate


# Shutdown server created inside the main script
httpshutdown_server = flask.Flask(__name__)
shutdown_event = threading.Event()



@httpshutdown_server.route('/shutdown')
def route_shutdown():
    threading.Timer(0.25, shutdown_event.set).start()
    return "Server shutting down"


def main():
    parser = argparse.ArgumentParser(description="NETSEC ACME Client ")
    parser.add_argument("challenge", choices=["dns01", "http01"])
    parser.add_argument("--dir", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--domain", action="append")
    parser.add_argument("--revoke", action="store_true")

    args = parser.parse_args()

    # Thread to the HTTP shutdown  server

    shutdown_thread = threading.Thread(target=lambda: httpshutdown_server.run(
        host="0.0.0.0", port=5003, debug=False, threaded=True), daemon=True)

    shutdown_thread.start()

    # Thread to obtain the certificate

    certificate_thread = threading.Thread(target=lambda: get_certificate(args))
    certificate_thread.start()

    certificate_thread.join()

    # Start HTTPS server to use the certificate
    https_server = flask.Flask(__name__)
    threading.Thread(target=lambda: https_server.run(
        host="0.0.0.0", port=5001, debug=False, threaded=True, ssl_context=(Path(__file__).parent.absolute() / "cert.pem", Path(__file__).parent.absolute() / "key.pem")), daemon=True).start()

    shutdown_event.wait()


if __name__ == "__main__":
    main()
