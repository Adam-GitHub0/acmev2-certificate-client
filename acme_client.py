from Crypto.Hash import SHA256
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import  json
import base64, time, hashlib
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


from dnslib import QTYPE, RR, TXT

from httpchallenge_server import register_http_challenge

import requests

from requests.adapters import HTTPAdapter


class ACMEClient():

    def __init__(self, directory_url, dns_server):






        self.directory_url = directory_url
        self.dns_server = dns_server

        # Required paramters in the JSON object in the ACME directory
        self.url_revoke_certificate = None
        self.url_get_nonce = None
        self.url_get_new_account = None
        self.url_get_new_order = None

        self.kid = None

        self.private_key = None
        self.signature = None

        self.client = requests.Session()
        self.jose_client = requests.Session()

        self.jose_client.headers.update(
            {"User-Agent": "acme-client", "Content-Type": "application/jose+json"})
        self.jose_client.mount('https://', HTTPAdapter(max_retries=0))
        self.client.headers.update({"User-Agent": "acme-client"})
        self.client.mount('https://', HTTPAdapter(max_retries=0))



        self.generate_keypair()







    # Method to create the account
    def get_account(self):
        protected_header = {
            "alg": "ES256",
            "jwk": self.create_jwk_object(),
            "nonce": self.get_nonce(),
            "url": self.url_get_new_account

        }

        payload = {
            "termsOfServiceAgreed": True,
        }

        protected_header_b64 = self.encode_b64(json.dumps(protected_header))
        payload_b64 = self.encode_b64(json.dumps(payload))

        # we sign the hash because that's how the DSS works (see documentation)

        signature = self.signature.sign(
            SHA256.new(f"{protected_header_b64}.{payload_b64}".encode('utf8')))

        jws = {
            "protected": protected_header_b64,
            "payload": payload_b64,
            "signature": self.encode_b64(signature)
        }

        # we send the jws to the server
        response = self.jose_client.post(self.url_get_new_account, json=jws)
        # Handle the response accordingly
        if response.status_code == 201:

            # Account created successfully, and we retrieve the kid to send it for next requests

            self.kid = response.headers["Location"]
            return response.json()
        else:
            # Handle error scenarios
            raise Exception(f"Account creation failed: {response.text}")






    def set_domains(self, domains):

        payload = {
            "identifiers": [{"type": "dns", "value": domain} for domain in domains]
        }
        encrypted_payload = self.jose_kid(self.url_get_new_order, payload)

        reply_server = self.jose_client.post(self.url_get_new_order, json=encrypted_payload)

        if reply_server.status_code == 201:
            return reply_server.json(), reply_server.headers["Location"]
        else:
            raise Exception(f"Order creation failed: {reply_server.text}")

    def challenge_dns(self, auth_url, dns_challenge):
        # page 54 of the ACME RFC
        # POST /acme/authz/PAniVnsZcis HTTP/1.1
        #  Host: example.com
        #  Content-Type: application/jose+json

        #  {
        #  "protected": base64url({
        #  "alg": "ES256",
        #  "kid": "https://example.com/acme/acct/evOfKhNU60wg",
        #  "nonce": "uQpSjlRb4vQVCjVYAyyUWg",
        #  "url": "https://example.com/acme/authz/PAniVnsZcis"
        #  }),
        #  "payload": "",
        #  "signature": "nuSDISbWG8mMgE7H...QyVUL68yzf3Zawps"
        #  }
        #  HTTP/1.1 200 OK
        #  Content-Type: application/json
        #  Link: <https://example.com/acme/directory>;rel="index"
        #  {
        #  "status": "pending",
        #  "expires": "2016-01-02T14:09:30Z",
        #  "identifier": {
        #  "type": "dns",
        #  "value": "www.example.org"
        #  },
        # "challenges": [
        #  {
        #  "type": "http-01",
        #  "url": "https://example.com/acme/chall/prV_B7yEyA4",
        #  "token": "DGyRejmCefe7v4NfDGDKfA"
        #  },
        #  {
        #  "type": "dns-01",
        #  "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
        #  "token": "DGyRejmCefe7v4NfDGDKfA"
        #  }
        #  ]
        #  }

        # The payload is empty as seen in the example above

        challenge_payload = self.jose_kid(auth_url, "")

        challenge_response = self.jose_client.post(auth_url, json=challenge_payload)  # this is like a post as get

        if challenge_response.status_code == 200:
            challenges = challenge_response.json()['challenges']

            for challenge in challenges:

                token = challenge["token"]
                key_authorization = self.set_key_authorization(token)

                if dns_challenge == "dns01" and challenge["type"] == "dns-01":
                    # A client fulfills this challenge by constructing a key authorization
                    #  from the "token" value provided in the challenge and the client’s
                    #  account key. The client then computes the SHA-256 digest [FIPS180-4]
                    #  of the key authorization.
                    #  The record provisioned to the DNS contains the base64url encoding of
                    #  this digest. The client constructs the validation domain name by
                    #  prepending the label "_acme-challenge" to the domain name being
                    #  validated, then provisions a TXT record with the digest value under
                    #  that name. For example, if the domain name being validated is
                    #  "www.example.org", then the client would provision the following DNS
                    #  record:
                    #  _acme-challenge.www.example.org. 300 IN TXT "gfj9Xq...Rg85nM


                    key_authorization = hashlib.sha256(
                        key_authorization.encode('utf8')).digest()  # I guess for efficiency issues (reduce the size )?
                    key_authorization_base64 = self.encode_b64(key_authorization)
                    domain_name = challenge_response.json()["identifier"]["value"]

                    domain = f"_acme-challenge.{domain_name}"

                    self.dns_server.dns_records.append(RR(domain, QTYPE.TXT, rdata=TXT(key_authorization_base64), ttl=300))



                    return challenge

    def http_challenge(self, auth_url, http_challenge):
        # page 54 of the ACME RFC
        # POST /acme/authz/PAniVnsZcis HTTP/1.1
        #  Host: example.com
        #  Content-Type: application/jose+json

        #  {
        #  "protected": base64url({
        #  "alg": "ES256",
        #  "kid": "https://example.com/acme/acct/evOfKhNU60wg",
        #  "nonce": "uQpSjlRb4vQVCjVYAyyUWg",
        #  "url": "https://example.com/acme/authz/PAniVnsZcis"
        #  }),
        #  "payload": "",
        #  "signature": "nuSDISbWG8mMgE7H...QyVUL68yzf3Zawps"
        #  }
        #  HTTP/1.1 200 OK
        #  Content-Type: application/json
        #  Link: <https://example.com/acme/directory>;rel="index"
        #  {
        #  "status": "pending",
        #  "expires": "2016-01-02T14:09:30Z",
        #  "identifier": {
        #  "type": "dns",
        #  "value": "www.example.org"
        #  },
        # "challenges": [
        #  {
        #  "type": "http-01",
        #  "url": "https://example.com/acme/chall/prV_B7yEyA4",
        #  "token": "DGyRejmCefe7v4NfDGDKfA"
        #  },
        #  {
        #  "type": "dns-01",
        #  "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
        #  "token": "DGyRejmCefe7v4NfDGDKfA"
        #  }
        #  ]
        #  }

        # The payload is empty as seen in the example above

        challenge_payload = self.jose_kid(auth_url, "")

        challenge_response = self.jose_client.post(auth_url, json=challenge_payload)  # this is like a post as get

        if challenge_response.status_code == 200:
            challenges = challenge_response.json()['challenges']

            for challenge in challenges:

                token = challenge["token"]
                key_authorization = self.set_key_authorization(token)


                if http_challenge == "http01" and challenge["type"] == "http-01":
                    register_http_challenge(token, key_authorization)
                    return challenge


    # Validate the certificate after the challenge
    def validate_certificate(self, validate_url):

        validate_payload = self.jose_kid(validate_url, {})


        validate_response = self.jose_client.post(validate_url, json=validate_payload)

        if validate_response.status_code == 200:

            validation_result = validate_response.json()
            return validation_result
        else:

            raise Exception(f"Validation request failed: {validate_response.status_code}, {validate_response.text}")



    def get_certificate(self, order_url, finalize_url, domains):
        # POST / acme / order / TOlocE8rfgo / finalize
        # HTTP / 1.1
        # Host: example.com
        # Content - Type: application / jose + json
        # {
        #     "protected": base64url({
        #         "alg": "ES256",
        #         "kid": "https://example.com/acme/acct/evOfKhNU60wg",
        #         "nonce": "MSF2j2nawWHPxxkE3ZJtKQ",
        #         "url": "https://example.com/acme/order/TOlocE8rfgo/finalize"
        #     }),
        #     "payload": base64url({
        #         "csr": "MIIBPTCBxAIBADBFMQ...FS6aKdZeGsysoCo4H9P",
        #     }),
        #     "signature": "uOrUfIIk5RyQ...nw62Ay1cl6AB"
        # }
        while 1:
            poll_payload = self.jose_kid(order_url, "")
            poll_request = self.jose_client.post(order_url, "", json=poll_payload)

            if poll_request.status_code == 200:

                current_status_json = poll_request.json()
                current_status = current_status_json.get('status')

                if current_status in ["ready", "processing", "valid"]:
                    order_status = current_status_json
                    break
                elif current_status in ["invalid"]:
                    order_status = False
                    break
            time.sleep(1)


        if not order_status:
            return False

        if order_status["status"] == "ready" or order_status["status"] == "processing" or order_status["status"] == "valid":


            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ETH ACME Client"),
            ])).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain)
                                             for domain in domains]),
                critical=False,
            ).sign(private_key, hashes.SHA256())

            der = csr.public_bytes(serialization.Encoding.DER)




            b64_csr = self.encode_b64(der)

            finalize_payload = {
                    "csr": b64_csr
                }


            encrypted_finalize_payload = self.jose_kid(finalize_url, finalize_payload)


            finalize_response = self.jose_client.post(finalize_url, json=encrypted_finalize_payload)

            if finalize_response.status_code == 200:

                    while 1:
                        poll_payload = self.jose_kid(order_url, "")
                        poll_request = self.jose_client.post(order_url, "", json=poll_payload)

                        if poll_request.status_code == 200:

                            current_status_json = poll_request.json()
                            current_status = current_status_json.get('status')

                            if current_status in ["valid"]:
                                jose_request_object = current_status_json
                                break
                            elif current_status in ["ready", "invalid", "pending"]:
                                jose_request_object = False
                                break
                        time.sleep(1)



                    if jose_request_object:
                        url_to_download_certificate = jose_request_object["certificate"]

                        encrypted_download_payload = self.jose_kid(url_to_download_certificate, "")

                        # Download the certificate
                        certificate_response = self.jose_client.post(url_to_download_certificate,
                                                                     json=encrypted_download_payload)
                        if certificate_response.status_code == 200:
                            # Return the certificate and the private key of the client
                            return  private_key ,certificate_response.content
                        else:
                            raise Exception(f"Failed to download the certificate: {certificate_response.text}")
                    else:
                        return None
            else:
                    raise Exception(f"Finalization failed: {finalize_response.text}")



    def revoke_certificate(self, certificate):
        # takes a certificate in PEM format, converts it to an X509 certificate object, and then serializes this object into DER format .
        cert = x509.load_pem_x509_certificate(certificate).public_bytes(serialization.Encoding.DER)

        encoded_certificate = self.encode_b64(cert)
        payload = {
            "certificate": encoded_certificate
        }
        jose_payload = self.jose_kid(self.url_revoke_certificate, payload)

        response = self.jose_client.post(self.url_revoke_certificate, json=jose_payload)
        if response.status_code == 200:
            return response.content







#################################################################################################################
# Utilitary functions :

    def generate_keypair(self):

        # private key with the curve p256
        self.private_key = ECC.generate(curve="p256")
        # or maybe
        # self.key=ec.generate_private_key(ec.SECP384R1())

        # object for signing the messages
        self.signature = DSS.new(self.private_key, "fips-186-3")


    def encode_b64(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')  # Convert string to bytes
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip(
            '=')  # see if you should switch order decode and rstrip

    # Get the values from the root ACME directory
    def get_directory_urls(self):



            response = self.client.get(self.directory_url)
            response.raise_for_status()  # Raise an HTTPError if the HTTP request returned an unsuccessful status code

            directory = response.json()

            # Set the various service endpoints using the directory information
            self.url_get_nonce = directory['newNonce']
            self.url_get_new_account = directory['newAccount']
            self.url_get_new_order = directory['newOrder']
            self.url_revoke_certificate = directory['revokeCert']




            return directory


    def create_jwk_object(self):
        # The two coordinates
        x = self.private_key.pointQ.x.to_bytes()
        y = self.private_key.pointQ.y.to_bytes()

        jwk_object = {
            "crv": "P-256",
            "kid": "1",
            # The account URL is used as the "kid" value in the JWS authenticating subsequent requests by this account(see Section 6.2).
            "kty": "EC",
            "x": self.encode_b64(x),
            "y": self.encode_b64(y),
        }

        return jwk_object

    def get_nonce(self):
        if self.url_get_nonce is None:
            raise ValueError("Nonce URL is missing. Have you fetched the directory my friend?")

        response = self.client.head(self.url_get_nonce)

        # Check for success status codes and presence of 'Replay-Nonce' header
        if response.status_code in (200, 204) and "Replay-Nonce" in response.headers:
            nonce = response.headers["Replay-Nonce"]
            return nonce
        else:
            # Handle unexpected status codes and missing nonce header
            error_message = f"Failed to get nonce, status code: {response.status_code}"
            if "Replay-Nonce" not in response.headers:
                error_message += ", 'Replay-Nonce' header is missing"
            raise Exception(error_message)

    def set_key_authorization(self, token):

        jwk_key =  {
            "crv": "P-256",
            "kty": "EC",
            "x": self.encode_b64(self.private_key.pointQ.x.to_bytes()),
            "y": self.encode_b64(self.private_key.pointQ.y.to_bytes()),
        }

        jwk_json = json.dumps(jwk_key, sort_keys=True, separators=(',', ':'))

        # Compute the SHA-256 digest of the JWK
        thumbprint = hashlib.sha256(jwk_json.encode('utf8')).digest()

        # Base64url encode the thumbprint
        thumbprint_b64url = self.encode_b64(thumbprint)

        # Construct the key authorization string
        key_authorization = f"{token}.{thumbprint_b64url}"

        return key_authorization
    def jose_kid(self, url, payload):


        protected_header = {
            "alg": "ES256",
            "kid": self.kid,
            "nonce": self.get_nonce(),
            "url": url

        }

        # Encode the protected header to Base64 URL format
        encoded_protected = self.encode_b64(json.dumps(protected_header))

        # Payload can be an empty string if there is no payload for the request
        # otherwise, it should be Base64 URL encoded.
        encoded_payload = "" if payload == "" else self.encode_b64(json.dumps(payload))

        # Compute the signature using the private key associated with 'kid'
        # Assuming 'self.signing_alg' is the DSS object holding your private key
        signature = self.signature.sign(
            SHA256.new(f"{encoded_protected}.{encoded_payload}".encode('utf8'))
        )

        # Create the JOSE object
        jose_object = {
            "protected": encoded_protected,
            "payload": encoded_payload,
            "signature": self.encode_b64(signature)
        }

        return jose_object


