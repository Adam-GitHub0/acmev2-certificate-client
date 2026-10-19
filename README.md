# ACMEv2 certificate client

A Python implementation of [ACMEv2 (RFC 8555)](https://www.rfc-editor.org/rfc/rfc8555) from ETH Zürich's [Network Security course (Autumn 2023)](https://netsec.ethz.ch/courses/netsec-2023/).

The client signs JOSE/JWS requests with an ECDSA P-256 account key, completes `dns-01` or `http-01` challenges, requests certificates for multiple domains and wildcard names, and can revoke a certificate. The project includes local DNS and HTTP challenge servers and an HTTPS server that presents the issued certificate chain.

## Run locally

Use Python 3.11 and an ACME test server such as Pebble configured to reach the challenge ports. The included `pebble.minica.pem` is Pebble's test CA certificate.

```bash
./compile
./run dns01 --dir https://localhost:14000/dir --record 127.0.0.1 --domain example.test
```

Use `http01` instead of `dns01` for HTTP validation, repeat `--domain` for a certificate with multiple names, and add `--revoke` to revoke the issued certificate. The course test setup uses UDP `10053` for DNS and TCP `5002` for HTTP challenges; the HTTPS and shutdown endpoints use TCP `5001` and `5003`.
