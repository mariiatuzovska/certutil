# certutil
*Generating certificates for a TLS server*

```
Usage of ./certutil:
  -ca
        Whether this cert should be its own Certificate Authority
  -cert-fn string
        Path to certificate file. Writes certificate by path
  -cn string
        Common name
  -der
        Whether this cert should be der encoded (default pem format)
  -duration duration
        Duration that certificate is valid for (default 8760h0m0s)
  -ecdsa string
        ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521
  -host string
        Comma-separated hostnames and IPs to generate a certificate for
  -key-fn string
        Path to key file. Writes key by path
  -o string
        Organization name
  -parent-cert-fn string
        Path to parent certificate file
  -parent-key-fn string
        Path to parent key file
  -rsa int
        Size of RSA key to generate. Ignored if --ecdsa-curve is set (default 2048)
  -start-date string
        Creation date formatted as Jan 1 15:04:05 2011
  ```
