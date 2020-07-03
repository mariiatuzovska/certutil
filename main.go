package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var (
	host         = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFrom    = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor     = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	isCA         = flag.Bool("ca", false, "Extended key usage: this cert should be its own Certificate Authority")
	isServer     = flag.Bool("server", false, "Extended key usage: this cert will be used for server authentication")
	isClient     = flag.Bool("client", false, "Extended key usage: this cert will be used for client authentication")
	derCert      = flag.Bool("der", false, "Whether this cert should be der encoded (default pem format)")
	rsaBits      = flag.Int("rsa", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve   = flag.String("ecdsa", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
	certFile     = flag.String("cert-fn", "", "Path to certificate file. Writes certificate by path")
	keyFile      = flag.String("key-fn", "", "Path to key file. Writes key by path")
	organization = flag.String("o", "", "Organization name")
	commonName   = flag.String("cn", "", "Common name")
	parentKey    = flag.String("parent-key-fn", "", "Path to parent key file")
	parencCert   = flag.String("parent-cert-fn", "", "Path to parent certificate file")
	derToPem     = flag.Bool("der-to-pem", false, "Encode from der to pem")
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func main() {

	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		log.Fatalln("Path to cert and key files must be not null")
	}
	if *derToPem {
		derCrt, err := ioutil.ReadFile(*certFile)
		if err != nil {
			log.Fatalln("Failed to read certificate:", err)
		}
		_, err = x509.ParseCertificate(derCrt)
		if err != nil {
			log.Fatalln("Failed to parse certificate:", err)
		}
		derKey, err := ioutil.ReadFile(*keyFile)
		if err != nil {
			log.Fatalln("Failed to read key:", err)
		}
		_, err = x509.ParsePKCS8PrivateKey(derKey)
		if err != nil {
			log.Fatalln("Failed to parse key:", err)
		}
		certOut, err := os.OpenFile(*certFile+".pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Failed to open %s for writing: %v", *certFile, err)
		}
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derCrt}); err != nil {
			log.Fatalf("Failed to write data to %s: %v", *certFile, err)
		}
		if err := certOut.Close(); err != nil {
			log.Fatalf("Error closing %s: %v", *certFile, err)
		}
		log.Println(fmt.Sprintf("wrote pem encoded %s", *certFile+".pem"))
		keyOut, err := os.OpenFile(*keyFile+".pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Failed to open %s for writing: %v", *keyFile, err)
			return
		}
		if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: derKey}); err != nil {
			log.Fatalf("Failed to write data to %s: %v", *keyFile, err)
		}
		if err := keyOut.Close(); err != nil {
			log.Fatalf("Error closing %s: %v", *keyFile, err)
		}
		log.Println(fmt.Sprintf("wrote pem encoded %s", *keyFile+".pem"))
		return
	}
	if *host == "" && !*isCA {
		log.Fatalln("Host flag must be defined")
	}
	if *organization == "" {
		log.Fatalln("Subject name error: organization unit must be not null")
	}
	if *commonName == "" {
		log.Fatalln("Subject name error: common name must be not null")
	}
	if !*isCA && !*isClient && !*isServer {
		log.Fatalln("Extended key usage must be defined")
	}

	var priv interface{}
	var err error
	switch *ecdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, *rsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		log.Fatalln("Unrecognized elliptic curve:", *ecdsaCurve)
	}
	if err != nil {
		log.Fatalln("Failed to generate private key:", err)
	}

	var notBefore time.Time
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2021", *validFrom)
		if err != nil {
			log.Fatalln("Failed to parse creation date:", err)
		}
	}

	notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalln("Failed to generate serial number:", err)
	}
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		Subject: pkix.Name{
			Organization: []string{*organization},
			Country:      []string{"UA"},
			Locality:     []string{"Kyiv"},
			SerialNumber: "UA-" + serialNumber.String(),
			CommonName:   *commonName,
		},
	}

	if *isCA {
		log.Printf("Certificate will be created as CA\n")
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature
		if len(*host) != 0 {
			hosts := strings.Split(*host, ",")
			for _, h := range hosts {
				if ip := net.ParseIP(h); ip != nil {
					template.IPAddresses = append(template.IPAddresses, ip)
				} else {
					template.DNSNames = append(template.DNSNames, h)
				}
			}
		}
	}

	if *isServer {
		log.Printf("Certificate will be created with extended key usage for server authentication\n")
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	if *isClient {
		log.Printf("Certificate will be created with extended key usage for client authentication\n")
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	var derBytes []byte

	if *parentKey != "" && *parencCert != "" {
		parentCertBytes, err := ioutil.ReadFile(*parencCert)
		if err != nil {
			log.Fatalln("Failed to read parent certificate:", err)
		}
		parentCert, err := x509.ParseCertificate(parentCertBytes)
		if err != nil {
			block, _ := pem.Decode(parentCertBytes)
			if block == nil || block.Type != "CERTIFICATE" {
				log.Fatalln("Failed to decode parent certificate pem block")
			}
			parentCert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Fatalln("Failed to read parent certificate:", err)
			}
		}
		parentKeyBytes, err := ioutil.ReadFile(*parentKey)
		if err != nil {
			log.Fatalln("Failed to read parent key:", err)
		}
		parentKeyData, err := x509.ParsePKCS8PrivateKey(parentKeyBytes)
		if err != nil {
			data, _ := pem.Decode(parentKeyBytes)
			rsaParentKey, err := x509.ParsePKCS1PrivateKey(data.Bytes)
			if err != nil {
				ecParentKey, err := x509.ParseECPrivateKey(data.Bytes)
				if err != nil {
					parentKeyData, err = x509.ParsePKCS8PrivateKey(parentKeyBytes)
					if err != nil {
						log.Fatalln("Failed to parse parent key:", err,
							". Try to do this with der encoded parent private key!\n",
							"For example: $openssl rsa -noout -text -inform DER -in private.der")
					}
					log.Printf("Parent key %s has been parsed from pem as PKCS8 private key\n", *parentKey)
				} else {
					parentKeyData = ecParentKey
					log.Printf("Parent key %s has been parsed from pem as EC private key\n", *parentKey)
				}
			} else {
				parentKeyData = rsaParentKey
				log.Printf("Parent key %s has been parsed from pem as PKCS1 private key\n", *parentKey)
			}
		} else {
			log.Printf("Parent key %s has been parsed from pem as PKCS8 private key\n", *parentKey)
		}
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, parentCert, publicKey(priv), parentKeyData)
		if err != nil {
			log.Fatalln("Failed to create certificate:", err)
		}
		log.Printf("Certificate is created as signed by %s parent\n", *parencCert)
	} else {
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
		if err != nil {
			log.Fatalln("Failed to create certificate:", err)
		}
		log.Println("Certificate is created as self-signed")
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}

	if *derCert {

		err = ioutil.WriteFile(*certFile, derBytes, os.ModePerm)
		if err != nil {
			log.Fatalln("Failed to create der encoded certificate file:", err)
		}
		log.Println(fmt.Sprintf("wrote der encoded %s", *certFile))
		err = ioutil.WriteFile(*keyFile, privBytes, os.ModePerm)
		if err != nil {
			log.Fatalln("Failed to create der encoded key file:", err)
		}
		log.Println(fmt.Sprintf("wrote der encoded %s", *keyFile))

	} else {

		certOut, err := os.Create(*certFile)
		if err != nil {
			log.Fatalf("Failed to open %s for writing: %v", *certFile, err)
		}
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
			log.Fatalf("Failed to write data to %s: %v", *certFile, err)
		}
		if err := certOut.Close(); err != nil {
			log.Fatalf("Error closing %s: %v", *certFile, err)
		}
		log.Println(fmt.Sprintf("wrote pem encoded %s", *certFile))
		keyOut, err := os.OpenFile(*keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Failed to open %s for writing: %v", *keyFile, err)
			return
		}
		if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
			log.Fatalf("Failed to write data to %s: %v", *keyFile, err)
		}
		if err := keyOut.Close(); err != nil {
			log.Fatalf("Error closing %s: %v", *keyFile, err)
		}
		log.Println(fmt.Sprintf("wrote pem encoded %s", *keyFile))
	}
}
