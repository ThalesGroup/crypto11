// A demo program using a PKCS#11-protected key to authenticate a web server.
//
// To use with nShield PKCS#11, assuming an OCS-protected key:
//
//   generatekey -b pkcs11req protect=token type=rsa size=2048 plainname=demo \
//     selfcert=yes embedsavefile=hkey.pem digest=sha256 \
//     x509country=GB x509province=England x509locality=Rutland x509org=org x509orgunit=any \
//     x509dnscommon=www.example.com
//   CKNFAST_DEBUG=2 CRYPTO11_CONFIG_PATH=../configs/config.nshield go run server.go
//
// 'plainname' corresponds to CKA_LABEL.
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"io/ioutil"
	"log"
	"net/http"
)

var keyLabel = "demo"
var certFile = "hkey_selfcert.pem"

func useHardwareKey(config *tls.Config, keyLabel string, certFile string) error {
	var err error
	var cert tls.Certificate
	var certPEM []byte
	var certDER *pem.Block
	var certParsed *x509.Certificate
	var key crypto.PrivateKey

	// Load the certificate. What we really want was for
	// crypto.tls.X509KeyPair or crypto.tls.LoadX509KeyPair to
	// accept keyFile=nil, but they don't, so we have to load the
	// certificate manually.
	log.Printf("loading certificate %s", certFile)
	if certPEM, err = ioutil.ReadFile(certFile); err != nil {
		return err
	}
	for {
		if certDER, certPEM = pem.Decode(certPEM); certDER == nil {
			break
		}
		if certDER.Type != "CERTIFICATE" {
			return fmt.Errorf("%s: unexpected type %s", certFile, certDER.Type)
		}
		cert.Certificate = append(cert.Certificate, certDER.Bytes)
	}
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("%s: no certificates found", certFile)
	}
	// Load the private key.
	log.Printf("loading key CKA_LABEL=%s", keyLabel)
	if key, err = crypto11.FindKeyPair(nil, []byte(keyLabel)); err != nil {
		return err
	}
	cert.PrivateKey = key
	// Check that the key and the certificate match.
	if certParsed, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return err
	}
	switch certPubKey := certParsed.PublicKey.(type) {
	case *rsa.PublicKey:
		if keyPubKey, ok := key.(crypto.Signer).Public().(*rsa.PublicKey); ok {
			if certPubKey.E != keyPubKey.E || certPubKey.N.Cmp(keyPubKey.N) != 0 {
				return fmt.Errorf("%s: public key does not match CKA_LABEL=%s", certFile, keyLabel)
			}
		} else {
			return fmt.Errorf("%s: key type does not match CKA_LABEL=%s", certFile, keyLabel)
		}
	default:
		return fmt.Errorf("%s: key type not implemented", certFile)
	}
	// It's all good, update the configuration
	config.Certificates = []tls.Certificate{cert}
	return nil
}

func main() {
	http.Handle("/", http.FileServer(http.Dir("/usr/share/doc")))
	server := &http.Server{Addr: ":9090", TLSConfig: &tls.Config{}}
	if err := useHardwareKey(server.TLSConfig, keyLabel, certFile); err != nil {
		log.Fatal(err)
	}
	log.Printf("starting server on %s", server.Addr)
	log.Fatal(server.ListenAndServeTLS("", ""))
}
