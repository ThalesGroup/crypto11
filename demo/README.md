Demo Program
============

A demo program using a PKCS#11-protected key to authenticate a web server.

To use with nShield PKCS#11, assuming an OCS-protected key:

    generatekey -b pkcs11req protect=token type=rsa size=2048 plainname=demo \
      selfcert=yes embedsavefile=hkey.pem digest=sha256 \
      x509country=GB x509province=England x509locality=Rutland x509org=org x509orgunit=any \
      x509dnscommon=www.example.com
    CKNFAST_DEBUG=2 CRYPTO11_CONFIG_PATH=../configs/config.nshield go run server.go

`plainname` corresponds to CKA_LABEL.
