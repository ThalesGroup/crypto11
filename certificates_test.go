// Copyright 2018 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package crypto11

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificate(t *testing.T) {
	skipTest(t, skipTestCert)

	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	id := randomBytes()
	label := randomBytes()

	cert := generateRandomCert(t, nil, "Foo", nil, nil)

	err = ctx.ImportCertificateWithLabel(id, label, cert)
	require.NoError(t, err)

	cert2, err := ctx.FindCertificate(nil, label, nil)
	require.NoError(t, err)
	require.NotNil(t, cert2)

	assert.Equal(t, cert.Signature, cert2.Signature)

	cert2, err = ctx.FindCertificate(nil, []byte("test2"), nil)
	require.NoError(t, err)
	assert.Nil(t, cert2)

	cert2, err = ctx.FindCertificate(nil, nil, cert.SerialNumber)
	require.NoError(t, err)
	require.NotNil(t, cert2)

	assert.Equal(t, cert.Signature, cert2.Signature)
}

// Test that provided attributes override default values
func TestCertificateAttributes(t *testing.T) {
	skipTest(t, skipTestCert)

	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	cert := generateRandomCert(t, nil, "Foo", nil, nil)

	// We import this with a different serial number, to test this is obeyed
	ourSerial := new(big.Int)
	ourSerial.Add(cert.SerialNumber, big.NewInt(1))

	derSerial, err := asn1.Marshal(ourSerial)
	require.NoError(t, err)

	template := NewAttributeSet()
	err = template.Set(CkaSerialNumber, derSerial)
	require.NoError(t, err)

	err = ctx.ImportCertificateWithAttributes(template, cert)
	require.NoError(t, err)

	// Try to find with old serial
	c, err := ctx.FindCertificate(nil, nil, cert.SerialNumber)
	assert.Nil(t, c)

	// Find with new serial
	c, err = ctx.FindCertificate(nil, nil, ourSerial)
	assert.NotNil(t, c)
}

func TestCertificateRequiredArgs(t *testing.T) {
	skipTest(t, skipTestCert)

	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	cert := generateRandomCert(t, nil, "Foo", nil, nil)

	val := randomBytes()

	err = ctx.ImportCertificateWithLabel(nil, val, cert)
	require.Error(t, err)

	err = ctx.ImportCertificateWithLabel(val, nil, cert)
	require.Error(t, err)

	err = ctx.ImportCertificateWithLabel(val, val, nil)
	require.Error(t, err)
}

func TestDeleteCertificate(t *testing.T) {
	skipTest(t, skipTestCert)

	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	randomCert := func() ([]byte, []byte, *x509.Certificate) {
		id := randomBytes()
		label := randomBytes()
		cert := generateRandomCert(t, nil, "Foo", nil, nil)
		return id, label, cert
	}
	importCertificate := func() ([]byte, []byte, *big.Int) {
		id, label, cert := randomCert()
		err = ctx.ImportCertificateWithLabel(id, label, cert)
		require.NoError(t, err)

		cert2, err := ctx.FindCertificate(id, label, cert.SerialNumber)
		require.NoError(t, err)
		require.NotNil(t, cert2)
		assert.Equal(t, cert.Signature, cert2.Signature)

		return id, label, cert.SerialNumber
	}

	err = ctx.DeleteCertificate(nil, nil, nil)
	require.Error(t, err)

	id, label, cert := randomCert()
	err = ctx.DeleteCertificate(id, label, cert.SerialNumber)
	require.NoError(t, err)

	id, label, serial := importCertificate()
	err = ctx.DeleteCertificate(id, label, serial)
	require.NoError(t, err)

	cert, err = ctx.FindCertificate(id, label, serial)
	require.NoError(t, err)
	require.Nil(t, cert)

	id, label, serial = importCertificate()
	err = ctx.DeleteCertificate(id, label, nil)
	require.NoError(t, err)

	cert, err = ctx.FindCertificate(id, label, serial)
	require.NoError(t, err)
	require.Nil(t, cert)

	id, label, serial = importCertificate()
	err = ctx.DeleteCertificate(id, nil, nil)
	require.NoError(t, err)

	cert, err = ctx.FindCertificate(id, label, serial)
	require.NoError(t, err)
	require.Nil(t, cert)

	id, label, serial = importCertificate()
	err = ctx.DeleteCertificate(nil, label, nil)
	require.NoError(t, err)

	cert, err = ctx.FindCertificate(id, label, serial)
	require.NoError(t, err)
	require.Nil(t, cert)

	id, label, serial = importCertificate()
	err = ctx.DeleteCertificate(nil, nil, serial)
	require.NoError(t, err)

	cert, err = ctx.FindCertificate(id, label, serial)
	require.NoError(t, err)
	require.Nil(t, cert)
}

func TestCertificateChain(t *testing.T) {
	skipTest(t, skipTestCert)

	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	certNames := []string{"Cert0", "Cert1", "Cert2"}

	var (
		parent                       *x509.Certificate
		originCertChain              []*x509.Certificate
		authorityKeyId, subjectKeyID []byte
		ids                          [][]byte
	)

	for _, name := range certNames {
		subjectKeyID = randomBytes()

		cert := generateRandomCert(t, parent, name, authorityKeyId, subjectKeyID)

		id := randomBytes()
		ids = append([][]byte{id}, ids...)

		err = ctx.ImportCertificate(id, cert)
		require.NoError(t, err)

		originCertChain = append([]*x509.Certificate{cert}, originCertChain...)

		parent = cert
		authorityKeyId = subjectKeyID
	}

	foundCertChain, err := ctx.FindCertificateChain(ids[0], nil, nil)
	require.NoError(t, err)
	require.NotNil(t, foundCertChain)

	assert.Equal(t, len(foundCertChain), len(originCertChain))

	for i := 0; i < len(foundCertChain); i++ {
		assert.Equal(t, foundCertChain[i].Signature, originCertChain[i].Signature)
	}

	err = ctx.DeleteCertificate(ids[len(ids)-1], nil, nil)
	require.NoError(t, err)

	oldCert := originCertChain[len(originCertChain)-1]
	newCert := generateRandomCert(t, nil, "NewCert", oldCert.AuthorityKeyId, oldCert.SubjectKeyId)

	originCertChain[len(originCertChain)-1] = newCert

	id := randomBytes()

	err = ctx.ImportCertificate(id, newCert)
	require.NoError(t, err)

	ids[len(ids)-1] = id

	foundCertChain, err = ctx.FindCertificateChain(ids[0], nil, nil)
	require.NoError(t, err)
	require.NotNil(t, foundCertChain)

	assert.Equal(t, len(foundCertChain), len(originCertChain))

	for i := 0; i < len(foundCertChain); i++ {
		assert.Equal(t, foundCertChain[i].Signature, originCertChain[i].Signature)
	}

	for _, id := range ids {
		err = ctx.DeleteCertificate(id, nil, nil)
		require.NoError(t, err)
	}

	foundCertChain, err = ctx.FindCertificateChain([]byte("test2"), nil, nil)
	require.NoError(t, err)
	assert.Nil(t, foundCertChain)
}

func generateRandomCert(t *testing.T, parent *x509.Certificate, commonName string,
	authorityKeyId, subjectKeyID []byte) *x509.Certificate {
	serial, err := rand.Int(rand.Reader, big.NewInt(20000))
	require.NoError(t, err)

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		AuthorityKeyId:        authorityKeyId,
		SubjectKeyId:          subjectKeyID,
		SerialNumber:          serial,
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	if parent == nil {
		parent = template
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	csr := &key.PublicKey
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, csr, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	return cert
}
