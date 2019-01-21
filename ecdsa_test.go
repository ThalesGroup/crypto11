// Copyright 2016, 2017 Thales e-Security, Inc
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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"github.com/stretchr/testify/require"
	"testing"
)

var curves = []elliptic.Curve{
	elliptic.P224(),
	elliptic.P256(),
	elliptic.P384(),
	elliptic.P521(),
	// plus something with explicit parameters
}

func TestNativeECDSA(t *testing.T) {
	var err error
	var key *ecdsa.PrivateKey
	for _, curve := range curves {
		if key, err = ecdsa.GenerateKey(curve, rand.Reader); err != nil {
			t.Errorf("crypto.ecdsa.GenerateKey: %v", err)
			return
		}
		testEcdsaSigning(t, key, crypto.SHA1)
		testEcdsaSigning(t, key, crypto.SHA224)
		testEcdsaSigning(t, key, crypto.SHA256)
		testEcdsaSigning(t, key, crypto.SHA384)
		testEcdsaSigning(t, key, crypto.SHA512)
	}
}

func TestHardECDSA(t *testing.T) {
	var key *PKCS11PrivateKeyECDSA
	var key2, key3 crypto.PrivateKey
	var id, label []byte
	_, err := ConfigureFromFile("config")
	require.NoError(t, err)

	for _, curve := range curves {
		if key, err = GenerateECDSAKeyPair(curve); err != nil {
			t.Errorf("GenerateECDSAKeyPair: %v", err)
			return
		}
		if key == nil {
			t.Errorf("crypto11.dsa.GenerateECDSAKeyPair: returned nil but no error")
			return
		}
		testEcdsaSigning(t, key, crypto.SHA1)
		testEcdsaSigning(t, key, crypto.SHA224)
		testEcdsaSigning(t, key, crypto.SHA256)
		testEcdsaSigning(t, key, crypto.SHA384)
		testEcdsaSigning(t, key, crypto.SHA512)
		// Get a fresh handle to  the key
		if id, label, err = key.Identify(); err != nil {
			t.Errorf("crypto11.ecdsa.PKCS11PrivateKeyECDSA.Identify: %v", err)
			return
		}
		if key2, err = FindKeyPair(id, nil); err != nil {
			t.Errorf("crypto11.ecdsa.FindECDSAKeyPair by id: %v", err)
			return
		}
		testEcdsaSigning(t, key2.(*PKCS11PrivateKeyECDSA), crypto.SHA256)
		if key3, err = FindKeyPair(nil, label); err != nil {
			t.Errorf("crypto11.ecdsa.FindKeyPair by label: %v", err)
			return
		}
		testEcdsaSigning(t, key3.(crypto.Signer), crypto.SHA384)
	}
	require.NoError(t, Close())
}

func testEcdsaSigning(t *testing.T, key crypto.Signer, hashFunction crypto.Hash) {
	var err error
	var sigDER []byte
	var sig dsaSignature

	plaintext := []byte("sign me with ECDSA")
	h := hashFunction.New()
	h.Write(plaintext)
	plaintextHash := h.Sum([]byte{}) // weird API
	if sigDER, err = key.Sign(rand.Reader, plaintextHash, nil); err != nil {
		t.Errorf("ECDSA Sign (hash %v): %v", hashFunction, err)
		return
	}
	if err = sig.unmarshalDER(sigDER); err != nil {
		t.Errorf("ECDSA unmarshalDER (hash %v): %v", hashFunction, err)
		return
	}
	ecdsaPubkey := key.Public().(crypto.PublicKey).(*ecdsa.PublicKey)
	if !ecdsa.Verify(ecdsaPubkey, plaintextHash, sig.R, sig.S) {
		t.Errorf("ECDSA Verify (hash %v): %v", hashFunction, err)
	}

}
