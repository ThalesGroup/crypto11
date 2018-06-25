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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"testing"
)

var rsaSizes = []int{1024, 2048}

func TestNativeRSA(t *testing.T) {
	var err error
	var key *rsa.PrivateKey
	for _, nbits := range rsaSizes {
		if key, err = rsa.GenerateKey(rand.Reader, nbits); err != nil {
			t.Errorf("crypto.rsa.GenerateKey: %v", err)
			return
		}
		if err = key.Validate(); err != nil {
			t.Errorf("crypto.rsa.PrivateKey.Validate: %v", err)
			return
		}
		testRsaSigning(t, key, nbits)
		testRsaEncryption(t, key, nbits)
	}
}

func TestHardRSA(t *testing.T) {
	var err error
	var key *PKCS11PrivateKeyRSA
	var key2, key3 crypto.PrivateKey
	var id, label []byte
	ConfigureFromFile("config")
	for _, nbits := range rsaSizes {
		if key, err = GenerateRSAKeyPair(nbits); err != nil {
			t.Errorf("crypto11.GenerateRSAKeyPair: %v", err)
			return
		}
		if key == nil {
			t.Errorf("crypto11.dsa.GenerateRSAKeyPair: returned nil but no error")
			return
		}
		if err = key.Validate(); err != nil {
			t.Errorf("crypto11.rsa.PKCS11PrivateKeyRSA.Validate: %v", err)
			return
		}
		testRsaSigning(t, key, nbits)
		testRsaEncryption(t, key, nbits)
		// Get a fresh handle to  the key
		if id, label, err = key.Identify(); err != nil {
			t.Errorf("crypto11.rsa.PKCS11PrivateKeyRSA.Identify: %v", err)
			return
		}
		if key2, err = FindKeyPair(id, nil); err != nil {
			t.Errorf("crypto11.rsa.FindRSAKeyPair by id: %v", err)
			return
		}
		testRsaSigning(t, key2.(*PKCS11PrivateKeyRSA), nbits)
		if key3, err = FindKeyPair(nil, label); err != nil {
			t.Errorf("crypto11.rsa.FindKeyPair by label: %v", err)
			return
		}
		testRsaSigning(t, key3.(crypto.Signer), nbits)
	}
}

func testRsaSigning(t *testing.T, key crypto.Signer, nbits int) {
	testRsaSigningPKCS1v15(t, key, crypto.SHA1)
	testRsaSigningPKCS1v15(t, key, crypto.SHA224)
	testRsaSigningPKCS1v15(t, key, crypto.SHA256)
	testRsaSigningPKCS1v15(t, key, crypto.SHA384)
	testRsaSigningPKCS1v15(t, key, crypto.SHA512)
	testRsaSigningPSS(t, key, crypto.SHA1)
	testRsaSigningPSS(t, key, crypto.SHA224)
	testRsaSigningPSS(t, key, crypto.SHA256)
	testRsaSigningPSS(t, key, crypto.SHA384)
	if nbits > 1024 { // key too smol for SHA512 with sLen=hLen
		testRsaSigningPSS(t, key, crypto.SHA512)
	}
}

func testRsaSigningPKCS1v15(t *testing.T, key crypto.Signer, hashFunction crypto.Hash) {
	var err error
	var sig []byte

	plaintext := []byte("sign me with PKCS#1 v1.5")
	h := hashFunction.New()
	h.Write(plaintext)
	plaintextHash := h.Sum([]byte{}) // weird API
	if sig, err = key.Sign(rand.Reader, plaintextHash, hashFunction); err != nil {
		t.Errorf("PKCS#1 v1.5 Sign (hash %v): %v", hashFunction, err)
		return
	}
	rsaPubkey := key.Public().(crypto.PublicKey).(*rsa.PublicKey)
	if err = rsa.VerifyPKCS1v15(rsaPubkey, hashFunction, plaintextHash, sig); err != nil {
		t.Errorf("PKCS#1 v1.5 Verify (hash %v): %v", hashFunction, err)
	}
}

func testRsaSigningPSS(t *testing.T, key crypto.Signer, hashFunction crypto.Hash) {
	var err error
	var sig []byte

	plaintext := []byte("sign me with PSS")
	h := hashFunction.New()
	h.Write(plaintext)
	plaintextHash := h.Sum([]byte{}) // weird API
	pssOptions := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hashFunction,
	}
	if sig, err = key.Sign(rand.Reader, plaintextHash, pssOptions); err != nil {
		t.Errorf("PSS Sign (hash %v): %v", hashFunction, err)
		return
	}
	rsaPubkey := key.Public().(crypto.PublicKey).(*rsa.PublicKey)
	if err = rsa.VerifyPSS(rsaPubkey, hashFunction, plaintextHash, sig, pssOptions); err != nil {
		t.Errorf("PSS Verify (hash %v): %v", hashFunction, err)
	}
}

func testRsaEncryption(t *testing.T, key crypto.Decrypter, nbits int) {
	testRsaEncryptionPKCS1v15(t, key)
	testRsaEncryptionOAEP(t, key, crypto.SHA1, []byte{})
	testRsaEncryptionOAEP(t, key, crypto.SHA224, []byte{})
	testRsaEncryptionOAEP(t, key, crypto.SHA256, []byte{})
	testRsaEncryptionOAEP(t, key, crypto.SHA384, []byte{})
	if nbits > 1024 { // key too smol for SHA512
		testRsaEncryptionOAEP(t, key, crypto.SHA512, []byte{})
	}
	testRsaEncryptionOAEP(t, key, crypto.SHA1, []byte{1, 2, 3, 4})
	testRsaEncryptionOAEP(t, key, crypto.SHA224, []byte{5, 6, 7, 8})
	testRsaEncryptionOAEP(t, key, crypto.SHA256, []byte{9})
	testRsaEncryptionOAEP(t, key, crypto.SHA384, []byte{10, 11, 12, 13, 14, 15})
	if nbits > 1024 {
		testRsaEncryptionOAEP(t, key, crypto.SHA512, []byte{16, 17, 18})
	}
}

func testRsaEncryptionPKCS1v15(t *testing.T, key crypto.Decrypter) {
	var err error
	var ciphertext, decrypted []byte

	plaintext := []byte("encrypt me with old and busted crypto")
	rsaPubkey := key.Public().(crypto.PublicKey).(*rsa.PublicKey)
	if ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, rsaPubkey, plaintext); err != nil {
		t.Errorf("PKCS#1v1.5 Encrypt: %v", err)
		return
	}
	if decrypted, err = key.Decrypt(rand.Reader, ciphertext, nil); err != nil {
		t.Errorf("PKCS#1v1.5 Decrypt (nil options): %v", err)
		return
	}
	if bytes.Compare(plaintext, decrypted) != 0 {
		t.Errorf("PKCS#1v1.5 Decrypt (nil options): wrong answer")
		return
	}
	options := &rsa.PKCS1v15DecryptOptions{
		SessionKeyLen: 0,
	}
	if decrypted, err = key.Decrypt(rand.Reader, ciphertext, options); err != nil {
		t.Errorf("PKCS#1v1.5 Decrypt %v", err)
		return
	}
	if bytes.Compare(plaintext, decrypted) != 0 {
		t.Errorf("PKCS#1v1.5 Decrypt: wrong answer")
		return
	}
}

func testRsaEncryptionOAEP(t *testing.T, key crypto.Decrypter, hashFunction crypto.Hash, label []byte) {
	var err error
	var ciphertext, decrypted []byte

	plaintext := []byte("encrypt me with new hotness")
	h := hashFunction.New()
	rsaPubkey := key.Public().(crypto.PublicKey).(*rsa.PublicKey)
	if ciphertext, err = rsa.EncryptOAEP(h, rand.Reader, rsaPubkey, plaintext, label); err != nil {
		t.Errorf("OAEP Encrypt: %v", err)
		return
	}
	options := &rsa.OAEPOptions{
		Hash:  hashFunction,
		Label: label,
	}
	if decrypted, err = key.Decrypt(rand.Reader, ciphertext, options); err != nil {
		t.Errorf("OAEP Decrypt %v", err)
		return
	}
	if bytes.Compare(plaintext, decrypted) != 0 {
		t.Errorf("OAEP Decrypt: wrong answer")
		return
	}
}
