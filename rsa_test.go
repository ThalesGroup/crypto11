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
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
	"testing"
)

var rsaSizes = []int{1024, 2048}

func TestNativeRSA(t *testing.T) {
	var key *rsa.PrivateKey
	_, err := ConfigureFromFile("config")
	require.NoError(t, err)

	for _, nbits := range rsaSizes {
		t.Run(fmt.Sprintf("%v", nbits), func(t *testing.T) {
			t.Run("Generate", func(t *testing.T) {
				if key, err = rsa.GenerateKey(rand.Reader, nbits); err != nil {
					t.Errorf("crypto.rsa.GenerateKey: %v", err)
					return
				}
				if err = key.Validate(); err != nil {
					t.Errorf("crypto.rsa.PrivateKey.Validate: %v", err)
					return
				}
			})
			t.Run("Sign", func(t *testing.T) { testRsaSigning(t, key, nbits, ^uint(0)) })
			t.Run("Encrypt", func(t *testing.T) { testRsaEncryption(t, key, nbits, ^uint(0)) })
		})
	}

	require.NoError(t, Close())
}

func TestHardRSA(t *testing.T) {
	var key *PKCS11PrivateKeyRSA
	var key2, key3 crypto.PrivateKey
	var id, label []byte

	_, err := ConfigureFromFile("config")
	require.NoError(t, err)

	for _, nbits := range rsaSizes {
		t.Run(fmt.Sprintf("%v", nbits), func(t *testing.T) {
			t.Run("Generate", func(t *testing.T) {
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
			})
			t.Run("Sign", func(t *testing.T) { testRsaSigning(t, key, nbits, key.Slot) })
			t.Run("Encrypt", func(t *testing.T) { testRsaEncryption(t, key, nbits, key.Slot) })
			t.Run("FindId", func(t *testing.T) {
				// Get a fresh handle to  the key
				if id, label, err = key.Identify(); err != nil {
					t.Errorf("crypto11.rsa.PKCS11PrivateKeyRSA.Identify: %v", err)
					return
				}
				if key2, err = FindKeyPair(id, nil); err != nil {
					t.Errorf("crypto11.rsa.FindRSAKeyPair by id: %v", err)
					return
				}
			})
			t.Run("SignId", func(t *testing.T) {
				if key2 == nil {
					t.SkipNow()
				}
				testRsaSigning(t, key2.(*PKCS11PrivateKeyRSA), nbits, key2.(*PKCS11PrivateKeyRSA).Slot)
			})
			t.Run("FindLabel", func(t *testing.T) {
				if key3, err = FindKeyPair(nil, label); err != nil {
					t.Errorf("crypto11.rsa.FindKeyPair by label: %v", err)
					return
				}
			})
			t.Run("SignLabel", func(t *testing.T) {
				if key3 == nil {
					t.SkipNow()
				}
				testRsaSigning(t, key3.(crypto.Signer), nbits, key3.(*PKCS11PrivateKeyRSA).Slot)
			})
		})
	}
	require.NoError(t, Close())
}

func testRsaSigning(t *testing.T, key crypto.Signer, nbits int, slot uint) {
	t.Run("SHA1", func(t *testing.T) { testRsaSigningPKCS1v15(t, key, crypto.SHA1) })
	t.Run("SHA224", func(t *testing.T) { testRsaSigningPKCS1v15(t, key, crypto.SHA224) })
	t.Run("SHA256", func(t *testing.T) { testRsaSigningPKCS1v15(t, key, crypto.SHA256) })
	t.Run("SHA384", func(t *testing.T) { testRsaSigningPKCS1v15(t, key, crypto.SHA384) })
	t.Run("SHA512", func(t *testing.T) { testRsaSigningPKCS1v15(t, key, crypto.SHA512) })
	t.Run("PSSSHA1", func(t *testing.T) { testRsaSigningPSS(t, key, crypto.SHA1, slot) })
	t.Run("PSSSHA224", func(t *testing.T) { testRsaSigningPSS(t, key, crypto.SHA224, slot) })
	t.Run("PSSSHA256", func(t *testing.T) { testRsaSigningPSS(t, key, crypto.SHA256, slot) })
	t.Run("PSSSHA384", func(t *testing.T) { testRsaSigningPSS(t, key, crypto.SHA384, slot) })
	t.Run("PSSSHA512", func(t *testing.T) {
		if nbits > 1024 {
			testRsaSigningPSS(t, key, crypto.SHA512, slot)
		} else {
			t.Skipf("key too smol for SHA512 with sLen=hLen")
		}
	})
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

func testRsaSigningPSS(t *testing.T, key crypto.Signer, hashFunction crypto.Hash, slot uint) {
	var err error
	var sig []byte

	needMechanism(t, slot, pkcs11.CKM_RSA_PKCS_PSS)
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

func testRsaEncryption(t *testing.T, key crypto.Decrypter, nbits int, slot uint) {
	t.Run("PKCS1v15", func(t *testing.T) { testRsaEncryptionPKCS1v15(t, key) })
	t.Run("OAEPSHA1", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA1, []byte{}, slot) })
	t.Run("OAEPSHA224", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA224, []byte{}, slot) })
	t.Run("OAEPSHA256", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA256, []byte{}, slot) })
	t.Run("OAEPSHA384", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA384, []byte{}, slot) })
	t.Run("OAEPSHA512", func(t *testing.T) {
		if nbits > 1024 {
			testRsaEncryptionOAEP(t, key, crypto.SHA512, []byte{}, slot)
		} else {
			t.Skipf("key too smol for SHA512")
		}
	})
	t.Run("OAEPSHA1Label", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA1, []byte{1, 2, 3, 4}, slot) })
	t.Run("OAEPSHA224Label", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA224, []byte{5, 6, 7, 8}, slot) })
	t.Run("OAEPSHA256Label", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA256, []byte{9}, slot) })
	t.Run("OAEPSHA384Label", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA384, []byte{10, 11, 12, 13, 14, 15}, slot) })
	t.Run("OAEPSHA512Label", func(t *testing.T) {
		if nbits > 1024 {
			testRsaEncryptionOAEP(t, key, crypto.SHA512, []byte{16, 17, 18}, slot)
		} else {
			t.Skipf("key too smol for SHA512")
		}
	})
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

func testRsaEncryptionOAEP(t *testing.T, key crypto.Decrypter, hashFunction crypto.Hash, label []byte, slot uint) {
	var err error
	var ciphertext, decrypted []byte
	needMechanism(t, slot, pkcs11.CKM_RSA_PKCS_OAEP)
	// Doesn't seem to be a way to query supported MGFs so we do that the hard way.
	var info pkcs11.Info
	if info, err = instance.ctx.GetInfo(); err != nil {
		t.Errorf("GetInfo: %v", err)
		return
	}
	if info.ManufacturerID == "SoftHSM" && (hashFunction != crypto.SHA1 || len(label) > 0) {
		t.Skipf("SoftHSM OAEP only supports SHA-1 with no label")
	}
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

func needMechanism(t *testing.T, slot uint, wantMech uint) {
	var err error
	var mechs []*pkcs11.Mechanism

	if slot == ^uint(0) { // not using PKCS#11
		return
	}
	if mechs, err = instance.ctx.GetMechanismList(slot); err != nil {
		t.Errorf("GetMechanismList: %v", err)
		return
	}
	for _, mech := range mechs {
		if mech.Mechanism == wantMech {
			return
		}
	}
	t.Skipf("mechanism %v not supported", wantMech)
}
