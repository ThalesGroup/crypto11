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
	"fmt"
	"github.com/miekg/pkcs11"
)

// SymmetricCipher represents information about a symmetric cipher.
type SymmetricCipher struct {
	// Key type (CKK_...)
	KeyType uint

	// Key generation mechanism (CKM_..._KEY_GEN)
	GenMech uint

	// Block size in bytes
	BlockSize int

	// True if encryption supported
	Encrypt bool

	// True if MAC supported
	MAC bool

	// ECB mechanism (CKM_..._ECB)
	ECBMech uint
}

// CipherAES describes the AES cipher. Use this with the
// GenerateSecretKey... functions.
var CipherAES = SymmetricCipher{
	KeyType:   pkcs11.CKK_AES,
	GenMech:   pkcs11.CKM_AES_KEY_GEN,
	BlockSize: 16,
	Encrypt:   true,
	MAC:       false,
	ECBMech:   pkcs11.CKM_AES_ECB,
}

// CipherDES3 describes the three-key triple-DES cipher. Use this with the
// GenerateSecretKey... functions.
var CipherDES3 = SymmetricCipher{
	KeyType:   pkcs11.CKK_DES3,
	GenMech:   pkcs11.CKM_DES3_KEY_GEN,
	BlockSize: 8,
	Encrypt:   true,
	MAC:       false,
	ECBMech:   pkcs11.CKM_DES3_ECB,
}

// Ciphers is a map of PKCS#11 key types (CKK_...) to symmetric cipher information.
var Ciphers = map[int]*SymmetricCipher{
	pkcs11.CKK_AES:  &CipherAES,
	pkcs11.CKK_DES3: &CipherDES3,
}

// PKCS11SecretKey contains a reference to a loaded PKCS#11 symmetric key object.
//
// A *PKCS11SecretKey implements the cipher.Block interface, allowing it be used
// as the argument to cipher.NewCBCDecrypter, etc.
type PKCS11SecretKey struct {
	PKCS11Object

	// Symmetric cipher information
	Cipher *SymmetricCipher
}

// Key generation -------------------------------------------------------------

// GenerateSecretKey creates an secret key of given length and type.
//
// The key will have a random label and ID.
func GenerateSecretKey(bits int, cipher *SymmetricCipher) (*PKCS11SecretKey, error) {
	return GenerateSecretKeyOnSlot(instance.slot, nil, nil, bits, cipher)
}

// GenerateSecretKeyOnSlot creates as symmetric key on a specified slot
//
// Either or both label and/or id can be nil, in which case random values will be generated.
func GenerateSecretKeyOnSlot(slot uint, id []byte, label []byte, bits int, cipher *SymmetricCipher) (*PKCS11SecretKey, error) {
	var k *PKCS11SecretKey
	var err error
	if err = ensureSessions(instance, slot); err != nil {
		return nil, err
	}
	err = withSession(slot, func(session *PKCS11Session) error {
		k, err = GenerateSecretKeyOnSession(session, slot, id, label, bits, cipher)
		return err
	})
	return k, err
}

// GenerateSecretKeyOnSession creates a symmetric key of given type and
// length, on a specified session.
//
// Either or both label and/or id can be nil, in which case random values will be generated.
func GenerateSecretKeyOnSession(session *PKCS11Session, slot uint, id []byte, label []byte, bits int, cipher *SymmetricCipher) (key *PKCS11SecretKey, err error) {
	// TODO refactor with the other key generation implementations
	if label == nil {
		if label, err = generateKeyLabel(); err != nil {
			return nil, err
		}
	}
	if id == nil {
		if id, err = generateKeyLabel(); err != nil {
			return nil, err
		}
	}
	secretKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, cipher.KeyType),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, cipher.MAC),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, cipher.MAC),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, cipher.Encrypt),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, cipher.Encrypt),

		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	if bits > 0 {
		secretKeyTemplate = append(secretKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, bits/8))
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(cipher.GenMech, nil)}
	privHandle, err := session.Ctx.GenerateKey(session.Handle, mech, secretKeyTemplate)
	if err != nil {
		return nil, err
	}
	key = &PKCS11SecretKey{PKCS11Object{privHandle, slot}, cipher}
	return
}

// cipher.Block ---------------------------------------------------------

// BlockSize returns the cipher's block size in bytes.
func (key *PKCS11SecretKey) BlockSize() int {
	return key.Cipher.BlockSize
}

// Decrypt decrypts the first block in src into dst.
// Dst and src must overlap entirely or not at all.
func (key *PKCS11SecretKey) Decrypt(dst, src []byte) {
	var result []byte
	if err := withSession(key.Slot, func(session *PKCS11Session) (err error) {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(key.Cipher.ECBMech, nil)}
		if err = session.Ctx.DecryptInit(session.Handle, mech, key.Handle); err != nil {
			return
		}
		if result, err = session.Ctx.Decrypt(session.Handle, src[:key.Cipher.BlockSize]); err != nil {
			return
		}
		if len(result) != key.Cipher.BlockSize {
			err = fmt.Errorf("C_Decrypt: returned %v bytes, wanted %v", len(result), key.Cipher.BlockSize)
			return
		}
		return
	}); err != nil {
		panic(err)
	} else {
		copy(dst[:key.Cipher.BlockSize], result)
	}
}

// Encrypt encrypts the first block in src into dst.
// Dst and src must overlap entirely or not at all.
func (key *PKCS11SecretKey) Encrypt(dst, src []byte) {
	var result []byte
	if err := withSession(key.Slot, func(session *PKCS11Session) (err error) {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(key.Cipher.ECBMech, nil)}
		if err = session.Ctx.EncryptInit(session.Handle, mech, key.Handle); err != nil {
			return
		}
		if result, err = session.Ctx.Encrypt(session.Handle, src[:key.Cipher.BlockSize]); err != nil {
			return
		}
		if len(result) != key.Cipher.BlockSize {
			err = fmt.Errorf("C_Encrypt: unexpectedly returned %v bytes, wanted %v", len(result), key.Cipher.BlockSize)
			return
		}
		return
	}); err != nil {
		panic(err)
	} else {
		copy(dst[:key.Cipher.BlockSize], result)
	}
}
