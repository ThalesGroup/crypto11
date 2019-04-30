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

	"github.com/miekg/pkcs11"
)

// Find a key object.  For asymmetric keys this only finds one half so
// callers will call it twice.
func findKey(session *pkcs11Session, id []byte, label []byte, keyclass *uint, keytype *uint) (obj pkcs11.ObjectHandle, err error) {
	var handles []pkcs11.ObjectHandle
	var template []*pkcs11.Attribute

	if keyclass != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, *keyclass))
	}
	if keytype != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, *keytype))
	}
	if id != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}
	if err = session.ctx.FindObjectsInit(session.handle, template); err != nil {
		return 0, err
	}
	defer func() {
		finalErr := session.ctx.FindObjectsFinal(session.handle)
		if err == nil {
			err = finalErr
		}
	}()
	if handles, _, err = session.ctx.FindObjects(session.handle, 1); err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, ErrKeyNotFound
	}
	return handles[0], nil
}

// FindKeyPair retrieves a previously created asymmetric key.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
func (c *Context) FindKeyPair(id []byte, label []byte) (Signer, error) {

	if c.closed.Get() {
		return nil, ErrClosed
	}

	var k Signer

	err := c.withSession(func(session *pkcs11Session) error {
		var err error
		var privHandle, pubHandle pkcs11.ObjectHandle
		var pub crypto.PublicKey

		if privHandle, err = findKey(session, id, label, uintPtr(pkcs11.CKO_PRIVATE_KEY), nil); err != nil {
			return err
		}
		attributes := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
		}
		if attributes, err = session.ctx.GetAttributeValue(session.handle, privHandle, attributes); err != nil {
			return err
		}
		keyType := bytesToUlong(attributes[0].Value)
		if pubHandle, err = findKey(session, id, label, uintPtr(pkcs11.CKO_PUBLIC_KEY), &keyType); err != nil {
			return err
		}
		switch keyType {
		case pkcs11.CKK_DSA:
			if pub, err = exportDSAPublicKey(session, pubHandle); err != nil {
				return err
			}
			k = &pkcs11PrivateKeyDSA{
				pkcs11PrivateKey: pkcs11PrivateKey{
					pkcs11Object: pkcs11Object{
						handle:  privHandle,
						context: c,
					},
					pubKeyHandle: pubHandle,
					pubKey:       pub,
				}}

		case pkcs11.CKK_RSA:
			if pub, err = exportRSAPublicKey(session, pubHandle); err != nil {
				return err
			}
			k = &pkcs11PrivateKeyRSA{
				pkcs11PrivateKey: pkcs11PrivateKey{
					pkcs11Object: pkcs11Object{
						handle:  privHandle,
						context: c,
					},
					pubKeyHandle: pubHandle,
					pubKey:       pub,
				}}

		case pkcs11.CKK_ECDSA:
			if pub, err = exportECDSAPublicKey(session, pubHandle); err != nil {
				return err
			}
			k = &pkcs11PrivateKeyECDSA{
				pkcs11PrivateKey: pkcs11PrivateKey{
					pkcs11Object: pkcs11Object{
						handle:  privHandle,
						context: c,
					},
					pubKeyHandle: pubHandle,
					pubKey:       pub,
				}}

		default:
			return ErrUnsupportedKeyType
		}

		return nil
	})
	return k, err
}

// Public returns the public half of a private key.
//
// This partially implements the go.crypto.Signer and go.crypto.Decrypter interfaces for
// pkcs11PrivateKey. (The remains of the implementation is in the
// key-specific types.)
func (k pkcs11PrivateKey) Public() crypto.PublicKey {
	return k.pubKey
}

// FindKey retrieves a previously created symmetric key.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
func (c *Context) FindKey(id []byte, label []byte) (k *SecretKey, err error) {
	if c.closed.Get() {
		return nil, ErrClosed
	}

	err = c.withSession(func(session *pkcs11Session) error {
		var privHandle pkcs11.ObjectHandle
		if privHandle, err = findKey(session, id, label, uintPtr(pkcs11.CKO_SECRET_KEY), nil); err != nil {
			return err
		}
		attributes := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
		}
		if attributes, err = session.ctx.GetAttributeValue(session.handle, privHandle, attributes); err != nil {
			return err
		}
		if cipher, ok := Ciphers[int(bytesToUlong(attributes[0].Value))]; ok {
			k = &SecretKey{pkcs11Object{privHandle, c}, cipher}
		} else {
			return ErrUnsupportedKeyType
		}
		return nil
	})
	return
}

func uintPtr(i uint) *uint { return &i }
