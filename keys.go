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
	"github.com/pkg/errors"
)

// Find a key object.  For asymmetric keys this only finds one half so
// callers will call it twice. Returns nil if the key does not exist on the token.
func findKeys(session *pkcs11Session, id []byte, label []byte, keyclass *uint, keytype *uint) (handles []pkcs11.ObjectHandle, err error) {
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
		return nil, err
	}
	defer func() {
		finalErr := session.ctx.FindObjectsFinal(session.handle)
		if err == nil {
			err = finalErr
		}
	}()
	if handles, _, err = session.ctx.FindObjects(session.handle, 1); err != nil {
		return nil, err
	}

	return handles, nil
}

// Find a key object.  For asymmetric keys this only finds one half so
// callers will call it twice. Returns nil if the key does not exist on the token.
func findKey(session *pkcs11Session, id []byte, label []byte, keyclass *uint, keytype *uint) (obj *pkcs11.ObjectHandle, err error) {
	handles, err := findKeys(session, id, label, keyclass, keytype)

	if len(handles) == 0 {
		return nil, nil
	}
	return &handles[0], nil
}

func (c *Context) makeKeyPair(session *pkcs11Session, id []byte, label []byte, privHandle *pkcs11.ObjectHandle) (signer Signer, err error) {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
	}
	if attributes, err = session.ctx.GetAttributeValue(session.handle, *privHandle, attributes); err != nil {
		return nil, err
	}
	keyType := bytesToUlong(attributes[0].Value)

	pubHandle, err := findKey(session, id, label, uintPtr(pkcs11.CKO_PUBLIC_KEY), &keyType)
	if err != nil {
		return nil, err
	}
	if pubHandle == nil {
		// We can't return a Signer if we don't have private and public key. Treat it as an error.
		return nil, errors.New("could not find public key to match private key")
	}

	var pub crypto.PublicKey
	switch keyType {
	case pkcs11.CKK_DSA:
		if pub, err = exportDSAPublicKey(session, *pubHandle); err != nil {
			return nil, err
		}
		return &pkcs11PrivateKeyDSA{
			pkcs11PrivateKey: pkcs11PrivateKey{
				pkcs11Object: pkcs11Object{
					handle:  *privHandle,
					context: c,
				},
				pubKeyHandle: *pubHandle,
				pubKey:       pub,
			}}, nil

	case pkcs11.CKK_RSA:
		if pub, err = exportRSAPublicKey(session, *pubHandle); err != nil {
			return nil, err
		}
		return &pkcs11PrivateKeyRSA{
			pkcs11PrivateKey: pkcs11PrivateKey{
				pkcs11Object: pkcs11Object{
					handle:  *privHandle,
					context: c,
				},
				pubKeyHandle: *pubHandle,
				pubKey:       pub,
			}}, nil

	case pkcs11.CKK_ECDSA:
		if pub, err = exportECDSAPublicKey(session, *pubHandle); err != nil {
			return nil, err
		}
		return &pkcs11PrivateKeyECDSA{
			pkcs11PrivateKey: pkcs11PrivateKey{
				pkcs11Object: pkcs11Object{
					handle:  *privHandle,
					context: c,
				},
				pubKeyHandle: *pubHandle,
				pubKey:       pub,
			}}, nil

	default:
		return nil, errors.Errorf("unsupported key type: %X", keyType)
	}
}

// FindKeyPair retrieves a previously created asymmetric key pair, or nil if it cannot be found.
//
// At least one of id and label must be specified. If the private key is found, but the public key is
// not, an error is returned because we cannot implement crypto.Signer without the public key.
func (c *Context) FindKeyPair(id []byte, label []byte) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	if id == nil && label == nil {
		return nil, errors.New("id and label cannot both be nil")
	}

	var k Signer

	err := c.withSession(func(session *pkcs11Session) error {
		privHandle, err := findKey(session, id, label, uintPtr(pkcs11.CKO_PRIVATE_KEY), nil)
		if err != nil {
			return err
		}
		if privHandle == nil {
			// Cannot continue, no key found
			return nil
		}

		k, err = c.makeKeyPair(session, id, label, privHandle)
		if err != nil {
			return err
		}

		return nil
	})
	return k, err
}

// FindKeyPairs retrieves all matching asymmetric key pairs, or a nil slice if none can be found.
//
// At least one of id and label must be specified.
// If a private key is found, but the corresponding public key is not, the key is not returned because we cannot
// implement crypto.Signer without the public key.
func (c *Context) FindKeyPairs(id []byte, label []byte) ([]Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	if id == nil && label == nil {
		return nil, errors.New("id and label cannot both be nil")
	}

	var keys []Signer

	err := c.withSession(func(session *pkcs11Session) error {
		privHandles, err := findKeys(session, id, label, uintPtr(pkcs11.CKO_PRIVATE_KEY), nil)
		if err != nil {
			return err
		}

		for _, privHandle := range(privHandles) {
			k, err := c.makeKeyPair(session, id, label, &privHandle)
			if err != nil {
				continue
			}

			keys = append(keys, k)
		}

		return nil
	})
	return keys, err
}

// FindAllKeyPairs retrieves all existing asymmetric key pairs, or a nil slice if none can be found.
//
// If a private key is found, but the corresponding public key is not, the key is not returned because we cannot
// implement crypto.Signer without the public key.
func (c *Context) FindAllKeyPairs() ([]Signer, error) {
	//if c.closed.Get() {
	//	return nil, errClosed
	//}
	//
	//var keys []Signer
	//
	//err := c.withSession(func(session *pkcs11Session) error {
	//	privHandles, err := findKeys(session, nil, nil, uintPtr(pkcs11.CKO_PRIVATE_KEY), nil)
	//	if err != nil {
	//		return err
	//	}
	//
	//	for _, privHandle := range(privHandles) {
	//		k, err := c.makeKeyPair(session, id, label, &privHandle)
	//		if err != nil {
	//			continue
	//		}
	//
	//		keys = append(keys, k)
	//	}
	//
	//	return nil
	//})
	//return keys, err

	return nil, errors.Errorf("Not yet supported")
}

// Public returns the public half of a private key.
//
// This partially implements the go.crypto.Signer and go.crypto.Decrypter interfaces for
// pkcs11PrivateKey. (The remains of the implementation is in the
// key-specific types.)
func (k pkcs11PrivateKey) Public() crypto.PublicKey {
	return k.pubKey
}

// FindKey retrieves a previously created symmetric key, or nil if it cannot be found.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
func (c *Context) FindKey(id []byte, label []byte) (*SecretKey, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	if id == nil && label == nil {
		return nil, errors.New("id and label cannot both be nil")
	}

	var k *SecretKey

	err := c.withSession(func(session *pkcs11Session) error {
		privHandle, err := findKey(session, id, label, uintPtr(pkcs11.CKO_SECRET_KEY), nil)
		if err != nil {
			return err
		}
		if privHandle == nil {
			// Key does not exist
			return nil
		}

		attributes := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
		}
		if attributes, err = session.ctx.GetAttributeValue(session.handle, *privHandle, attributes); err != nil {
			return err
		}
		keyType := bytesToUlong(attributes[0].Value)

		if cipher, ok := Ciphers[int(keyType)]; ok {
			k = &SecretKey{pkcs11Object{*privHandle, c}, cipher}
		} else {
			return errors.Errorf("unsupported key type: %X", keyType)
		}
		return nil
	})

	return k, err
}

// FindKeys retrieves all matching symmetric keys, or a nil slice if none can be found.
//
// At least one of id and label must be specified.
func (c *Context) FindKeys(id []byte, label []byte) ([]*SecretKey, error) {
	return nil, errors.Errorf("Not yet supported")
}

// FindAllKeyPairs retrieves all existing symmetric keys, or a nil slice if none can be found.
func (c *Context) FindAllKeys() ([]*SecretKey, error) {
	return nil, errors.Errorf("Not yet supported")
}

func uintPtr(i uint) *uint { return &i }

// GetAttributes gets the values of the specified attributes on the given key
func (c *Context) GetAttributes(signer *crypto.Signer, attributes []AttributeType) (a AttributeSet, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	//if sig, ok := (*signer).(Signer); !ok {
	//	nil, return errors.Errorf("not a PKCS#11 key")
	//}
	//
	//err := c.withSession(func(session *pkcs11Session) error {
	//	session.ctx.GetAttributeValue(session.handle, )
	//})

	return nil, errors.Errorf("Not yet supported")
}

// GetAttributes gets the value of the specified attribute on the given key
func (c *Context) GetAttribute(signer *crypto.Signer, attribute AttributeType) (a *Attribute, err error) {
	set, err := c.GetAttributes(signer, []AttributeType{attribute})
	if err != nil {
		return nil, err
	}

	return set[attribute], nil
}