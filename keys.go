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

const maxHandlePerFind = 20

func findKeysWithAttributes(session *pkcs11Session, template []*pkcs11.Attribute) (handles []pkcs11.ObjectHandle, err error) {
	if err = session.ctx.FindObjectsInit(session.handle, template); err != nil {
		return nil, err
	}
	defer func() {
		finalErr := session.ctx.FindObjectsFinal(session.handle)
		if err == nil {
			err = finalErr
		}
	}()

	newhandles, _, err := session.ctx.FindObjects(session.handle, maxHandlePerFind)
	if err != nil {
		return nil, err
	}

	for len(newhandles) > 0 {
		handles = append(handles, newhandles...)

		newhandles, _, err = session.ctx.FindObjects(session.handle, maxHandlePerFind)
		if err != nil {
			return nil, err
		}
	}

	return handles, nil
}

// Find key objects.  For asymmetric keys this only finds one half so
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

	if handles, err = findKeysWithAttributes(session, template); err != nil {
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

// Takes a handles to the private half of a keypair, locates the public half with the matching CKA_ID
// value and constructs a keypair object from them both.
func (c *Context) makeKeyPair(session *pkcs11Session, privHandle *pkcs11.ObjectHandle) (signer Signer, err error) {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
	}
	if attributes, err = session.ctx.GetAttributeValue(session.handle, *privHandle, attributes); err != nil {
		return nil, err
	}
	id := attributes[0].Value
	label := attributes[1].Value
	keyType := bytesToUlong(attributes[2].Value)

	// Find the public half which has a matching CKA_ID
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
	result, err := c.FindKeyPairs(id, label)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, nil
	}

	return result[0], nil
}

// FindKeyPairs retrieves all matching asymmetric key pairs, or a nil slice if none can be found.
//
// At least one of id and label must be specified.
// If a private key is found, but the corresponding public key is not, the key is not returned because we cannot
// implement crypto.Signer without the public key.
func (c *Context) FindKeyPairs(id []byte, label []byte) ([]Signer, error) {
	if id == nil && label == nil {
		return nil, errors.New("id and label cannot both be nil")
	}

	attributes := NewAttributeSet()

	if id != nil {
		attributes[CkaId] = pkcs11.NewAttribute(CkaId, id)
	}
	if label != nil {
		attributes[CkaLabel] = pkcs11.NewAttribute(CkaLabel, label)
	}

	return c.FindKeyPairsWithAttributes(attributes)
}

func (c *Context) FindKeyPairWithAttributes(attributes AttributeSet) (Signer, error) {
	result, err := c.FindKeyPairsWithAttributes(attributes)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, nil
	}

	return result[0], nil
}

// FindKeyPairsWithAttributes retrieves previously created asymmetric key pairs, or nil if none can be found.
// The given attributes are matched against the private half only. Then the public half with a matching CKA_ID
// value is found.
//
// If a private key is found, but the corresponding public key is not, the key is not returned because we cannot
//// implement crypto.Signer without the public key.
func (c *Context) FindKeyPairsWithAttributes(attributes AttributeSet) ([]Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var keys []Signer

	if _, ok := attributes[CkaClass]; ok {
		return nil, errors.Errorf("keypair attribute set must not contain CkaClass")
	}

	err := c.withSession(func(session *pkcs11Session) error {
		// Add the private key class to the template to find the private half
		privAttributes := attributes.Copy()
		privAttributes[CkaClass] = pkcs11.NewAttribute(CkaClass, pkcs11.CKO_PRIVATE_KEY)

		privHandles, err := findKeysWithAttributes(session, privAttributes.ToSlice())
		if err != nil {
			return err
		}

		for _, privHandle := range(privHandles) {
			k, err := c.makeKeyPair(session, &privHandle)
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
	return c.FindKeyPairsWithAttributes(NewAttributeSet())
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
	result, err := c.FindKeys(id, label)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, nil
	}

	return result[0], nil
}

// FindKeys retrieves all matching symmetric keys, or a nil slice if none can be found.
//
// At least one of id and label must be specified.
func (c *Context) FindKeys(id []byte, label []byte) ([]*SecretKey, error) {
	if id == nil && label == nil {
		return nil, errors.New("id and label cannot both be nil")
	}

	attributes := NewAttributeSet()

	if id != nil {
		attributes[CkaId] = pkcs11.NewAttribute(CkaId, id)
	}
	if label != nil {
		attributes[CkaLabel] = pkcs11.NewAttribute(CkaLabel, label)
	}

	return c.FindKeysWithAttributes(attributes)
}

func (c *Context) FindKeyWithAttributes(attributes AttributeSet) (*SecretKey, error) {
	result, err := c.FindKeysWithAttributes(attributes)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, nil
	}

	return result[0], nil
}

func (c *Context) FindKeysWithAttributes(attributes AttributeSet) ([]*SecretKey, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var keys []*SecretKey

	if _, ok := attributes[CkaClass]; ok {
		return nil, errors.Errorf("key attribute set must not contain CkaClass")
	}

	err := c.withSession(func(session *pkcs11Session) error {
		// Add the private key class to the template to find the private half
		privAttributes := attributes.Copy()
		privAttributes[CkaClass] = pkcs11.NewAttribute(CkaClass, pkcs11.CKO_SECRET_KEY)

		privHandles, err := findKeysWithAttributes(session, privAttributes.ToSlice())
		if err != nil {
			return err
		}

		for _, privHandle := range(privHandles) {
			attributes := []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
			}
			if attributes, err = session.ctx.GetAttributeValue(session.handle, privHandle, attributes); err != nil {
				return err
			}
			keyType := bytesToUlong(attributes[0].Value)

			if cipher, ok := Ciphers[int(keyType)]; ok {
				k := &SecretKey{pkcs11Object{privHandle, c}, cipher}
				keys = append(keys, k)
			} else {
				return errors.Errorf("unsupported key type: %X", keyType)
			}
		}

		return nil
	})

	return keys, err
}

// FindAllKeyPairs retrieves all existing symmetric keys, or a nil slice if none can be found.
func (c *Context) FindAllKeys() ([]*SecretKey, error) {
	return c.FindKeysWithAttributes(NewAttributeSet())
}

func uintPtr(i uint) *uint { return &i }

func (c *Context) getAttributes(handle pkcs11.ObjectHandle, attributes []AttributeType) (a AttributeSet, err error) {
	values := NewAttributeSet()

	err = c.withSession(func(session *pkcs11Session) error {
		var attrs []*pkcs11.Attribute
		for _, a := range(attributes) {
			attrs = append(attrs, pkcs11.NewAttribute(a, nil))
		}

		p11values, err := session.ctx.GetAttributeValue(session.handle, handle, attrs)
		if err != nil {
			return err
		}

		for _, a := range(p11values) {
			values[a.Type] = pkcs11.NewAttribute(a.Type, a.Value)
		}

		return nil
	})

	return values, err
}

// GetAttributes gets the values of the specified attributes on the given key
// If the key is asymmetric, then the attributes are retrieved from the private half
func (c *Context) GetAttributes(key interface{}, attributes []AttributeType) (a AttributeSet, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var handle pkcs11.ObjectHandle

	switch k := (key).(type) {
	case *pkcs11PrivateKeyDSA:
		handle = k.handle
	case *pkcs11PrivateKeyRSA:
		handle = k.handle
	case *pkcs11PrivateKeyECDSA:
		handle = k.handle
	case *SecretKey:
		handle = k.handle
	default:
		return nil, errors.Errorf("not a PKCS#11 key")
	}

	return c.getAttributes(handle, attributes)
}

// GetAttribute gets the value of the specified attribute on the given key
// If the key is asymmetric, then the attribute is retrieved from the private half
func (c *Context) GetAttribute(key interface{}, attribute AttributeType) (a *Attribute, err error) {
	set, err := c.GetAttributes(key, []AttributeType{attribute})
	if err != nil {
		return nil, err
	}

	return set[attribute], nil
}

// GetPubAttributes gets the values of the specified attributes on the public half of the given key
func (c *Context) GetPubAttributes(key interface{}, attributes []AttributeType) (a AttributeSet, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var handle pkcs11.ObjectHandle

	switch k := (key).(type) {
	case *pkcs11PrivateKeyDSA:
		handle = k.pubKeyHandle
	case *pkcs11PrivateKeyRSA:
		handle = k.pubKeyHandle
	case *pkcs11PrivateKeyECDSA:
		handle = k.pubKeyHandle
	default:
		return nil, errors.Errorf("not an asymmetric PKCS#11 key")
	}

	return c.getAttributes(handle, attributes)
}

// GetPubAttribute gets the value of the specified attribute on the public half of the given key
func (c *Context) GetPubAttribute(key interface{}, attribute AttributeType) (a *Attribute, err error) {
	set, err := c.GetPubAttributes(key, []AttributeType{attribute})
	if err != nil {
		return nil, err
	}

	return set[attribute], nil
}