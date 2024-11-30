package crypto11

import (
	"crypto"
	"io"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

type PrivateKey interface {
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)

	KeyType() uint
}

func (k *pkcs11PrivateKeyDSA) KeyType() uint {
	return pkcs11.CKK_DSA
}

func (k *pkcs11PrivateKeyRSA) KeyType() uint {
	return pkcs11.CKK_RSA
}

func (k *pkcs11PrivateKeyECDSA) KeyType() uint {
	return pkcs11.CKK_ECDSA
}

// Takes a handles to the private half of a keypair.
func (c *Context) makePrivateKey(session *pkcs11Session, privHandle *pkcs11.ObjectHandle) (signer PrivateKey, err error) {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
	}
	if attributes, err = session.ctx.GetAttributeValue(session.handle, *privHandle, attributes); err != nil {
		return nil, err
	}
	keyType := bytesToUlong(attributes[0].Value)

	resultPkcs11PrivateKey := pkcs11PrivateKey{
		pkcs11Object: pkcs11Object{
			handle:  *privHandle,
			context: c,
		},
	}

	switch keyType {
	case pkcs11.CKK_DSA:
		result := &pkcs11PrivateKeyDSA{pkcs11PrivateKey: resultPkcs11PrivateKey}
		return result, nil

	case pkcs11.CKK_RSA:
		result := &pkcs11PrivateKeyRSA{pkcs11PrivateKey: resultPkcs11PrivateKey}
		return result, nil

	case pkcs11.CKK_ECDSA:
		result := &pkcs11PrivateKeyECDSA{pkcs11PrivateKey: resultPkcs11PrivateKey}
		return result, nil

	default:
		return nil, errors.Errorf("unsupported key type: %X", keyType)
	}
}

// FindPrivateKey retrieves a previously created asymmetric private key, or nil if it cannot be found.
//
// At least one of id and label must be specified.
func (c *Context) FindPrivateKey(id []byte, label []byte) (PrivateKey, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	result, err := c.FindPrivateKeys(id, label)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, nil
	}

	return result[0], nil
}

// FindPrivateKeys retrieves all matching asymmetric private keys, or a nil slice if none can be found.
//
// At least one of id and label must be specified.
func (c *Context) FindPrivateKeys(id []byte, label []byte) (signer []PrivateKey, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	if id == nil && label == nil {
		return nil, errors.New("id and label cannot both be nil")
	}

	attributes := NewAttributeSet()

	if id != nil {
		err = attributes.Set(CkaId, id)
		if err != nil {
			return nil, err
		}
	}
	if label != nil {
		err = attributes.Set(CkaLabel, label)
		if err != nil {
			return nil, err
		}
	}

	return c.FindPrivateKeysWithAttributes(attributes)
}

// FindPrivateKeyWithAttributes retrieves a previously created asymmetric private keys, or nil if it cannot be found.
// The given attributes are matched against the private half only.
func (c *Context) FindPrivateKeyWithAttributes(attributes AttributeSet) (PrivateKey, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	result, err := c.FindPrivateKeysWithAttributes(attributes)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, nil
	}

	return result[0], nil
}

// FindPrivateKeysWithAttributes retrieves previously created asymmetric private keys, or nil if none can be found.
// The given attributes are matched against the private half only.
func (c *Context) FindPrivateKeysWithAttributes(attributes AttributeSet) (signer []PrivateKey, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var keys []PrivateKey

	if _, ok := attributes[CkaClass]; ok {
		return nil, errors.Errorf("keypair attribute set must not contain CkaClass")
	}

	err = c.withSession(func(session *pkcs11Session) error {
		// Add the private key class to the template to find the private half
		privAttributes := attributes.Copy()
		err = privAttributes.Set(CkaClass, pkcs11.CKO_PRIVATE_KEY)
		if err != nil {
			return err
		}

		privHandles, err := findKeysWithAttributes(session, privAttributes.ToSlice())
		if err != nil {
			return err
		}

		for _, privHandle := range privHandles {
			k, err := c.makePrivateKey(session, &privHandle)
			if err != nil {
				return err
			}

			keys = append(keys, k)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return keys, nil
}
