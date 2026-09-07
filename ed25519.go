// Copyright 2024 Thales Group
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
	"crypto/ed25519"
	"encoding/asn1"
	"io"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// Edwards-curve support was added in PKCS#11 v3.0; github.com/miekg/pkcs11
// does not define these constants.
const (
	ckkECEdwards           = 0x00000040
	ckmECEdwardsKeyPairGen = 0x00001055
	ckmEDDSA               = 0x00001057
)

// ed25519OID is the DER encoding of id-Ed25519 (RFC 8410: 1.3.101.112), used
// as the CKA_EC_PARAMS value for an Ed25519 key.
var ed25519OID = mustMarshal(asn1.ObjectIdentifier{1, 3, 101, 112})

// pkcs11PrivateKeyEd25519 contains a reference to a loaded PKCS#11 Ed25519 private key object.
type pkcs11PrivateKeyEd25519 struct {
	pkcs11PrivateKey
}

func (k *pkcs11PrivateKeyEd25519) KeyType() uint {
	return ckkECEdwards
}

// exportEd25519PublicKey exports the public key corresponding to a private
// Ed25519 key. CKA_EC_POINT holds the 32-byte Ed25519 point wrapped in a DER
// OCTET STRING, the same convention PKCS#11 uses for classical EC curves.
func exportEd25519PublicKey(session *pkcs11Session, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	exported, err := session.ctx.GetAttributeValue(session.handle, pubHandle, template)
	if err != nil {
		return nil, err
	}

	// Most tokens wrap the point in a DER OCTET STRING; some return the raw
	// 32 bytes.
	pointBytes := exported[0].Value
	if unwrapped := []byte(nil); len(pointBytes) != ed25519.PublicKeySize {
		if _, err := asn1.Unmarshal(pointBytes, &unwrapped); err != nil {
			return nil, errors.WithMessage(err, "ed25519 public key point is invalid ASN.1")
		}
		pointBytes = unwrapped
	}
	if len(pointBytes) != ed25519.PublicKeySize {
		return nil, errors.Errorf("unexpected ed25519 public key length: %d", len(pointBytes))
	}
	return ed25519.PublicKey(pointBytes), nil
}

// GenerateEd25519KeyPair creates an Ed25519 key pair on the token. The id parameter is used to
// set CKA_ID and must be non-nil.
func (c *Context) GenerateEd25519KeyPair(id []byte) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithID(id)
	if err != nil {
		return nil, err
	}
	private := public.Copy()

	return c.GenerateEd25519KeyPairWithAttributes(public, private)
}

// GenerateEd25519KeyPairWithLabel creates an Ed25519 key pair on the token. The id and label
// parameters are used to set CKA_ID and CKA_LABEL respectively and must be non-nil.
func (c *Context) GenerateEd25519KeyPairWithLabel(id, label []byte) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithIDAndLabel(id, label)
	if err != nil {
		return nil, err
	}
	private := public.Copy()

	return c.GenerateEd25519KeyPairWithAttributes(public, private)
}

// GenerateEd25519KeyPairWithAttributes creates an Ed25519 key pair on the token. After this
// function returns, public and private will contain the attributes applied to the key pair.
// If required attributes are missing, they will be set to a default value.
func (c *Context) GenerateEd25519KeyPairWithAttributes(public, private AttributeSet) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var k Signer
	err := c.withSession(func(session *pkcs11Session) error {
		public.AddIfNotPresent([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, ckkECEdwards),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519OID),
		})
		private.AddIfNotPresent([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		})

		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmECEdwardsKeyPairGen, nil)}
		pubHandle, privHandle, err := session.ctx.GenerateKeyPair(session.handle,
			mech,
			public.ToSlice(),
			private.ToSlice())
		if err != nil {
			return err
		}
		pub, err := exportEd25519PublicKey(session, pubHandle)
		if err != nil {
			return err
		}
		k = &pkcs11PrivateKeyEd25519{
			pkcs11PrivateKey: pkcs11PrivateKey{
				pkcs11Object: pkcs11Object{
					handle:  privHandle,
					context: c,
				},
				pubKeyHandle: pubHandle,
				pubKey:       pub,
			}}
		return nil
	})
	return k, err
}

// Sign signs a message using an Ed25519 key, completing crypto.Signer for
// pkcs11PrivateKeyEd25519. Ed25519 signs the raw message, so per the
// crypto.Signer convention opts.HashFunc() must be 0 and digest is the full
// message. The signature is the raw 64-byte value, not DER-encoded, so this
// does not go through dsaGeneric.
func (signer *pkcs11PrivateKeyEd25519) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.Errorf("ed25519 keys do not support pre-hashing, got hash func %v", opts.HashFunc())
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmEDDSA, nil)}
	err = signer.context.withSession(func(session *pkcs11Session) error {
		if err := session.ctx.SignInit(session.handle, mech, signer.handle); err != nil {
			return err
		}
		signature, err = session.ctx.Sign(session.handle, digest)
		return err
	})
	return signature, err
}
