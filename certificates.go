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
	"crypto/x509"
	"encoding/asn1"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// FindCertificate retrieves a previously imported certificate
//
// Either (but not all three) of id, label and serial may be nil, in which case they are ignored.
// If specified, serial should be the ASN.1 Integer DER-encoding of the certificate serial number.
func (c *Context) FindCertificate(id []byte, label []byte, serial []byte) (*x509.Certificate, error) {
	var handles []pkcs11.ObjectHandle
	var template []*pkcs11.Attribute

	if c.closed.Get() {
		return nil, errClosed
	}

	var cert *x509.Certificate
	err := c.withSession(func(session *pkcs11Session) (err error) {
		if id == nil && label == nil && serial == nil {
			return errors.New("id, label and serial cannot both be nil")
		}
		if id != nil {
			template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
		}
		if label != nil {
			template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
		}
		if serial != nil {
			template = append(template, pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, serial))
		}

		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE))

		if err = session.ctx.FindObjectsInit(session.handle, template); err != nil {
			return err
		}
		defer func() {
			finalErr := session.ctx.FindObjectsFinal(session.handle)
			if err == nil {
				err = finalErr
			}
		}()
		if handles, _, err = session.ctx.FindObjects(session.handle, 1); err != nil {
			return err
		}
		if len(handles) == 0 {
			return nil
		}

		attributes := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, 0),
		}

		if attributes, err = session.ctx.GetAttributeValue(session.handle, handles[0], attributes); err != nil {
			return err
		}

		cert, err = x509.ParseCertificate(attributes[0].Value)

		return err
	})

	return cert, err
}

// ImportCertificate imports a certificate onto the token.  he id parameter is used to
// set CKA_ID and must be non-nil.
func (c *Context) ImportCertificate(id []byte, certificate *x509.Certificate) error {

	if err := notNilBytes(id, "id"); err != nil {
		return err
	}

	return c.importCertificate(id, nil, certificate)
}

// ImportCertificateWithLabel imports a certificate onto the token.  The id and label parameters are used to
// set CKA_ID and CKA_LABEL respectively and must be non-nil.
func (c *Context) ImportCertificateWithLabel(id []byte, label []byte, certificate *x509.Certificate) error {

	if err := notNilBytes(id, "id"); err != nil {
		return err
	}
	if err := notNilBytes(label, "label"); err != nil {
		return err
	}

	return c.importCertificate(id, label, certificate)
}

func (c *Context) importCertificate(id []byte, label []byte, certificate *x509.Certificate) error {

	serial, err := asn1.Marshal(certificate.SerialNumber)
	if err != nil {
		return err
	}

	err = c.withSession(func(session *pkcs11Session) (err error) {
		attributes := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
			pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
			pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, certificate.RawSubject),
			pkcs11.NewAttribute(pkcs11.CKA_ISSUER, certificate.RawIssuer),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
			pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, serial),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, certificate.Raw),
		}

		_, err = session.ctx.CreateObject(session.handle, attributes)

		return err
	})

	return err
}
