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
	"crypto"
	"crypto/dsa"
	"fmt"
	"testing"
)

func TestClose(t *testing.T) {
	// Verify that close and re-open works.
	var err error
	var key *PKCS11PrivateKeyDSA
	if _, err := ConfigureFromFile("config"); err != nil {
		t.Fatal(err)
	}
	psize := dsa.L1024N160
	if key, err = GenerateDSAKeyPair(dsaSizes[psize]); err != nil {
		t.Errorf("crypto11.GenerateDSAKeyPair: %v", err)
		return
	}
	if key == nil {
		t.Errorf("crypto11.dsa.GenerateDSAKeyPair: returned nil but no error")
		return
	}
	var id []byte
	if id, _, err = key.Identify(); err != nil {
		t.Errorf("crypto11.dsa.PKCS11PrivateKeyDSA.Identify: %v", err)
		return
	}
	if err = Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := ConfigureFromFile("config"); err != nil {
			t.Fatal(err)
		}
		var key2 crypto.PrivateKey
		if key2, err = FindKeyPair(id, nil); err != nil {
			t.Errorf("crypto11.dsa.FindDSAKeyPair by id: %v", err)
			return
		}
		testDsaSigning(t, key2.(*PKCS11PrivateKeyDSA), psize, fmt.Sprintf("close%d", i))
		if err = Close(); err != nil {
			t.Fatal(err)
		}
	}
}
