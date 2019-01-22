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
	"bytes"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
	"hash"
	"testing"
)

func TestHmac(t *testing.T) {
	_, err := ConfigureFromFile("config")
	require.NoError(t, err)

	var info pkcs11.Info
	if info, err = instance.ctx.GetInfo(); err != nil {
		t.Errorf("GetInfo: %v", err)
		return
	}
	if info.ManufacturerID == "SoftHSM" {
		t.Skipf("HMAC not implemented on SoftHSM")
	}
	t.Run("HMACSHA1", func(t *testing.T) {
		testHmac(t, pkcs11.CKK_SHA_1_HMAC, pkcs11.CKM_SHA_1_HMAC, 0, 20, false)
	})
	t.Run("HMACSHA1General", func(t *testing.T) {
		testHmac(t, pkcs11.CKK_SHA_1_HMAC, pkcs11.CKM_SHA_1_HMAC_GENERAL, 10, 10, true)
	})
	t.Run("HMACSHA256", func(t *testing.T) {
		testHmac(t, pkcs11.CKK_SHA256_HMAC, pkcs11.CKM_SHA256_HMAC, 0, 32, false)
	})
	require.NoError(t, Close())
}

func testHmac(t *testing.T, keytype int, mech int, length int, xlength int, full bool) {
	var err error
	var key *PKCS11SecretKey
	t.Run("Generate", func(t *testing.T) {
		if key, err = GenerateSecretKey(256, Ciphers[keytype]); err != nil {
			t.Errorf("crypto11.GenerateSecretKey: %v", err)
			return
		}
		if key == nil {
			t.Errorf("crypto11.GenerateSecretKey: returned nil but no error")
			return
		}
	})
	if key == nil {
		return
	}
	t.Run("Short", func(t *testing.T) {
		input := []byte("a short string")
		var h1, h2 hash.Hash
		if h1, err = key.NewHMAC(mech, length); err != nil {
			t.Errorf("key.NewHMAC: %v", err)
			return
		}
		if n, err := h1.Write(input); err != nil || n != len(input) {
			t.Errorf("h1.Write: %v/%d", err, n)
			return
		}
		r1 := h1.Sum([]byte{})
		if h2, err = key.NewHMAC(mech, length); err != nil {
			t.Errorf("key.NewHMAC: %v", err)
			return
		}
		if n, err := h2.Write(input); err != nil || n != len(input) {
			t.Errorf("h2.Write: %v/%d", err, n)
			return
		}
		r2 := h2.Sum([]byte{})
		if bytes.Compare(r1, r2) != 0 {
			t.Errorf("h1/h2 inconsistent")
			return
		}
		if len(r1) != xlength {
			t.Errorf("r1 wrong length (want %v got %v)", xlength, len(r1))
			return
		}
	})
	if full { // Independent of hash, only do these once
		t.Run("Empty", func(t *testing.T) {
			// Must be able to MAC empty inputs without panicing
			var h1 hash.Hash
			if h1, err = key.NewHMAC(mech, length); err != nil {
				t.Errorf("key.NewHMAC: %v", err)
				return
			}
			h1.Sum([]byte{})
		})
		t.Run("MultiSum", func(t *testing.T) {
			input := []byte("a different short string")
			var h1 hash.Hash
			if h1, err = key.NewHMAC(mech, length); err != nil {
				t.Errorf("key.NewHMAC: %v", err)
				return
			}
			if n, err := h1.Write(input); err != nil || n != len(input) {
				t.Errorf("h1.Write: %v/%d", err, n)
				return
			}
			r1 := h1.Sum([]byte{})
			r2 := h1.Sum([]byte{})
			if bytes.Compare(r1, r2) != 0 {
				t.Errorf("r1/r2 inconsistent")
				return
			}
			// Can't add more after Sum()
			if n, err := h1.Write(input); err != ErrHmacClosed {
				t.Errorf("h1.Write: %v/%d", err, n)
				return
			}
			// 0-length is special
			if n, err := h1.Write([]byte{}); err != nil || n != 0 {
				t.Errorf("h1.Write: %v/%d", err, n)
				return
			}
		})
		t.Run("Reset", func(t *testing.T) {
			var h1 hash.Hash
			if h1, err = key.NewHMAC(mech, length); err != nil {
				t.Errorf("key.NewHMAC: %v", err)
				return
			}
			if n, err := h1.Write([]byte{1}); err != nil || n != 1 {
				t.Errorf("h1.Write: %v/%d", err, n)
				return
			}
			r1 := h1.Sum([]byte{})
			h1.Reset()
			if n, err := h1.Write([]byte{2}); err != nil || n != 1 {
				t.Errorf("h1.Write: %v/%d", err, n)
				return
			}
			r2 := h1.Sum([]byte{})
			h1.Reset()
			if n, err := h1.Write([]byte{1}); err != nil || n != 1 {
				t.Errorf("h1.Write: %v/%d", err, n)
				return
			}
			r3 := h1.Sum([]byte{})
			if bytes.Compare(r1, r3) != 0 {
				t.Errorf("r1/r3 inconsistent")
				return
			}
			if bytes.Compare(r1, r2) == 0 {
				t.Errorf("r1/r2 unexpectedly equal")
				return
			}
		})
		t.Run("ResetFast", func(t *testing.T) {
			// Reset() immediately after creation should be safe
			var h1 hash.Hash
			if h1, err = key.NewHMAC(mech, length); err != nil {
				t.Errorf("key.NewHMAC: %v", err)
				return
			}
			h1.Reset()
			if n, err := h1.Write([]byte{2}); err != nil || n != 1 {
				t.Errorf("h1.Write: %v/%d", err, n)
				return
			}
			h1.Sum([]byte{})
		})
	}
}
