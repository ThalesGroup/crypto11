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
	"crypto/elliptic"
	"crypto/rand"
	"github.com/miekg/pkcs11"
	"testing"
	"time"
)

func TestPoolTimeout(t *testing.T) {
	t.Run("first login", func(t *testing.T) {
		prevIdleTimeout := instance.idleTimeout
		defer func() {instance.idleTimeout = prevIdleTimeout}()
		instance.idleTimeout = time.Second

		configureWithPin(t)
		defer Close()

		time.Sleep(instance.idleTimeout + time.Second)

		_, err := GenerateECDSAKeyPair(elliptic.P256())
		if err != nil {
			if perr, ok := err.(pkcs11.Error); ok && perr == pkcs11.CKR_USER_NOT_LOGGED_IN {
				t.Fatal("pool handle session incorrectly, login required but missing:", err)
			} else {
				t.Fatal("failed to generate a key, unexpected error:", err)
			}
		}
	})

	t.Run("reuse expired handle", func(t *testing.T) {
		prevIdleTimeout := instance.idleTimeout
		defer func() {instance.idleTimeout = prevIdleTimeout}()
		instance.idleTimeout = time.Second

		configureWithPin(t)
		defer Close()

		key, err := GenerateECDSAKeyPair(elliptic.P256())
		if err != nil {
			t.Fatal("failed to generate a key:", err)
		}

		time.Sleep(instance.idleTimeout + time.Second)

		_, err = key.Sign(rand.Reader, crypto.SHA256.New().Sum([]byte("sha256")), crypto.SHA256)
		if err != nil {
			if perr, ok := err.(pkcs11.Error); !ok || perr != pkcs11.CKR_OBJECT_HANDLE_INVALID {
				t.Fatal("failed to reuse existing key handle, unexpected error:", err)
			}
		}
	})
}

