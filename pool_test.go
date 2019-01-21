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
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestPoolTimeout(t *testing.T) {
	for _, d := range []time.Duration{0, time.Second} {
		t.Run(fmt.Sprintf("first login, exp %v", d), func(t *testing.T) {
			prevIdleTimeout := instance.cfg.IdleTimeout
			defer func() { instance.cfg.IdleTimeout = prevIdleTimeout }()
			instance.cfg.IdleTimeout = d

			_, err := configureWithPin(t)
			require.NoError(t, err)

			defer func() {
				require.NoError(t, Close())
			}()

			time.Sleep(instance.cfg.IdleTimeout + time.Second)

			_, err = GenerateECDSAKeyPair(elliptic.P256())
			if err != nil {
				if perr, ok := err.(pkcs11.Error); ok && perr == pkcs11.CKR_USER_NOT_LOGGED_IN {
					t.Fatal("pool handle session incorrectly, login required but missing:", err)
				} else {
					t.Fatal("failed to generate a key, unexpected error:", err)
				}
			}
		})

		t.Run(fmt.Sprintf("reuse expired handle, exp %v", d), func(t *testing.T) {
			prevIdleTimeout := instance.cfg.IdleTimeout
			defer func() { instance.cfg.IdleTimeout = prevIdleTimeout }()
			instance.cfg.IdleTimeout = d

			_, err := configureWithPin(t)
			require.NoError(t, err)

			defer func() {
				require.NoError(t, Close())
			}()

			key, err := GenerateECDSAKeyPair(elliptic.P256())
			if err != nil {
				t.Fatal("failed to generate a key:", err)
			}

			time.Sleep(instance.cfg.IdleTimeout + time.Second)

			digest := crypto.SHA256.New()
			digest.Write([]byte("sha256"))
			_, err = key.Sign(rand.Reader, digest.Sum(nil), crypto.SHA256)
			if err != nil {
				if perr, ok := err.(pkcs11.Error); !ok || perr != pkcs11.CKR_OBJECT_HANDLE_INVALID {
					t.Fatal("failed to reuse existing key handle, unexpected error:", err)
				}
			}
		})
	}
}
