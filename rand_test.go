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
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRandomReader(t *testing.T) {
	var a [32768]byte
	var r PKCS11RandReader
	var n int
	_, err := ConfigureFromFile("config")
	require.NoError(t, err)

	for _, size := range []int{1, 16, 32, 256, 347, 4096, 32768} {
		if n, err = r.Read(a[:size]); err != nil {
			t.Errorf("crypto11.PKCS11RandRead.Read: %v", err)
			return
		}
		if n < size {
			t.Errorf("crypto11.PKCS11RandRead.Read: only got %d bytes expected %d", n, size)
			return
		}
	}
	require.NoError(t, Close())
}
