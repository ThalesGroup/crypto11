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
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

var threadCount = 32
var signaturesPerThread = 256

func TestThreadedRSA(t *testing.T) {
	var key *PKCS11PrivateKeyRSA
	_, err := ConfigureFromFile("config")
	require.NoError(t, err)

	if key, err = GenerateRSAKeyPair(1024); err != nil {
		t.Errorf("crypto11.GenerateRSAKeyPair: %v", err)
		return
	}
	done := make(chan int)
	started := time.Now()
	t.Logf("Starting %v threads", threadCount)
	for i := 0; i < threadCount; i++ {
		go signingRoutine(t, key, done)
	}
	t.Logf("Waiting for %v threads", threadCount)
	for i := 0; i < threadCount; i++ {
		_ = <-done
	}
	finished := time.Now()
	ticks := finished.Sub(started)
	elapsed := float64(ticks) / 1000000000.0
	t.Logf("Made %v signatures in %v elapsed (%v/s)",
		threadCount*signaturesPerThread,
		elapsed, float64(threadCount*signaturesPerThread)/elapsed)
	require.NoError(t, Close())
}

func signingRoutine(t *testing.T, key crypto.Signer, done chan int) {
	for i := 0; i < signaturesPerThread; i++ {
		testRsaSigningPKCS1v15(t, key, crypto.SHA1)
	}
	done <- 1

}
