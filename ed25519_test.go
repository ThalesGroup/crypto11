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
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHardEd25519(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	id := randomBytes()
	label := randomBytes()

	key, err := ctx.GenerateEd25519KeyPairWithLabel(id, label)
	require.NoError(t, err)
	require.NotNil(t, key)
	defer func(k Signer) { _ = k.Delete() }(key)

	pub, ok := key.Public().(ed25519.PublicKey)
	require.True(t, ok, "expected ed25519.PublicKey, got %T", key.Public())

	testEd25519Signing(t, key, pub)

	key2, err := ctx.FindKeyPair(id, nil)
	require.NoError(t, err)
	testEd25519Signing(t, key2.(crypto.Signer), pub)

	key3, err := ctx.FindKeyPair(nil, label)
	require.NoError(t, err)
	testEd25519Signing(t, key3.(crypto.Signer), pub)
}

func testEd25519Signing(t *testing.T, key crypto.Signer, pub ed25519.PublicKey) {
	t.Helper()

	message := []byte("sign me with Ed25519")

	// Ed25519 signs the raw message: opts.HashFunc() must be crypto.Hash(0).
	sig, err := key.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	require.Len(t, sig, ed25519.SignatureSize)

	require.True(t, ed25519.Verify(pub, message, sig), "ed25519 signature failed to verify")
}

func TestEd25519RequiredArgs(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	_, err = ctx.GenerateEd25519KeyPair(nil)
	require.Error(t, err)

	val := randomBytes()

	_, err = ctx.GenerateEd25519KeyPairWithLabel(nil, val)
	require.Error(t, err)

	_, err = ctx.GenerateEd25519KeyPairWithLabel(val, nil)
	require.Error(t, err)
}
