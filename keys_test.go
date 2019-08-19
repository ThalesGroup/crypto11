package crypto11

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withContext executes a test function with a context.
func withContext(t *testing.T, f func(ctx *Context)) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	f(ctx)
}

func TestFindKeysRequiresIdOrLabel(t *testing.T) {
	withContext(t, func(ctx *Context) {
		_, err := ctx.FindKey(nil, nil)
		assert.Error(t, err)

		_, err = ctx.FindKeys(nil, nil)
		assert.Error(t, err)

		_, err = ctx.FindKeyPair(nil, nil)
		assert.Error(t, err)

		_, err = ctx.FindKeyPairs(nil, nil)
		assert.Error(t, err)
	})
}

func TestFindingKeysWithAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()
		id2 := randomBytes()

		key, err := ctx.GenerateSecretKey(id, 128, CipherAES)
		require.NoError(t, err)
		require.NotNil(t, key)
		defer key.Delete()

		key, err = ctx.GenerateSecretKey(id2, 128, CipherAES)
		require.NoError(t, err)
		require.NotNil(t, key)
		defer key.Delete()

		key, err = ctx.GenerateSecretKey(id2, 256, CipherAES)
		require.NoError(t, err)
		require.NotNil(t, key)
		defer key.Delete()

		attrs, err := NewAttributeSetWithID(id)
		require.NoError(t, err)

		keys, err := ctx.FindKeysWithAttributes(attrs)
		require.Len(t, keys, 1)

		attrs, err = NewAttributeSetWithID(id2)
		require.NoError(t, err)

		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.Len(t, keys, 2)

		attrs = NewAttributeSet()
		err = attrs.Set(CkaValueLen, 16)
		require.NoError(t, err)

		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.Len(t, keys, 2)

		attrs = NewAttributeSet()
		err = attrs.Set(CkaValueLen, 32)
		require.NoError(t, err)

		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.Len(t, keys, 1)
	})
}

func TestFindingKeyPairsWithAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()
		id2 := randomBytes()

		key, err := ctx.GenerateRSAKeyPair(id, 1024)
		require.NoError(t, err)
		require.NotNil(t, key)
		defer key.Delete()

		key, err = ctx.GenerateRSAKeyPair(id2, 1024)
		require.NoError(t, err)
		require.NotNil(t, key)
		defer key.Delete()

		key, err = ctx.GenerateRSAKeyPair(id2, 2048)
		require.NoError(t, err)
		require.NotNil(t, key)
		defer key.Delete()

		attrs, err := NewAttributeSetWithID(id)
		require.NoError(t, err)

		keys, err := ctx.FindKeyPairsWithAttributes(attrs)
		require.Len(t, keys, 1)

		attrs, err = NewAttributeSetWithID(id2)
		require.NoError(t, err)

		keys, err = ctx.FindKeyPairsWithAttributes(attrs)
		require.Len(t, keys, 2)

		attrs = NewAttributeSet()
		err = attrs.Set(CkaPublicExponent, []byte{1, 0, 1})
		require.NoError(t, err)

		keys, err = ctx.FindKeyPairsWithAttributes(attrs)
		require.Len(t, keys, 3)
	})
}

func TestFindingAllKeys(t *testing.T) {
	withContext(t, func(ctx *Context) {
		for i := 0; i < 10; i++ {
			id := randomBytes()
			key, err := ctx.GenerateSecretKey(id, 128, CipherAES)
			require.NoError(t, err)
			require.NotNil(t, key)

			defer key.Delete()
		}

		keys, err := ctx.FindAllKeys()
		require.NoError(t, err)
		require.NotNil(t, keys)

		require.Len(t, keys, 10)
	})
}

func TestFindingAllKeyPairs(t *testing.T) {
	withContext(t, func(ctx *Context) {
		for i := 1; i <= 5; i++ {
			id := randomBytes()
			key, err := ctx.GenerateRSAKeyPair(id, 1024)
			require.NoError(t, err)
			require.NotNil(t, key)

			defer key.Delete()
		}

		keys, err := ctx.FindAllKeyPairs()
		require.NoError(t, err)
		require.NotNil(t, keys)

		require.Len(t, keys, 5)
	})
}

func TestGettingPrivateKeyAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()

		key, err := ctx.GenerateRSAKeyPair(id, 1024)
		require.NoError(t, err)
		require.NotNil(t, key)
		defer key.Delete()

		attrs, err := ctx.GetAttributes(key, []AttributeType{CkaModulus})
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.Len(t, attrs, 1)

		require.Len(t, attrs[CkaModulus].Value, 128)
	})
}

func TestGettingPublicKeyAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()

		key, err := ctx.GenerateRSAKeyPair(id, 1024)
		require.NoError(t, err)
		require.NotNil(t, key)
		defer key.Delete()

		attrs, err := ctx.GetPubAttributes(key, []AttributeType{CkaModulusBits})
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.Len(t, attrs, 1)

		require.Equal(t, uint(1024), bytesToUlong(attrs[CkaModulusBits].Value))
	})
}

func TestGettingSecretKeyAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()

		key, err := ctx.GenerateSecretKey(id, 128, CipherAES)
		require.NoError(t, err)
		require.NotNil(t, key)
		defer key.Delete()

		attrs, err := ctx.GetAttributes(key, []AttributeType{CkaValueLen})
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.Len(t, attrs, 1)

		require.Equal(t, uint(16), bytesToUlong(attrs[CkaValueLen].Value))
	})
}

func TestGettingUnsupportedKeyTypeAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)

		_, err = ctx.GetAttributes(key, []AttributeType{CkaModulusBits})
		require.Error(t, err)
	})
}
