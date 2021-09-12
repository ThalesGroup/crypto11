package crypto11

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/miekg/pkcs11"

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

		var err error
        // Compensate for unclean starting condition
		preconditionAttrs_CkaValueLen16 := NewAttributeSet()
		err = preconditionAttrs_CkaValueLen16.Set(CkaValueLen, 16)
		require.NoError(t, err)

		var preconditionKeys_CkaValueLen16 []*SecretKey
		preconditionKeys_CkaValueLen16, err = ctx.FindKeysWithAttributes(preconditionAttrs_CkaValueLen16)
		require.NoError(t, err)

		preconditionAttrs_CkaValueLen32 := NewAttributeSet()
		err = preconditionAttrs_CkaValueLen32.Set(CkaValueLen, 32)
		require.NoError(t, err)

		var preconditionKeys_CkaValueLen32 []*SecretKey
		preconditionKeys_CkaValueLen32, err = ctx.FindKeysWithAttributes(preconditionAttrs_CkaValueLen32)
		require.NoError(t, err)

		label := randomBytes()
		label2 := randomBytes()

		var key *SecretKey
		key, err = ctx.GenerateSecretKeyWithLabel(randomBytes(), label, 128, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		key, err = ctx.GenerateSecretKeyWithLabel(randomBytes(), label2, 128, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		key, err = ctx.GenerateSecretKeyWithLabel(randomBytes(), label2, 256, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		attrs := NewAttributeSet()
		_ = attrs.Set(CkaLabel, label)
		keys, err := ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 1)

		_ = attrs.Set(CkaLabel, label2)
		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 2)

		attrs = NewAttributeSet()
		err = attrs.Set(CkaValueLen, 16)
		require.NoError(t, err)

		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 2 + len(preconditionKeys_CkaValueLen16))

		attrs = NewAttributeSet()
		err = attrs.Set(CkaValueLen, 32)
		require.NoError(t, err)

		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 1 + len(preconditionKeys_CkaValueLen32))
	})
}

func TestFindingKeyPairsWithAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {

		// Compensate for unclean starting stage
		var err error
		preconditionAttrs_CkaType_CKK_RSA := NewAttributeSet()
		err = preconditionAttrs_CkaType_CKK_RSA.Set(CkaKeyType, pkcs11.CKK_RSA)
		var preconditionKeysRsa []Signer
		preconditionKeysRsa, err = ctx.FindKeyPairsWithAttributes(preconditionAttrs_CkaType_CKK_RSA)
		require.NoError(t, err)

		// Note: we use common labels, not IDs in this test code. AWS CloudHSM
		// does not accept two keys with the same ID.

		label := randomBytes()
		label2 := randomBytes()

		key, err := ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		key, err = ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label2, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		key, err = ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label2, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		attrs := NewAttributeSet()
		_ = attrs.Set(CkaLabel, label)
		keys, err := ctx.FindKeyPairsWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 1)

		_ = attrs.Set(CkaLabel, label2)
		keys, err = ctx.FindKeyPairsWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 2)

		attrs = NewAttributeSet()
		_ = attrs.Set(CkaKeyType, pkcs11.CKK_RSA)
		keys, err = ctx.FindKeyPairsWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 3 + len(preconditionKeysRsa))
	})
}

func TestFindingAllKeys(t *testing.T) {
	withContext(t, func(ctx *Context) {

		var preconditionKeys []*SecretKey
		var err error
		preconditionKeys, err = ctx.FindAllKeys()

		for i := 0; i < 10; i++ {
			id := randomBytes()
			key, err := ctx.GenerateSecretKey(id, 128, CipherAES)
			require.NoError(t, err)

			defer func(k *SecretKey) { _ = k.Delete() }(key)
		}
		var keys []*SecretKey
		keys, err = ctx.FindAllKeys()
		require.NoError(t, err)
		require.NotNil(t, keys)

		require.Len(t, keys, 10 + len(preconditionKeys))
	})
}

func TestFindingAllKeyPairs(t *testing.T) {
	withContext(t, func(ctx *Context) {

		var preconditionRsaKeys []Signer
		var err error
		preconditionRsaKeys, err = ctx.FindAllKeyPairs()

		for i := 1; i <= 5; i++ {
			id := randomBytes()
			key, err := ctx.GenerateRSAKeyPair(id, rsaSize)
			require.NoError(t, err)

			defer func(k Signer) { _ = k.Delete() }(key)
		}

		var keys []Signer
		keys, err = ctx.FindAllKeyPairs()
		require.NoError(t, err)
		require.NotNil(t, keys)

		require.Len(t, keys, 5 + len(preconditionRsaKeys))
	})
}

func TestGettingPrivateKeyAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()

		key, err := ctx.GenerateRSAKeyPair(id, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		attrs, err := ctx.GetAttributes(key, []AttributeType{CkaModulus})
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.Len(t, attrs, 1)

		require.Len(t, attrs[CkaModulus].Value, 256)
	})
}

func TestGettingPublicKeyAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()

		key, err := ctx.GenerateRSAKeyPair(id, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		attrs, err := ctx.GetPubAttributes(key, []AttributeType{CkaModulusBits})
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.Len(t, attrs, 1)

		require.Equal(t, uint(rsaSize), bytesToUlong(attrs[CkaModulusBits].Value))
	})
}

func TestGettingSecretKeyAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()

		key, err := ctx.GenerateSecretKey(id, 128, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		attrs, err := ctx.GetAttributes(key, []AttributeType{CkaValueLen})
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.Len(t, attrs, 1)

		require.Equal(t, uint(16), bytesToUlong(attrs[CkaValueLen].Value))
	})
}

func TestGettingUnsupportedKeyTypeAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		key, err := rsa.GenerateKey(rand.Reader, rsaSize)
		require.NoError(t, err)

		_, err = ctx.GetAttributes(key, []AttributeType{CkaModulusBits})
		require.Error(t, err)
	})
}
