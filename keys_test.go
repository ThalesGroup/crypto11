package crypto11

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindKeysRequiresIdOrLabel(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	_, err = ctx.FindKey(nil, nil)
	assert.Error(t, err)

	_, err = ctx.FindKeys(nil, nil)
	assert.Error(t, err)

	_, err = ctx.FindKeyPair(nil, nil)
	assert.Error(t, err)

	_, err = ctx.FindKeyPairs(nil, nil)
	assert.Error(t, err)
}
