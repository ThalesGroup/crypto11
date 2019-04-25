package crypto11

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateKeyLabel(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)
	defer func() {
		err = ctx.Close()
		require.NoError(t, err)
	}()

	for i := 0; i < 100; i++ {
		label, err := ctx.generateKeyLabel()
		require.NoError(t, err)
		require.Len(t, label, labelLength)
		for _, b := range label {
			require.NotEqual(t, byte(0), b)
		}
	}
}
