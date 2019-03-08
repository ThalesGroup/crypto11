package crypto11

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGenerateKeyLabel(t *testing.T) {
	_, err := ConfigureFromFile("config")
	require.NoError(t, err)

	for i :=0; i < 100; i++ {
		label, err := generateKeyLabel()
		require.NoError(t, err)
		require.Len(t, label, labelLength)
		for _, b := range label {
			require.NotEqual(t, byte(0), b)
		}
	}
}
