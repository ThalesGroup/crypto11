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
	"crypto/dsa"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitializeFromConfig(t *testing.T) {
	// TODO - this test is odd looking and needs reworking
	var config Config
	config.Path = "NoSuchFile"
	config.Pin = "NoSuchPin"
	config.TokenSerial = "NoSuchToken"
	config.TokenLabel = "NoSuchToken"
	//assert.Panics(Configure(config), "Invalid config should panic")
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)
	require.NoError(t, ctx.Close())
}

func TestLoginContext(t *testing.T) {
	t.Run("key identity with login", func(t *testing.T) {
		ctx, err := configureWithPin(t)
		require.NoError(t, err)

		defer func() {
			err = ctx.Close()
			require.NoError(t, err)
		}()

		// Generate a key and and close a session
		const pSize = dsa.L1024N160
		id := randomBytes()
		key, err := ctx.GenerateDSAKeyPair(id, nil, dsaSizes[pSize])
		require.NoError(t, err)
		require.NotNil(t, key)

		err = ctx.Close()
		require.NoError(t, err)

		// Reopen a session and try to find a key.
		// Valid session must enlist a key.
		// If login is not performed than it will fail.
		ctx, err = configureWithPin(t)
		require.NoError(t, err)

		key2, err := ctx.FindKeyPair(id, nil)
		require.NoError(t, err)

		testDsaSigning(t, key2.(*PKCS11PrivateKeyDSA), pSize, fmt.Sprintf("close%d", 0))
	})

	t.Run("login context shared between sessions", func(t *testing.T) {
		ctx, err := configureWithPin(t)
		require.NoError(t, err)

		defer func() {
			err = ctx.Close()
			require.NoError(t, err)
		}()

		// Generate a key and and close a session
		const pSize = dsa.L1024N160
		id := randomBytes()
		key, err := ctx.GenerateDSAKeyPair(id, nil, dsaSizes[pSize])
		require.NoError(t, err)
		require.NotNil(t, key)

		// TODO - need to examine this test in more detail to see what it accomplishes
		err = ctx.withSession(func(s1 *pkcs11Session) error {
			return ctx.withSession(func(s2 *pkcs11Session) error {
				key2, err := ctx.FindKeyPair(id, nil)
				require.NoError(t, err)
				testDsaSigning(t, key2.(*PKCS11PrivateKeyDSA), pSize, fmt.Sprintf("close%d", 0))
				return nil
			})
		})
		require.NoError(t, err)
	})
}

func configureWithPin(t *testing.T) (*Context, error) {
	cfg, err := getConfig("config")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Pin == "" {
		t.Fatal("invalid configuration. configuration must have PIN non empty.")
	}

	ctx, err := Configure(cfg)
	if err != nil {
		t.Fatal("failed to configure service:", err)
	}

	return ctx, nil
}

func getConfig(configLocation string) (ctx *Config, err error) {
	file, err := os.Open(configLocation)
	if err != nil {
		log.Printf("Could not open config file: %s", configLocation)
		return nil, err
	}
	defer func() {
		err = file.Close()
	}()

	configDecoder := json.NewDecoder(file)
	config := &Config{}
	err = configDecoder.Decode(config)
	if err != nil {
		log.Printf("Could decode config file: %s", err.Error())
		return nil, err
	}
	return config, nil
}
