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
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func TestKeysPersistAcrossContexts(t *testing.T) {
	ctx, err := configureWithPin(t)
	require.NoError(t, err)

	defer func() {
		err = ctx.Close()
		require.NoError(t, err)
	}()

	// Generate a key and and close a session
	const pSize = dsa.L1024N160
	id := randomBytes()
	key, err := ctx.GenerateDSAKeyPair(id, dsaSizes[pSize])
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

	testDsaSigning(t, key2.(*pkcs11PrivateKeyDSA), pSize, fmt.Sprintf("close%d", 0))

	err = key2.Delete()
	require.NoError(t, err)
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

func TestKeyPairDelete(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	id := randomBytes()
	key, err := ctx.GenerateRSAKeyPair(id, 2048)
	require.NoError(t, err)

	// Check we can find it
	_, err = ctx.FindKeyPair(id, nil)
	require.NoError(t, err)

	err = key.Delete()
	require.NoError(t, err)

	k, err := ctx.FindKeyPair(id, nil)
	require.NoError(t, err)
	require.Nil(t, k)
}

func TestKeyDelete(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	id := randomBytes()
	key, err := ctx.GenerateSecretKey(id, 128, CipherAES)
	require.NoError(t, err)

	// Check we can find it
	_, err = ctx.FindKey(id, nil)
	require.NoError(t, err)

	err = key.Delete()
	require.NoError(t, err)

	k, err := ctx.FindKey(id, nil)
	require.NoError(t, err)
	require.Nil(t, k)
}

func TestAmbiguousTokenConfig(t *testing.T) {
	slotNum := 1
	tests := []struct {
		config *Config
		err    string
	}{
		{
			config: &Config{TokenSerial: "serial", TokenLabel: "label"},
			err:    "config must specify exactly one way to select a token: token label, token serial number given",
		},
		{
			config: &Config{TokenSerial: "serial", SlotNumber: &slotNum},
			err:    "config must specify exactly one way to select a token: slot number, token serial number given",
		},
		{
			config: &Config{SlotNumber: &slotNum, TokenLabel: "label"},
			err:    "config must specify exactly one way to select a token: slot number, token label given",
		},
		{
			config: &Config{},
			err:    "config must specify exactly one way to select a token: none given",
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("test_%d", i), func(t *testing.T) {
			_, err := Configure(test.config)
			if assert.Error(t, err) {
				assert.Equal(t, test.err, err.Error())
			}
		})
	}
}

func TestSelectBySlot(t *testing.T) {
	config, err := loadConfigFromFile("config")
	require.NoError(t, err)

	// Look up slot number for label
	ctx, err := Configure(config)
	require.NoError(t, err)

	slotNumber := int(ctx.slot)
	t.Logf("Using slot %d", slotNumber)
	err = ctx.Close()
	require.NoError(t, err)

	slotConfig := &Config{
		SlotNumber: &slotNumber,
		Pin:        config.Pin,
		Path:       config.Path,
	}

	ctx, err = Configure(slotConfig)
	require.NoError(t, err)

	slotNumber2 := int(ctx.slot)
	err = ctx.Close()
	require.NoError(t, err)

	assert.Equal(t, slotNumber, slotNumber2)
}

func TestSelectByNonExistingSlot(t *testing.T) {
	config, err := loadConfigFromFile("config")
	require.NoError(t, err)

	rand.Seed(time.Now().UnixNano())
	randomSlot := int(rand.Uint32())

	config.TokenLabel = ""
	config.TokenSerial = ""
	config.SlotNumber = &randomSlot

	// Look up slot number for label
	_, err = Configure(config)
	require.Equal(t, errTokenNotFound, err)
}
